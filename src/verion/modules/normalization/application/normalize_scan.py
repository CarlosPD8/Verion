from collections.abc import Callable

from verion.modules.normalization.domain.exceptions import UnknownScannerOutput
from verion.modules.normalization.domain.finding import (
    Finding,
    FindingSighting,
    collapse_by_identity,
)
from verion.modules.normalization.domain.mappers.semgrep import map_semgrep_output
from verion.modules.normalization.domain.mappers.trivy import map_trivy_output
from verion.modules.normalization.domain.mappers.zap import map_zap_output
from verion.modules.normalization.domain.normalization_run import NormalizationRun
from verion.modules.normalization.ports.finding_repository import FindingRepositoryPort
from verion.modules.normalization.ports.normalization_run_repository import (
    NormalizationRunRepositoryPort,
)

# `scanning`'s PORT, never its domain or adapters — the same legality
# RunScanUseCase relies on in the other direction, and the reason the
# cross-module-normalization contract sets allow_indirect_imports. Note what is
# deliberately NOT imported: `ScanResult` itself. Its type is inferred from the
# port's return annotation, so mypy checks every attribute access below without
# this module naming a type it is forbidden to import.
from verion.modules.scanning.ports.scan_result_repository import ScanResultRepositoryPort
from verion.shared_kernel.ports import ClockPort, IdGeneratorPort
from verion.shared_kernel.scanner_tools import ScannerTool

# A mapping keyed by the enum, never an `if tool == "zap"` chain — the same rule
# 4 shape ADR-016 decision 4 established for scanner dispatch, applied to the
# other end of the pipeline. Adding a scanner means writing a mapper and adding a
# row here; it means editing no logic.
_Mapper = Callable[..., list[Finding]]
_MAPPERS: dict[ScannerTool, _Mapper] = {
    ScannerTool.SEMGREP: map_semgrep_output,
    ScannerTool.TRIVY: map_trivy_output,
    ScannerTool.ZAP: map_zap_output,
}

# A failure_reason is persisted and (once M4.5 surfaces it) returned, so it is
# bounded for the same reason RunScanUseCase bounds its own.
_MAX_FAILURE_REASON_CHARS = 2000


class NormalizeScanUseCase:
    """Turns one scan's trustworthy raw output into `Finding`s and sightings.

    **Entry point is `get_succeeded_by_scan_id`, never `Scan.status`** (ADR-016
    decision 2). That is not a preference about where to read a flag: `Scan.status`
    is a derived, human-facing summary of per-tool outcomes, and a pipeline taking
    it as input is a pipeline downstream of a summary. The succeeded rows draw the
    line directly, and every one of them is guaranteed to carry non-null
    `raw_output` by `ck_scan_results_outcome_shape`.

    **A `PARTIAL` scan is normalized, and so is one where every tool failed**
    (ADR-0017 decision 3). Both take this same path with no branch: the failed
    tools' rows simply are not returned. The second case produces zero findings and
    a `completed` run — `NormalizationRunStatus.FAILED` means *normalization*
    failed, never that the scan did.

    **Failure splits on one question: is it deterministic in the persisted
    `ScanResult` rows?** Those rows do not change between attempts, so this whole
    operation is a pure function of them plus the id generator and the clock.

    - *Transient or unanticipated* — a DB error, an unexpected exception anywhere
      in mapping or persistence. Record `failed` and **re-raise**, so arq retries
      with backoff. The retry re-claims (only `completed` is terminal) and re-runs
      the identical pass.
    - *Deterministic and isolated* — a finding group that disagrees on a rule-level
      attribute. Skip that group, persist everything else, record `failed`, and
      **do not re-raise**: a retry would fail identically, so it buys five wasted
      attempts.

    **A retry cannot damage what an earlier attempt wrote**, and that is a property
    of ADR-0020 rather than of care taken here: `upsert` refreshes a set that is
    total except the two surrogate ids, and `record_sighting` overwrites a per-scan
    total rather than incrementing. Re-running the identical pass writes identical
    values.
    """

    def __init__(
        self,
        scan_results: ScanResultRepositoryPort,
        findings: FindingRepositoryPort,
        normalization_runs: NormalizationRunRepositoryPort,
        id_generator: IdGeneratorPort,
        clock: ClockPort,
    ) -> None:
        self._scan_results = scan_results
        self._findings = findings
        self._normalization_runs = normalization_runs
        self._id_generator = id_generator
        self._clock = clock

    async def execute(self, run: NormalizationRun) -> None:
        """Normalize the scan this already-claimed run refers to.

        Takes the claimed `NormalizationRun` rather than a `scan_id` because the
        claim is a transaction of its own — it has to commit before this work
        begins, or `RUNNING` would be written and overwritten inside one
        transaction and never be observable, which would make a job killed
        mid-flight indistinguishable from one that never started. `worker.py`
        owns that boundary, the same way it owns `run_scan`'s commit-in-`finally`.
        """
        try:
            observed = await self._map_all(run)
            skipped = await self._persist(observed, run)
        except Exception as exc:
            # Deliberately broad, and it re-raises — unlike RunScanUseCase's
            # per-scanner catch, which swallows because a tool's failure is that
            # tool's recorded outcome. Here there is no per-element outcome to
            # record and nothing partial worth keeping, so the run is marked
            # failed for visibility and arq is left to retry, exactly as
            # RunScanUseCase does for its pre-tool failures.
            #
            # If the failure was a DB error this write aborts too and the row
            # stays at its last committed value — `running`, from the claim — and
            # the sweep recovers it. That is why `get_stale` includes `running`.
            #
            # **The exception's TYPE only, never `str(exc)` — this is rule 12.**
            # `failure_reason` is persisted and M4.5 returns it, and the most
            # likely exception here is a SQLAlchemy `StatementError`, whose
            # `__str__` renders `[SQL: …] [parameters: …]`. The statement that
            # would be in it is the finding upsert, whose bound parameters include
            # `title` and `Evidence.raw_payload` — scanned source code. So the
            # obvious, useful-looking `f"{type(exc).__name__}: {exc}"` puts the
            # contents of a scanned repository into an API response, by a route
            # nobody would look for.
            #
            # The cost is real: this loses the diagnostic. It is the right trade
            # anyway, because the alternative is a redaction that has to be
            # correct for every exception type any dependency may raise in future,
            # and rule 12 exists precisely because that kind of guarantee does not
            # hold. Debugging goes through the stack trace arq logs from the
            # re-raise below, which is not a persisted, API-reachable sink.
            await self._normalization_runs.update(
                run.fail(
                    self._clock.now(),
                    f"Normalization failed with {type(exc).__name__}. The message is "
                    f"deliberately not persisted (rule 12): it can carry scanned file "
                    f"contents. See the worker's traceback for this scan."[
                        :_MAX_FAILURE_REASON_CHARS
                    ],
                )
            )
            raise

        if skipped:
            # Everything else is already persisted. The run is still marked failed
            # because a dropped security finding with no record of the drop is the
            # invisible loss this project's register exists to prevent — and
            # `failure_reason` is the field ADR-0017 decision 1 created for a
            # failure that is neither a scanner outcome nor a pre-tool failure.
            #
            # Only the hashes and the count, never the disagreeing values.
            #
            # **The reason is narrower than this comment claimed until M4.5, and
            # the overstatement is corrected rather than left standing.** It said
            # `title`/`severity` "can carry scanned content (rule 12)". They
            # cannot, under any mapper this project has: `title` is `check_id`
            # for Semgrep, `VulnerabilityID` plus the advisory's own title for
            # Trivy, and the alert name for ZAP — rule- and advisory-derived
            # prose, never the matched source. `severity` is a closed vocabulary.
            # The true reason to omit them is duller and still sufficient: they
            # do not identify WHICH group was skipped, `dedup_hash` does, and a
            # bounded diagnostic field should carry the identifier rather than
            # the payload. Rule 12 was doing no work here.
            #
            # It mattered enough to fix because M4.5 makes this field an API
            # response, so a false claim about what may safely go in it is now a
            # claim about what may safely leave the system.
            await self._normalization_runs.update(
                run.fail(
                    self._clock.now(),
                    f"{len(skipped)} finding group(s) could not be collapsed and were "
                    f"skipped; every other finding in this scan was persisted. "
                    f"collapse_by_identity rejects a group either because its members "
                    f"disagree on a rule-level attribute or because they span projects — "
                    f"which of the two is deliberately not asserted here, since this "
                    f"handler does not distinguish them. dedup_hash: "
                    f"{', '.join(sorted(skipped))}"[:_MAX_FAILURE_REASON_CHARS],
                )
            )
            return

        await self._normalization_runs.update(run.complete(self._clock.now()))

    async def _map_all(self, run: NormalizationRun) -> list[Finding]:
        """Every succeeded tool's output, mapped and concatenated into one list.

        **One list across all tools, deliberately, and it is what satisfies
        ADR-0020 decision 5's second contract.** `collapse_by_identity` then runs
        one pass over the whole scan, so each identity yields exactly one
        `(representative, total)` pair and therefore exactly one `record_sighting`
        call carrying a complete count. Per-tool batching would happen to be safe
        (`source` is a `dedup_hash` input, so no identity spans two tools), but
        `match_count` is a total the repository OVERWRITES — so any shape that
        called it twice for one `(finding, scan)` would silently keep only the
        last partial count.
        """
        observed: list[Finding] = []
        for result in await self._scan_results.get_succeeded_by_scan_id(run.scan_id):
            try:
                tool = ScannerTool(result.tool)
            except ValueError as exc:
                raise UnknownScannerOutput(
                    f"Scan '{run.scan_id}' has a result for tool '{result.tool}', which is not "
                    f"a known scanner"
                ) from exc
            mapper = _MAPPERS.get(tool)
            if mapper is None:
                raise UnknownScannerOutput(
                    f"Scan '{run.scan_id}' has a result for tool '{tool}', which has no mapper"
                )
            if result.raw_output is None:
                # Unreachable: ck_scan_results_outcome_shape guarantees a
                # SUCCEEDED row carries output, which is exactly why the mappers
                # take `str` and not `str | None`. Kept as a raise rather than an
                # assert or a cast because it is the one place that guarantee is
                # consumed, and a silent `or ""` here would turn a broken
                # constraint into an empty scan.
                raise UnknownScannerOutput(
                    f"Scan '{run.scan_id}' has a SUCCEEDED result for '{tool}' with no "
                    f"raw_output — ck_scan_results_outcome_shape should make this impossible"
                )
            observed.extend(
                mapper(
                    project_id=run.project_id,
                    scan_id=run.scan_id,
                    raw_output=result.raw_output,
                    id_generator=self._id_generator,
                    clock=self._clock,
                )
            )
        return observed

    async def _persist(self, observed: list[Finding], run: NormalizationRun) -> list[str]:
        """Upsert each identity and record its sighting. Returns skipped hashes.

        **`collapse_by_identity` is called once per identity group rather than
        once over the whole list**, which is what bounds the blast radius of its
        raise to a single identity. It raises when a group disagrees on a
        rule-level attribute — normally a mapper bug, but reachable from data
        through the `"(unidentified)"` `rule_id` fallback (ADR-0019 decision 2).
        Called once over everything, one malformed element would abort a whole
        scan's normalization, which is the `PRODUCT_SPEC.md` §12 corruption the
        `Location` guard was removed to avoid, arriving through a different
        validation rule.

        The function itself is unchanged and both of its guards still fire: a
        single-group call checks the project boundary and the rule-level
        agreement alike, because both are checks *within* a group.

        **What does change for the project guard is its outcome, and the
        persisted reason is worded not to overstate it.** `collapse_by_identity`
        raises a bare `ValueError` for both conditions, so this handler cannot
        tell them apart; catching one and re-raising the other would mean matching
        on a message string, which is worse. The project case is inert today —
        one scan is one project — and its guard exists so the function enforces
        the same boundary `merge_observation` does rather than because a caller
        can reach it. If a caller ever can, this handler skipping it is still the
        right behaviour; what would need to change is the domain raising two
        distinct types so the reason can name the cause.
        """
        # The same one-line grouping collapse_by_identity does internally. Repeated
        # rather than exposed from the domain because what this needs is the
        # partition, not the collapse, and widening that function's return type to
        # hand back groups would make every other caller destructure something it
        # does not want.
        grouped: dict[str, list[Finding]] = {}
        for finding in observed:
            grouped.setdefault(finding.dedup_hash, []).append(finding)

        skipped: list[str] = []
        # Sorted so a scan's writes happen in a deterministic order regardless of
        # the order the tools emitted their elements — the same total order
        # collapse_by_identity and get_by_project_id already return in.
        for dedup_hash in sorted(grouped):
            try:
                collapsed = collapse_by_identity(grouped[dedup_hash])
            except ValueError:
                skipped.append(dedup_hash)
                continue
            for representative, match_count in collapsed:
                stored = await self._findings.upsert(representative)
                await self._findings.record_sighting(
                    FindingSighting(
                        # `stored.id`, NEVER `representative.id` (ADR-0020
                        # decision 5). Identity is the hash and `id` is a
                        # surrogate, so only the upsert settles which id wins: on
                        # every scan after the first, the observation's freshly
                        # generated id loses to the stored one, and a sighting
                        # written against the observation's id would point at a
                        # finding that does not exist.
                        finding_id=stored.id,
                        scan_id=run.scan_id,
                        observed_at=self._clock.now(),
                        match_count=match_count,
                    )
                )
        return skipped
