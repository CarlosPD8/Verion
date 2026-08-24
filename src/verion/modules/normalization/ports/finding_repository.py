from typing import Protocol

from verion.modules.normalization.domain.finding import Finding, FindingSighting, SightedFinding
from verion.shared_kernel.scanner_tools import ScannerTool
from verion.shared_kernel.severity import Severity


class FindingRepositoryPort(Protocol):
    """Persistence for the identity model ADR-0019 decided, plus M4.5's read side.

    Until M4.5 every read here was **by a key**, and the docstring said why: a
    filtered or paginated listing would encode a staleness rule, an ordering and a
    filter vocabulary that were M4.5's to choose — the same line ADR-0017 decision
    2 drew between shipping `get_by_scan_id` and deferring the sweep query. **That
    deferral is discharged**, and `list_for_project`/`count_for_project` below
    carry the choices it was waiting for: rank-descending order derived from
    `Severity.rank`, `min_severity`/`source` as the whole filter vocabulary, and
    limit/offset paging.

    **What is still deliberately absent is anything scan-relative.** There is no
    `get_by_scan_id`, no "still open" predicate and no sighting query keyed by
    scan. Those want a scan-first index on `finding_sightings` (`scan_id` is not
    the leading column of its primary key) — and, more importantly, "not sighted
    in scan N" only means resolved for the tools that SUCCEEDED in scan N
    (ADR-0019's Consequences). Both belong to M9.1, together, which is where the
    index ships in the migration carrying its query.
    """

    async def upsert(self, finding: Finding) -> Finding:
        """Insert this finding, or fold it into the stored one, and return the result.

        **`merge_observation` is the executable spec for what this does**, and
        implementations must not re-invent the policy in an `ON CONFLICT DO
        UPDATE` clause. The two agree because that function's refresh set is
        *total except the two surrogate ids*: it keeps `existing.id` and
        `existing.evidence.id` and takes every other value from the observation.
        See ADR-0020 — including the condition under which that equivalence
        stops holding.

        **Returns the resolved `Finding`, and the return type is load-bearing.**
        Identity is the hash and `id` is a surrogate, so only this upsert settles
        which id wins (ADR-0019 decision 1). `NormalizeScanUseCase` cannot
        construct a `FindingSighting` without it, and since M4.4 it does exactly
        that: `finding_id=stored.id`, never the observation's own. That is why
        this returns a value where
        `NormalizationRunRepositoryPort.request` returns `None`: there, both
        outcomes of the conflict mean the same thing to the caller and no caller
        branches; here the caller's next write depends on the answer.
        """
        ...

    async def record_sighting(self, sighting: FindingSighting) -> None:
        """Record that this scan observed this finding. Idempotent.

        **`match_count` is the complete per-scan total, never an increment**, and
        this method overwrites it rather than adding to it. That is the contract,
        not an implementation detail:

        - Overwriting is the only *idempotent* option, and idempotency is the
          requirement — `ARCHITECTURE.md` §9 says re-normalizing a scan refreshes
          rows rather than adding them, and an arq retry re-running every enabled
          scanner is guaranteed rather than hypothetical (ADR-016 decision 1).
        - Summing would therefore double-count on every retry, silently.
        - `ON CONFLICT DO NOTHING` would leave a stale count and never refresh
          `observed_at`. ADR-0017's reason for choosing it there does not
          transfer: that row carries a state machine `DO UPDATE` would reset, and
          a sighting has none.

        So a caller that computes the total in more than one pass over a scan
        must **aggregate before calling**, not call twice. `collapse_by_identity`
        produces the total in one pass, which is what makes `NormalizeScanUseCase`
        satisfy this — it maps every succeeded tool's output into ONE list and
        collapses that, rather than batching per tool;
        per-tool batching is also safe by construction, since `source` is a
        `dedup_hash` input and no `(finding_id, scan_id)` can span two tools.
        Chunking *within* one tool's output is the case that would break it.
        """
        ...

    async def list_for_project(
        self,
        *,
        project_id: str,
        min_severity: Severity | None,
        source: ScannerTool | None,
        limit: int,
        offset: int,
    ) -> list[SightedFinding]:
        """One page of a project's findings, each with its sighting aggregate.

        **`min_severity` is a `Severity`, not a `str`, and that annotation is a
        gate rather than documentation.** `Severity.HIGH == "high"` is True but
        `Severity.HIGH >= "high"` raises (ADR-0018 decision 2) — equality survives
        an HTTP boundary and ordering does not. Declaring the parameter as the
        enum makes `mypy --strict` reject an uncoerced query parameter here, so
        the coercion cannot be forgotten at the one place it has to happen.

        Implementations filter by **rank**, so `min_severity` means "this rank or
        higher". One consequence is sharp enough to be part of the contract rather
        than an implementation note: `UNKNOWN` ranks lowest, *below* `INFO`, so
        any `min_severity` other than `UNKNOWN` itself **excludes findings whose
        severity no tool could determine**. `min_severity=UNKNOWN` is rank 0 and
        therefore a no-op that returns everything.

        Ordered by rank descending, then `dedup_hash` as a total tiebreak so the
        order is deterministic regardless of insertion order. `UNKNOWN` therefore
        sorts last — the display convention `Severity`'s own docstring declares,
        honoured rather than re-decided here.

        Ordering and paging are the caller's question, so no page/total wrapper
        type is returned: `total` is `count_for_project`, and the envelope is the
        inbound adapter's to assemble (`ARCHITECTURE.md` §6.1).
        """
        ...

    async def count_for_project(
        self, *, project_id: str, min_severity: Severity | None, source: ScannerTool | None
    ) -> int:
        """How many findings `list_for_project` would return unpaged.

        Separate from the listing rather than bundled into a page object, because
        the two are genuinely separate questions — M8.2's dashboard will want the
        count without a page — and because a `(items, total)` dataclass has fields
        that are artifacts of a request rather than facts about a finding, so it
        belongs in neither `domain/` nor a port.

        **The cost, stated because `DO UPDATE`-style invisibility is how this kind
        of thing gets missed:** two statements under Postgres's default READ
        COMMITTED, so a normalization committing between them can leave `total`
        disagreeing with the page by a row. Same class of inconsistency offset
        paging already carries, not a new one, and bounded the same way — writes
        arrive per scan rather than continuously.
        """
        ...

    async def get_by_project_id(self, project_id: str) -> list[Finding]:
        """Every finding in a project, unfiltered, unpaged, with no sighting join.

        **Kept when M4.5 added `list_for_project`, rather than replaced by it, and
        the reason is a real difference rather than inertia.** `list_for_project`
        enforces the invariant that every finding has at least one sighting — true
        in production, because `NormalizeScanUseCase` writes both in one
        transaction, and it raises otherwise because a finding silently vanishing
        from a listing is the worse failure. This method does not, so it can read
        a finding that the *write path* stored without a sighting.

        That is what the write-path tests need, and it matters that they do not
        share a reader with the listing: if the only way to verify `upsert` were
        through `list_for_project`, a defect in the sighting join could mask a
        defect in the upsert, and the suite would be checking the read path
        against itself. Same reasoning ADR-0020 decision 4 gives for `upsert`
        returning a `RETURNING` row rather than the object it was handed.

        Ordered by `dedup_hash` — the same total order `collapse_by_identity`
        returns in — deliberately NOT by the listing's severity rank, so that this
        read carries none of M4.5's display policy.
        """
        ...

    async def get_by_id(self, *, project_id: str, finding_id: str) -> Finding | None:
        """One finding, scoped to a project. `None` if it is not in THAT project.

        **The `project_id` is a filter, not a convenience.** Without it a caller
        authorized for project A could pass a finding id from project B and read
        its evidence — which is a verbatim copy of another tenant's scanned source.
        Scoping in the query rather than fetching-then-checking also makes "no such
        finding" and "someone else's finding" the same answer, so the route's 404
        leaks nothing about which ids exist elsewhere.
        """
        ...

    async def get_sightings_by_finding_id(self, finding_id: str) -> list[FindingSighting]: ...
