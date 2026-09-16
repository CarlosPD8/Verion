from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum

from verion.shared_kernel.scanner_tools import ScannerTool
from verion.shared_kernel.severity import Severity

# ADR-0005 decision 1's thresholds, named so the two places that read them — `bucket_for`
# and every test asserting a boundary — cannot drift apart.
FIX_NOW_AT = 6
PLAN_AT = 4

SEVERITY_SIGNAL = "severity_signal"
EXPOSURE_SIGNAL = "exposure_signal"
CORROBORATION_SIGNAL = "corroboration_signal"


class Priority(StrEnum):
    """The bucket a scored surface lands in. FR-7's first output."""

    FIX_NOW = "fix_now"
    PLAN = "plan"
    MONITOR = "monitor"


@dataclass(frozen=True, kw_only=True)
class SurfaceMember:
    """One member of a surface, as the three scalars scoring actually reads.

    **This is `risk_engine`'s own type over scalars, and it names nothing belonging to
    another module.** `cross-module-risk-engine` forbids `normalization.domain`, so
    `Finding` may not appear here or anywhere in this module; `ScannerTool` and `Severity`
    are `shared_kernel/`'s, which is the package ADR-0018 decision 2 exists to hold exactly
    such cross-module vocabularies.

    ADR-0005 decision 2 says the domain receives scalars at one keyword-only construction
    site, `build_match_key`'s shape. A per-member pair needs a carrier, so the single
    boundary is `score_surface` and this is the carrier it takes; the alternative, a bare
    `tuple[str, ScannerTool, Severity]`, is literally one site and unreadable at every
    call.
    """

    finding_id: str
    source: ScannerTool
    severity: Severity


@dataclass(frozen=True, kw_only=True)
class Signal:
    """One scored term: its value, and **the member that produced it**.

    `produced_by` is what makes rule 5 hold rather than being asserted. ADR-0005 decision 1
    requires a bucket to be re-derivable by hand, and a bare integer is not: a reader given
    `severity_signal = 4` cannot check it without being told which member was the HIGH one.
    A signal that contributed nothing carries an empty `produced_by` and a `note` saying
    why — the two are distinguishable, which is the property the `UNKNOWN` rule needs.
    """

    name: str
    value: int
    produced_by: tuple[str, ...]
    note: str | None = None


@dataclass(frozen=True, kw_only=True)
class RiskReasoning:
    """The three signals behind a bucket. FR-7's traceability, ADR-0003's constraint.

    **Carries no `explanation_text`.** `ARCHITECTURE.md` §4.1's design block names one, but
    prose is M7.1's — the LLM narrates a reasoning already decided and may never alter the
    priority (rule 6, ADR-0004). A text field here with nothing to put in it would invite
    exactly that.

    **Carries no `confidence` either, and that absence is a decision rather than an
    oversight** — see **G63**. FR-7 and ADR-0003 both require one; ADR-0005 deferred the
    scale and M6.2 records that it emits none, because choosing between a
    grouping-confidence and an evidence-confidence needs the consumer that renders it
    (M7.1).
    """

    severity: Signal
    exposure: Signal
    corroboration: Signal

    @property
    def signals(self) -> tuple[Signal, ...]:
        """The three, in the order they are summed."""
        return (self.severity, self.exposure, self.corroboration)


@dataclass(frozen=True, kw_only=True)
class ScoredSurface:
    """A scored candidate Risk: what was scored, the number, the bucket, and the working.

    **A SURFACE, not a vulnerability** — ADR-0005 decision 0. `package`/`url` are the key's
    fields, so this is "everything wrong with that package or route path". It is emphatically
    **not** "these findings describe the same vulnerability": group membership comes from the
    route map, and no available field separates a substantive cross-tool member from a
    coincidental one (**G62**). No text derived from this may claim otherwise.

    Carries no `id`: a candidate Risk is a projection with no identity (ADR-0025 decision 1),
    and this adds a score to it without adding a row.
    """

    project_id: str
    package: str | None
    url: str | None
    finding_ids: tuple[str, ...]
    priority_score: int
    priority: Priority
    reasoning: RiskReasoning


def bucket_for(priority_score: int) -> Priority:
    """The thresholds alone: `fix_now` at ≥ 6, `plan` at 4–5, `monitor` below 4.

    Split out of `score_surface` so a caller can bucket a score it computed some other way
    — which is what `PRODUCT_SPEC.md` §10's margin assertion needs: it subtracts the
    corroboration term from a real surface's score and asks which bucket the remainder
    falls in, without mutating this function and without constructing a member no scanner
    could emit.
    """
    if priority_score >= FIX_NOW_AT:
        return Priority.FIX_NOW
    if priority_score >= PLAN_AT:
        return Priority.PLAN
    return Priority.MONITOR


def _severity_signal(members: Sequence[SurfaceMember]) -> Signal:
    """Highest rank among members whose severity is **not** `UNKNOWN`; 0 if none.

    **`UNKNOWN` contributes nothing and is never the maximum** (ADR-0005 decision 1,
    answering the question `shared_kernel/severity.py` insisted M6 answer explicitly).
    `_RANK` puts `UNKNOWN` at 0 as a *sort position*, and reading that position as a score
    would decide by accident that "the tool did not know" means "least dangerous".

    Note what this costs in testability, because it is the reason the reasoning matters more
    than the number here: since `UNKNOWN`'s rank is 0 and the no-member fallback is also 0,
    including or excluding `UNKNOWN` produces an **identical score in every case**. Only
    `produced_by` and `note` tell the two apart.

    Ties are broken by the lowest `finding_id`, so the producer is deterministic.
    """
    stated = [member for member in members if member.severity is not Severity.UNKNOWN]
    if not stated:
        return Signal(
            name=SEVERITY_SIGNAL,
            value=0,
            produced_by=(),
            note="no member stated a severity",
        )

    top_rank = max(member.severity.rank for member in stated)
    producers = sorted(member.finding_id for member in stated if member.severity.rank == top_rank)
    return Signal(name=SEVERITY_SIGNAL, value=top_rank, produced_by=(producers[0],))


def _exposure_signal(members: Sequence[SurfaceMember]) -> Signal:
    """1 if any member's source is ZAP, else 0.

    **This is what a DAST member IS**, not FR-7's exposure: a ZAP finding exists because a
    scanner reached the surface over the network, which is explicit and already in the data.
    FR-7's exposure — the project's own statement about the asset — is declined for M6
    (ADR-0005 decision 4), since it exists only as `SecurityContext.exposure_tags`: free
    text behind a persistence port another module must not consume, and unreadable once a
    project has two context rows (**G55**).
    """
    reached = sorted(member.finding_id for member in members if member.source is ScannerTool.ZAP)
    if not reached:
        return Signal(
            name=EXPOSURE_SIGNAL,
            value=0,
            produced_by=(),
            note="no member was reported by a DAST scanner",
        )
    return Signal(name=EXPOSURE_SIGNAL, value=1, produced_by=(reached[0],))


def _corroboration_signal(members: Sequence[SurfaceMember]) -> Signal:
    """1 if the members carry two or more distinct sources, else 0.

    **It says two tools reported on one surface. It does NOT say they agree** — and the
    distinction is not pedantry, it is **G62**: measured over the committed corpus, the only
    passive instance of this signal has 4 of 4 DAST members that are header hygiene,
    unrelated to the SAST finding they are grouped with. No field on any member separates
    that from a substantive pair, so this fires identically on both. The name is
    `corroboration` rather than `agreement` for that reason, and no narrative built on it
    may say "two tools agree".

    `produced_by` carries **one representative per distinct source** — the lowest id in
    each — so a reader can see which tools the point came from rather than only that it was
    earned. Counting DISTINCT SOURCES is the whole rule: counting members instead would
    give `urllib3`'s twelve single-source findings the same point as a genuine cross-tool
    surface.
    """
    by_source: dict[ScannerTool, list[str]] = {}
    for member in members:
        by_source.setdefault(member.source, []).append(member.finding_id)

    if len(by_source) < 2:
        only = next(iter(by_source), None)
        note = (
            "the surface has no members"
            if only is None
            else f"every member was reported by {only.value}"
        )
        return Signal(name=CORROBORATION_SIGNAL, value=0, produced_by=(), note=note)

    representatives = tuple(sorted(min(ids) for ids in by_source.values()))
    return Signal(name=CORROBORATION_SIGNAL, value=1, produced_by=representatives)


def score_surface(
    *,
    project_id: str,
    package: str | None,
    url: str | None,
    members: Sequence[SurfaceMember],
) -> ScoredSurface:
    """Score one surface. Pure: no I/O, no clock, no id generator, no persistence.

    `priority_score = severity_signal + exposure_signal + corroboration_signal`, bucketed
    `fix_now ≥ 6` / `plan 4–5` / `monitor < 4`. The arithmetic is deliberately this small:
    ADR-0005 decision 1 requires every bucket to be re-derivable by hand from the reasoning,
    which is rule 5, and a weighted model would satisfy neither.

    **Refused inputs, each on a measured ground** (ADR-0005 decision 1): CVSS, which is 20/20
    on Trivy and absent from every member of the one cross-tool surface, so any CVSS term
    would rank every package group above it by construction; member count, since `urllib3`
    is n=12 against that surface's 5; CWE, which Semgrep never supplies (**G6**) and which a
    Trivy database refresh can rewrite underneath (**G26**); and `native_severity`, because
    comparing `ERROR` against `HIGH` across tools is the incomparable-scales problem ADR-0018
    decision 1 exists to prevent — the literal value stays provenance.

    **What this function cannot reach from real scanner output, recorded because a green test
    suite will not say so** (**G64**): only Trivy emits `CRITICAL`, and a Trivy finding is
    either package-keyed or — when the vulnerability carries no `PkgName` — keyed with no
    signal at all, which `group_by_match_key` makes a singleton. Either way it cannot share a
    surface with another tool, so a `CRITICAL` surface is always single-source and tops out at
    5 → `plan`. The only cross-source pairing `build_match_key` can produce is
    Semgrep-with-a-derived-route plus ZAP, so **corroboration implies exposure**, and the only
    reachable decomposition of 6 is `4 + 1 + 1`: a route-path surface carrying both tools with
    at least one `HIGH` member. **That `HIGH` may come from EITHER tool** — ZAP's riskcode 3
    maps to `HIGH`, exhibited by the committed active capture — so a Semgrep `ERROR` is
    sufficient but not necessary. A `CRITICAL` dependency CVE can never exceed `plan`.
    """
    severity = _severity_signal(members)
    exposure = _exposure_signal(members)
    corroboration = _corroboration_signal(members)
    priority_score = severity.value + exposure.value + corroboration.value

    return ScoredSurface(
        project_id=project_id,
        package=package,
        url=url,
        finding_ids=tuple(member.finding_id for member in members),
        priority_score=priority_score,
        priority=bucket_for(priority_score),
        reasoning=RiskReasoning(severity=severity, exposure=exposure, corroboration=corroboration),
    )
