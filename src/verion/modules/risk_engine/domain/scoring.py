from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum

from verion.shared_kernel.confidence import Confidence
from verion.shared_kernel.scanner_tools import ScannerTool
from verion.shared_kernel.severity import Severity

# ADR-0005 decision 1's thresholds, named so the two places that read them — `bucket_for`
# and every test asserting a boundary — cannot drift apart.
FIX_NOW_AT = 6
PLAN_AT = 4

SEVERITY_SIGNAL = "severity_signal"
EXPOSURE_SIGNAL = "exposure_signal"
CORROBORATION_SIGNAL = "corroboration_signal"

# What each signal MEANS, in words a reader outside this module can be given verbatim —
# today the Explanation Layer's prompt (M7.1, ADR-0032). Declared here, beside the
# functions that compute them, so this module stays the single owner of what its numbers
# claim: `brief` forwards these strings and never writes its own description of a signal.
# Each one states the limit of its signal, because a narrative can overstate a number
# only where the number's meaning is left to the narrator.
SEVERITY_DEFINITION = (
    "The highest severity any scanner stated for a finding on this surface, as a rank "
    "from 1 (info) to 5 (critical). A finding whose severity the scanner did not know "
    "contributes nothing."
)
EXPOSURE_DEFINITION = (
    "1 when a dynamic (DAST) scanner reached this surface over the network, otherwise 0. "
    "It is not a statement about how exposed the deployed application is."
)
CORROBORATION_DEFINITION = (
    "1 when findings on this surface were reported by two or more different scanners, "
    "otherwise 0. It means only that more than one scanner reported something on the "
    "same surface. It does not mean the scanners agree, confirm each other, or found the "
    "same vulnerability."
)


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

    **`confidence` joined at M8.5** (ADR-0037) and is a fourth scalar rather than an
    exception to that rule: `Confidence` is `shared_kernel`'s, like the two above it, so
    this module still names nothing belonging to `correlation`. A bare `str` was rejected
    for this field specifically — it would let `"inferrd"` type-check on a frozen domain
    type feeding three routes, and a typo must be a type error.
    """

    finding_id: str
    source: ScannerTool
    severity: Severity
    confidence: Confidence


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
    prose is the Explanation Layer's — the LLM narrates a reasoning already decided and may
    never alter the priority (rule 6, ADR-0004). A text field here with nothing to put in it
    would invite exactly that. What crosses to that layer is a copy of this reasoning,
    `risk_engine/ports/explainable_decision.py`, filled inside this module (ADR-0032).

    **Carries no `confidence`, and since M8.5 that is a PLACEMENT rather than an absence.**
    A Risk has one — its grouping provenance — and it lives on `ScoredSurface`, not here,
    because this type is the three summed signals and the confidence is summed into nothing
    (ADR-0037 decision 7). Adding it here would make it look like a fourth term.
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

    **`confidence` is carried BESIDE the score and is never summed into it** (M8.5,
    ADR-0037 decision 7). It is the surface's grouping provenance, folded from its members
    by `_confidence`. It is not a signal: it is not in `RiskReasoning`, it has no
    `produced_by`, and `priority_score` is the same three terms it has been since M6.2.
    """

    project_id: str
    package: str | None
    url: str | None
    finding_ids: tuple[str, ...]
    priority_score: int
    priority: Priority
    reasoning: RiskReasoning
    confidence: Confidence


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
    may say "two tools agree" — which is why `CORROBORATION_DEFINITION` states that limit
    in the words the Explanation Layer forwards to its model (M7.1, ADR-0032).

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


def _confidence(members: Sequence[SurfaceMember]) -> Confidence:
    """The surface's grouping provenance, folded over its members. M8.5, ADR-0037 decision 6.

    `INFERRED` if any member is; else `UNGROUPED` if any member is; else `REPORTED`.

    **Total, and the second branch is reachable only for a surface of one.** `UNGROUPED`
    means the member's key carried no signal, and `group_by_match_key` makes such a finding a
    singleton — so a mixed `UNGROUPED`/`REPORTED` surface cannot be produced by the shipped
    grouping. The branch is written anyway rather than asserted away, because this function
    takes members and not a group, and a fold that raised or guessed on an input the type
    admits would be deciding by accident.

    **The fold lives here rather than in `correlation` because a SURFACE is this module's
    unit** (ADR-0005 decision 0): "this surface's membership was partly inferred" is a
    statement about the thing being scored. `correlation` supplies the per-member facts and
    does not decide what they mean for a group.

    **`INFERRED` wins on ANY member**, not a majority or all: the claim it qualifies is that
    the group is what it says it is, and one inferred member is enough to make that partly
    Verion's inference rather than the scanners'.

    **A surface with NO members folds to `REPORTED`**, which is vacuous rather than wrong —
    "no member was placed by inference" is true of an empty surface. It is unreachable through
    `ComputeRiskUseCase`, where a group always has at least one member and a member the second
    read cannot supply raises `MemberFindingMissing`. Stated because `score_surface` accepts
    the input and `test_a_surface_with_no_members_scores_zero_rather_than_raising` exercises
    it, so the value is observable even though no pipeline produces it.
    """
    if any(member.confidence is Confidence.INFERRED for member in members):
        return Confidence.INFERRED
    if any(member.confidence is Confidence.UNGROUPED for member in members):
        return Confidence.UNGROUPED
    return Confidence.REPORTED


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

    **A consequence of that closure, and the ground for not summing `confidence` into the
    score** (M8.5, ADR-0037 decision 7): the only cross-source pairing is a route-derived
    Semgrep member with a ZAP member, so **every `fix_now` surface reachable from real
    scanner output contains an `INFERRED` member**. A term penalising `inferred` would close
    the top bucket outright; one rewarding it would reward inference. Corpus-bounded like the
    paragraph above it, and that ADR carries the reopen conditions — the strongest being a
    mapper change that gives a Semgrep finding a `Location.url`, which no **G64** clause
    reaches.
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
        # Folded, not summed. `priority_score` above is the same three terms as at M6.2.
        confidence=_confidence(members),
    )


def _rank_order(surface: ScoredSurface) -> tuple[int, str, bool, str, bool, str, str]:
    """`correlation`'s `_group_order` tuple, behind a descending score.

    **Copied rather than imported**, for the reason that function gives about copying
    `_representative_key`: it is private and sits on the far side of
    `cross-module-risk-engine`. `None` sorts before a value (`False < True`), and the
    lowest member id is the final tiebreak — unique across surfaces, so no two can tie
    on it and the order is total rather than merely deterministic.

    A surface with no members sorts on an empty id. `score_surface` admits one
    (`test_a_surface_with_no_members_scores_zero_rather_than_raising`) while
    `group_by_match_key` cannot produce one, so this is a totality guard rather than a
    reachable case.
    """
    return (
        -surface.priority_score,
        surface.project_id,
        surface.package is not None,
        surface.package or "",
        surface.url is not None,
        surface.url or "",
        surface.finding_ids[0] if surface.finding_ids else "",
    )


def rank_surfaces(surfaces: Sequence[ScoredSurface]) -> list[ScoredSurface]:
    """Highest priority first, tie-broken so the order AGREES with the unscored listing.

    **In `domain/` rather than in the route**, per ADR-0030 decision 2: an ordering
    contract living in an inbound adapter is one no unit test reaches. `ComputeRiskUseCase`
    deliberately does not call this — it returns `correlation`'s group order, and
    `test_the_order_is_correlations_group_order_and_not_a_priority_order` pins that — so
    ranking enters only at the use case behind the scored route.

    **Descending `priority_score`, then `_group_order`'s own tuple.** Within one bucket the
    two routes therefore return the same relative order, and a reader comparing them sees
    one order refined rather than two unrelated ones. That agreement is an invariant across
    two modules, one of them private, so `tests/unit/test_ranking.py` imports **both**
    orderings and asserts they agree on a tie: a copied invariant with nothing checking it
    is a prose claim over a silent divergence, which is this project's recorded failure
    class.
    """
    return sorted(surfaces, key=_rank_order)
