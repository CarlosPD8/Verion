"""The scoring function itself, over scalars. ADR-0005 decision 1.

**Every `SurfaceMember` in this file is hand-written, and that is this issue's one
instance of G19** — synthetic input whose shape differs from production. Two of the
combinations below are impossible for any pipeline to emit: no ZAP finding is ever
`CRITICAL` (ADR-0018 decision 1 gives ZAP a `HIGH` ceiling), and no Trivy finding ever
shares a match key with a Semgrep one. They are exercised anyway, because the arithmetic
admits them and an untested branch of a scoring function is worse than a synthetic input
that is labelled — which is what the `UNREACHABLE` ids below do. The pipeline-level
consequence is **G64**; `test_compute_risk.py` is where the reachable route is scored
through the real mappers.
"""

import typing

import pytest

from verion.modules.risk_engine.domain.scoring import (
    CORROBORATION_SIGNAL,
    EXPOSURE_SIGNAL,
    SEVERITY_SIGNAL,
    Priority,
    ScoredSurface,
    SurfaceMember,
    bucket_for,
    score_surface,
)
from verion.shared_kernel.confidence import Confidence
from verion.shared_kernel.scanner_tools import ScannerTool
from verion.shared_kernel.severity import Severity

PROJECT = "proj-1"


def _member(finding_id, source, severity, confidence=Confidence.REPORTED):
    """`confidence` defaults here and NOT on `SurfaceMember` itself, deliberately.

    A default on the frozen domain type would let a real caller omit the field and silently
    get `REPORTED` — an inferred member labelled as reported, which is exactly the mutation
    the provenance exists to make impossible. Defaulting in this helper keeps the scoring
    tests readable while leaving the production construction site required.
    """
    return SurfaceMember(
        finding_id=finding_id, source=source, severity=severity, confidence=confidence
    )


def _score(*members, package=None, url="/thing"):
    return score_surface(project_id=PROJECT, package=package, url=url, members=list(members))


# --- the severity term ---------------------------------------------------------------


def test_the_severity_term_is_the_highest_rank_and_names_the_member_that_produced_it():
    scored = _score(
        _member("f-low", ScannerTool.TRIVY, Severity.LOW),
        _member("f-high", ScannerTool.TRIVY, Severity.HIGH),
        _member("f-medium", ScannerTool.TRIVY, Severity.MEDIUM),
    )

    assert scored.reasoning.severity.value == Severity.HIGH.rank == 4
    assert scored.reasoning.severity.produced_by == ("f-high",)
    assert scored.reasoning.severity.name == SEVERITY_SIGNAL


def test_unknown_is_excluded_from_the_maximum_rather_than_ranked_at_the_bottom_of_it():
    """ADR-0005 decision 1: UNKNOWN contributes nothing and is never the maximum."""
    scored = _score(
        _member("f-unknown", ScannerTool.TRIVY, Severity.UNKNOWN),
        _member("f-medium", ScannerTool.TRIVY, Severity.MEDIUM),
    )

    assert scored.reasoning.severity.value == Severity.MEDIUM.rank == 3
    assert scored.reasoning.severity.produced_by == ("f-medium",)


def test_a_surface_whose_every_member_is_unknown_scores_zero_and_names_no_producer():
    """**The only assertion in the suite that can kill "let UNKNOWN contribute its rank".**

    `_RANK["unknown"]` is 0 and the no-member fallback is also 0, so that mutation produces
    an identical `priority_score` on every input in this repository. What distinguishes the
    two is the reasoning: correct behaviour names no producer and says no tool stated a
    severity; the mutation names the UNKNOWN member as the one that produced a 0.
    """
    scored = _score(
        _member("f-a", ScannerTool.TRIVY, Severity.UNKNOWN),
        _member("f-b", ScannerTool.TRIVY, Severity.UNKNOWN),
    )

    assert scored.reasoning.severity.value == 0
    assert scored.reasoning.severity.produced_by == ()
    assert scored.reasoning.severity.note == "no member stated a severity"
    assert scored.priority is Priority.MONITOR


def test_a_severity_tie_is_broken_by_the_lowest_finding_id_so_the_producer_is_deterministic():
    scored = _score(
        _member("f-z", ScannerTool.TRIVY, Severity.HIGH),
        _member("f-a", ScannerTool.TRIVY, Severity.HIGH),
    )

    assert scored.reasoning.severity.produced_by == ("f-a",)


# --- the exposure term ---------------------------------------------------------------


def test_exposure_is_earned_by_a_dast_member_and_names_it():
    scored = _score(
        _member("f-sast", ScannerTool.SEMGREP, Severity.HIGH),
        _member("f-dast", ScannerTool.ZAP, Severity.INFO),
    )

    assert scored.reasoning.exposure.value == 1
    assert scored.reasoning.exposure.produced_by == ("f-dast",)
    assert scored.reasoning.exposure.name == EXPOSURE_SIGNAL


def test_a_surface_no_dast_scanner_reached_scores_no_exposure_and_says_so():
    scored = _score(_member("f-a", ScannerTool.TRIVY, Severity.CRITICAL))

    assert scored.reasoning.exposure.value == 0
    assert scored.reasoning.exposure.produced_by == ()
    assert scored.reasoning.exposure.note == "no member was reported by a DAST scanner"


# --- the corroboration term ----------------------------------------------------------


def test_corroboration_is_earned_by_two_distinct_sources_and_names_one_member_per_source():
    scored = _score(
        _member("f-zap-2", ScannerTool.ZAP, Severity.LOW),
        _member("f-semgrep", ScannerTool.SEMGREP, Severity.HIGH),
        _member("f-zap-1", ScannerTool.ZAP, Severity.MEDIUM),
    )

    assert scored.reasoning.corroboration.value == 1
    # One representative per source, lowest id in each, sorted.
    assert scored.reasoning.corroboration.produced_by == ("f-semgrep", "f-zap-1")
    assert scored.reasoning.corroboration.name == CORROBORATION_SIGNAL


def test_many_members_from_one_tool_earn_no_corroboration_however_many_there_are():
    """**The only assertion that can kill "count members instead of distinct sources".**

    Across the Trivy package surfaces that mutation changes no bucket — every one moves
    4 → 5 and stays in `plan`, because each tops out at `HIGH` — and the one cross-tool
    surface scores 1 either way. It is **not** bucket-invariant everywhere: the
    `zap_synthetic_edges.json` `/` surface has two members and would move 3 → 4, crossing
    into `plan`. No test asserts that surface's bucket, so in practice this value assertion
    is what kills the mutation. Sibling of the UNKNOWN case above for that reason.
    `urllib3`'s twelve single-source findings are the real instance.
    """
    scored = _score(
        *(_member(f"f-{index}", ScannerTool.TRIVY, Severity.HIGH) for index in range(12)),
        package="urllib3",
        url=None,
    )

    assert scored.reasoning.corroboration.value == 0
    assert scored.reasoning.corroboration.produced_by == ()
    assert scored.reasoning.corroboration.note == "every member was reported by trivy"
    assert scored.priority_score == 4
    assert scored.priority is Priority.PLAN


# --- the buckets ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("priority_score", "expected"),
    [
        (0, Priority.MONITOR),
        (3, Priority.MONITOR),
        (4, Priority.PLAN),
        (5, Priority.PLAN),
        (6, Priority.FIX_NOW),
        (7, Priority.FIX_NOW),
    ],
)
def test_the_bucket_boundaries_are_where_adr_0005_put_them(priority_score, expected):
    assert bucket_for(priority_score) is expected


@pytest.mark.parametrize(
    "members",
    [
        pytest.param(
            [_member("f-1", ScannerTool.ZAP, Severity.CRITICAL)],
            id="5+1+0-exposure-only-UNREACHABLE-no-zap-finding-is-critical",
        ),
        pytest.param(
            [
                _member("f-1", ScannerTool.TRIVY, Severity.CRITICAL),
                _member("f-2", ScannerTool.SEMGREP, Severity.LOW),
            ],
            id="5+0+1-corroboration-only-UNREACHABLE-corroboration-implies-exposure",
        ),
        pytest.param(
            [
                _member("f-1", ScannerTool.SEMGREP, Severity.HIGH),
                _member("f-2", ScannerTool.ZAP, Severity.LOW),
            ],
            id="4+1+1-reachable-a-semgrep-error-on-a-derived-path-plus-a-zap-alert",
        ),
    ],
)
def test_every_arithmetic_route_the_function_admits_reaches_fix_now(members):
    """Named for the ARITHMETIC, not the route, because two of the three are unreachable.

    The ids carry which. See this module's docstring and **G64**: with real scanner output
    only the third occurs, because `CRITICAL` is Trivy-only and package-keyed while
    corroboration can only arise from a Semgrep/ZAP pair, which also carries exposure.
    """
    scored = score_surface(project_id=PROJECT, package=None, url="/thing", members=members)

    assert scored.priority_score == 6
    assert scored.priority is Priority.FIX_NOW


def test_a_critical_surface_with_neither_other_signal_is_plan_not_fix_now():
    """The closure that makes the §10 comparison meaningful, at the domain layer."""
    scored = _score(_member("f-1", ScannerTool.TRIVY, Severity.CRITICAL), package="p", url=None)

    assert scored.priority_score == 5
    assert scored.priority is Priority.PLAN


# --- the record as a whole -----------------------------------------------------------


def test_the_score_is_the_sum_of_exactly_the_three_recorded_signals():
    """Rule 5, mechanically: a bucket is re-derivable from the reasoning alone."""
    scored = _score(
        _member("f-sast", ScannerTool.SEMGREP, Severity.HIGH),
        _member("f-dast", ScannerTool.ZAP, Severity.MEDIUM),
    )

    assert [signal.value for signal in scored.reasoning.signals] == [4, 1, 1]
    assert sum(signal.value for signal in scored.reasoning.signals) == scored.priority_score
    assert scored.priority is bucket_for(scored.priority_score)


def test_every_signal_that_contributed_names_a_member_the_surface_actually_holds():
    scored = _score(
        _member("f-sast", ScannerTool.SEMGREP, Severity.HIGH),
        _member("f-dast", ScannerTool.ZAP, Severity.MEDIUM),
    )

    for signal in scored.reasoning.signals:
        if signal.value:
            assert signal.produced_by, f"{signal.name} contributed without naming a member"
            assert set(signal.produced_by) <= set(scored.finding_ids)
        else:
            assert signal.produced_by == ()
            assert signal.note is not None


def test_a_surface_carries_its_key_fields_and_its_members_and_no_identifier():
    scored = _score(_member("f-1", ScannerTool.TRIVY, Severity.LOW), package="flask", url=None)

    assert scored.project_id == PROJECT
    assert scored.package == "flask"
    assert scored.url is None
    assert scored.finding_ids == ("f-1",)
    # ADR-0025 decision 1: a candidate Risk is a projection with no identity.
    assert not hasattr(scored, "id")


def test_a_scored_surface_carries_its_confidence_and_the_reasoning_does_not():
    """M8.5 (ADR-0037), replacing M6.2's absence assertion, which **G63** owed.

    Both halves matter. The surface HAS one, so FR-8's fourth part has a producer; and
    `RiskReasoning` does NOT, because it is the three summed signals and this is summed into
    nothing. A confidence on the reasoning would read as a fourth term.
    """
    scored = _score(_member("f-1", ScannerTool.TRIVY, Severity.LOW))

    assert scored.confidence is Confidence.REPORTED
    assert not hasattr(scored.reasoning, "confidence")


def test_a_surface_with_one_inferred_member_is_inferred():
    """The fold is ANY, not all, and not a majority. ADR-0037 decision 6.

    The `/calculate` shape: a Semgrep member placed by the route map beside ZAP members that
    attached through their own url. One inferred member makes the group partly Verion's
    inference, which is the whole claim the value qualifies.
    """
    scored = _score(
        _member("f-sast", ScannerTool.SEMGREP, Severity.HIGH, Confidence.INFERRED),
        _member("f-dast-1", ScannerTool.ZAP, Severity.MEDIUM),
        _member("f-dast-2", ScannerTool.ZAP, Severity.LOW),
    )

    assert scored.confidence is Confidence.INFERRED


def test_a_surface_whose_members_all_attached_off_their_own_fields_is_reported():
    scored = _score(
        _member("f-1", ScannerTool.TRIVY, Severity.HIGH),
        _member("f-2", ScannerTool.TRIVY, Severity.LOW),
    )

    assert scored.confidence is Confidence.REPORTED


def test_a_no_signal_singleton_is_ungrouped_rather_than_reported():
    """The case the two-value scale the register drafted had no word for.

    `read`/`derived` would have called this `read`, claiming the membership came off a field
    the scanner reported when nothing came off anything: the key carried no signal, so nothing
    was grouped at all.
    """
    scored = _score(_member("f-1", ScannerTool.SEMGREP, Severity.HIGH, Confidence.UNGROUPED))

    assert scored.confidence is Confidence.UNGROUPED


def test_the_confidence_is_not_summed_into_the_score():
    """ADR-0037 decision 7: carried beside the score, never a fourth term.

    Two surfaces identical but for their members' provenance score the same and bucket the
    same. Without this, a later reader could add a term and every bucket assertion above would
    still pass, because none of them varies provenance.
    """
    reported = _score(_member("f-1", ScannerTool.ZAP, Severity.HIGH))
    inferred = _score(_member("f-1", ScannerTool.ZAP, Severity.HIGH, Confidence.INFERRED))

    assert reported.priority_score == inferred.priority_score
    assert reported.priority is inferred.priority
    assert reported.confidence is not inferred.confidence


def test_the_member_confidence_crosses_as_the_shared_vocabulary_and_not_a_bare_string():
    """A typo must be a type error, so the annotation is the enum and not `str`.

    `lint-imports` already stops this module naming a `correlation` type; it cannot see which
    annotation was chosen instead, and `str` would let `"inferrd"` type-check on a frozen
    domain type feeding three routes. Read through `get_type_hints` so the assertion is about
    the resolved annotation rather than about a string spelling of it.
    """
    assert typing.get_type_hints(SurfaceMember)["confidence"] is Confidence
    assert typing.get_type_hints(ScoredSurface)["confidence"] is Confidence


def test_a_surface_with_no_members_scores_zero_rather_than_raising():
    scored = score_surface(project_id=PROJECT, package=None, url="/empty", members=[])

    assert scored.priority_score == 0
    assert scored.priority is Priority.MONITOR
    assert scored.reasoning.corroboration.note == "the surface has no members"
