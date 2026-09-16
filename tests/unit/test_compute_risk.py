"""`ComputeRiskUseCase`, and `PRODUCT_SPEC.md` §10's demonstration.

**No `Finding` in this file is hand-written.** Every one is produced by the real mapper
from a committed capture, and every group by correlation's real `build_match_key` and
`group_by_match_key` — so the shapes are production's by construction rather than by a
conformance check, and **G40**'s count of hand-written values is unchanged by this issue.
The one synthetic thing here is the `paths_serving` stub, which stands in for a route map
that `tests/integration/test_derived_group_end_to_end.py` already exercises for real.
"""

import pytest

from verion.modules.correlation.application.match_key_builder import build_match_key
from verion.modules.correlation.domain.matching import group_by_match_key
from verion.modules.correlation.ports.candidate_risk import CandidateRiskAccessDenied
from verion.modules.normalization.domain.mappers.semgrep import map_semgrep_output
from verion.modules.normalization.domain.mappers.trivy import map_trivy_output
from verion.modules.normalization.domain.mappers.zap import map_zap_output
from verion.modules.risk_engine.application.compute_risk import ComputeRiskUseCase
from verion.modules.risk_engine.domain.exceptions import MemberFindingMissing
from verion.modules.risk_engine.domain.scoring import Priority, bucket_for
from verion.shared_kernel.scanner_tools import ScannerTool

PROJECT = "proj-1"
USER = "user-1"

_SEMGREP = "semgrep_scan.json"
_TRIVY_EDGES = "trivy_synthetic_edges.json"
_ZAP = "zap_scan.json"
_ZAP_EDGES = "zap_synthetic_edges.json"


class FakeCandidateRisks:
    """`CandidateRiskPort` — hands back groups built here. Records its calls."""

    def __init__(self, groups):
        self._groups = groups
        self.calls = []

    async def candidate_risks(self, *, project_id, user_id):
        self.calls.append((project_id, user_id))
        return self._groups


class DenyingCandidateRisks:
    """`CandidateRiskPort` that refuses, as it does for a caller who may not read."""

    async def candidate_risks(self, *, project_id, user_id):
        raise CandidateRiskAccessDenied(f"No readable project with id '{project_id}'")


def _serves_calculate(*, file_path, line):
    """The route map's answer for the demo target: `app.py` line 28 is served by /calculate.

    ADR-0029 decision 4's derivation, stubbed. The real map is built from the repository
    archive at Security Context time and read through `RouteMapPort`.
    """
    return ("/calculate",) if file_path == "app.py" and line == 28 else ()


def _map_all(scanner_fixture, id_generator, clock, *, semgrep=None, trivy=None, zap=None):
    findings = []
    for name, mapper in (
        (semgrep, map_semgrep_output),
        (trivy, map_trivy_output),
        (zap, map_zap_output),
    ):
        if name is None:
            continue
        findings.extend(
            mapper(
                project_id=PROJECT,
                scan_id="scan-1",
                raw_output=scanner_fixture(name),
                id_generator=id_generator,
                clock=clock,
            )
        )
    return findings


def _group(findings, paths_serving=None):
    return group_by_match_key(
        [
            (
                finding.id,
                build_match_key(
                    project_id=finding.project_id,
                    package=finding.location.package,
                    url=finding.location.url,
                    file_path=finding.location.file_path,
                    start_line=finding.location.start_line,
                    paths_serving=paths_serving,
                ),
            )
            for finding in findings
        ]
    )


async def _score(finding_repository, findings, groups):
    for finding in findings:
        await finding_repository.upsert(finding)
    use_case = ComputeRiskUseCase(
        candidate_risks=FakeCandidateRisks(groups), findings=finding_repository
    )
    return await use_case.execute(project_id=PROJECT, user_id=USER)


def _by_key(surfaces):
    return {(surface.package, surface.url): surface for surface in surfaces}


# --- the use case ---------------------------------------------------------------------


async def test_a_denied_caller_never_reaches_the_findings_read(exploding_finding_repository):
    """The gate is the port's, and this proves scoring adds no read in front of it."""
    use_case = ComputeRiskUseCase(
        candidate_risks=DenyingCandidateRisks(), findings=exploding_finding_repository
    )

    with pytest.raises(CandidateRiskAccessDenied):
        await use_case.execute(project_id=PROJECT, user_id=USER)


async def test_a_group_naming_an_absent_finding_raises_rather_than_scoring_a_short_surface(
    finding_repository, scanner_fixture, id_generator, clock
):
    """The two reads are separate and untransacted (**G61**); disagreement must be loud."""
    findings = _map_all(scanner_fixture, id_generator, clock, trivy=_TRIVY_EDGES)
    groups = _group(findings)

    use_case = ComputeRiskUseCase(
        candidate_risks=FakeCandidateRisks(groups), findings=finding_repository
    )

    # The groups are real; the repository was never populated.
    with pytest.raises(MemberFindingMissing):
        await use_case.execute(project_id=PROJECT, user_id=USER)


async def test_the_port_is_asked_for_the_project_and_caller_the_use_case_was_given(
    finding_repository, scanner_fixture, id_generator, clock
):
    """Pins the two ids and their order at the port boundary.

    Without this, swapping them — `candidate_risks(project_id=user_id, user_id=project_id)` —
    passes the whole suite, because every other test here fakes the port and never inspects
    what it was asked. Against the real `CorrelationCandidateRisks` that swap denies every
    caller, and the failure would first surface at M6.3's endpoint.
    """
    findings = _map_all(scanner_fixture, id_generator, clock, trivy=_TRIVY_EDGES)
    port = FakeCandidateRisks(_group(findings))
    for finding in findings:
        await finding_repository.upsert(finding)

    use_case = ComputeRiskUseCase(candidate_risks=port, findings=finding_repository)
    await use_case.execute(project_id=PROJECT, user_id=USER)

    assert port.calls == [(PROJECT, USER)]


async def test_the_order_is_correlations_group_order_and_not_a_priority_order(
    finding_repository, scanner_fixture, id_generator, clock
):
    """Ranking is M6.3's. Scoring must not quietly pre-empt it."""
    findings = _map_all(scanner_fixture, id_generator, clock, trivy=_TRIVY_EDGES)
    groups = _group(findings)
    surfaces = await _score(finding_repository, findings, groups)

    assert [surface.package for surface in surfaces] == [group.key.package for group in groups]
    scores = [surface.priority_score for surface in surfaces]
    assert scores != sorted(scores, reverse=True)


# --- the two branches no captured corpus can reach ------------------------------------


async def test_a_critical_package_surface_scores_five_and_buckets_plan(
    finding_repository, scanner_fixture, id_generator, clock
):
    """The CRITICAL branch, through the real Trivy mapper. **It does not reach `fix_now`.**

    ADR-0005 decision 5 says M6.2 owes scoring-level coverage of this branch. What it does
    not say, and this test is where it becomes visible, is that the branch and the top
    bucket are disjoint: a `CRITICAL` surface is Trivy-only, so it earns neither other
    signal and tops out at 5. **G64.**
    """
    findings = _map_all(scanner_fixture, id_generator, clock, trivy=_TRIVY_EDGES)
    surfaces = _by_key(await _score(finding_repository, findings, _group(findings)))

    critical = surfaces[("criticalpkg", None)]
    assert critical.reasoning.severity.value == 5
    assert critical.priority_score == 5
    assert critical.priority is Priority.PLAN


async def test_an_unknown_only_surface_scores_nothing_and_names_no_producer(
    finding_repository, scanner_fixture, id_generator, clock
):
    """The UNKNOWN branch, through the real Trivy mapper — `unknownpkg` is its own group."""
    findings = _map_all(scanner_fixture, id_generator, clock, trivy=_TRIVY_EDGES)
    surfaces = _by_key(await _score(finding_repository, findings, _group(findings)))

    unknown = surfaces[("unknownpkg", None)]
    assert unknown.reasoning.severity.value == 0
    assert unknown.reasoning.severity.produced_by == ()
    assert unknown.reasoning.severity.note == "no member stated a severity"
    assert unknown.priority is Priority.MONITOR


async def test_a_dast_only_high_surface_scores_five_and_buckets_plan(
    finding_repository, scanner_fixture, id_generator, clock
):
    """The exposure closure: **a DAST member alone cannot reach the top bucket.**

    `zap_synthetic_edges.json` carries alertRef 40012 at riskcode 3, which ADR-0018 maps to
    `HIGH` — the only HIGH ZAP alert in `tests/fixtures/scanners/`. (The committed **active**
    capture at `tests/integration/fixtures/active_scan/` carries two more, `6-5` and `90036`;
    that ZAP can emit `HIGH` at all is what makes a Semgrep `ERROR` sufficient but not
    necessary for `fix_now` — see **G64**.) Its surface is ZAP-only, so `4 + 1 + 0 = 5`.
    Without this, nothing pins that exposure is not what promotes `/calculate`.
    """
    findings = _map_all(scanner_fixture, id_generator, clock, zap=_ZAP_EDGES)
    surfaces = _by_key(await _score(finding_repository, findings, _group(findings)))

    search = surfaces[(None, "/search")]
    assert {ScannerTool.ZAP} == {
        finding.source for finding in findings if finding.location.url.endswith("/search")
    }
    assert search.reasoning.severity.value == 4
    assert search.reasoning.exposure.value == 1
    assert search.reasoning.corroboration.value == 0
    assert search.priority_score == 5
    assert search.priority is Priority.PLAN


# --- PRODUCT_SPEC.md §10 --------------------------------------------------------------


async def _section_ten_surfaces(finding_repository, scanner_fixture, id_generator, clock):
    findings = _map_all(
        scanner_fixture, id_generator, clock, semgrep=_SEMGREP, trivy=_TRIVY_EDGES, zap=_ZAP
    )
    groups = _group(findings, paths_serving=_serves_calculate)
    return findings, _by_key(await _score(finding_repository, findings, groups))


async def test_the_cross_tool_surface_is_the_only_fix_now_and_its_severity_comes_from_semgrep(
    finding_repository, scanner_fixture, id_generator, clock
):
    """§10's demonstration, and the half that says where the severity term came from.

    Measured: every alert instance in `zap_scan.json` is riskcode 2 or below, so ZAP's
    contribution to `/calculate` tops out at `MEDIUM`. The 4 is Semgrep's `ERROR` on
    `app.py:28`, attached to this surface through the route map — which is **G53**'s
    derived-provenance exposure, scored identically to a location read off the tool.
    """
    findings, surfaces = await _section_ten_surfaces(
        finding_repository, scanner_fixture, id_generator, clock
    )

    calculate = surfaces[(None, "/calculate")]
    semgrep = next(f for f in findings if f.source is ScannerTool.SEMGREP)

    assert calculate.priority_score == 6
    assert calculate.priority is Priority.FIX_NOW
    assert calculate.reasoning.severity.value == 4
    assert calculate.reasoning.severity.produced_by == (semgrep.id,)
    assert calculate.reasoning.exposure.value == 1
    assert calculate.reasoning.corroboration.value == 1

    fix_now = [s for s in surfaces.values() if s.priority is Priority.FIX_NOW]
    assert fix_now == [calculate]


async def test_what_cross_tool_correlation_buys_is_one_point_that_breaks_a_tie_with_a_critical_cve(
    finding_repository, scanner_fixture, id_generator, clock
):
    """**What §10 actually measures, stated at the width the evidence supports.**

    Asserting only that 6 > 5 would read as "correlation demonstrably improves
    prioritization" while measuring a single point. Exposure is not what correlation buys —
    a ZAP-only surface has it too (see the DAST closure above). Strip the corroboration
    term and `/calculate` **ties** the CRITICAL package surface exactly, in the same bucket.

    So the whole demonstration is one point, and it comes from the signal **G62** records
    as unable to tell a substantive cross-tool pair from a coincidental co-location — in
    this very corpus, all four of the DAST members it counts are header hygiene.
    """
    _, surfaces = await _section_ten_surfaces(
        finding_repository, scanner_fixture, id_generator, clock
    )

    calculate = surfaces[(None, "/calculate")]
    critical = surfaces[("criticalpkg", None)]

    without_corroboration = calculate.priority_score - calculate.reasoning.corroboration.value

    assert calculate.reasoning.corroboration.value == 1
    assert without_corroboration == critical.priority_score == 5
    assert bucket_for(without_corroboration) is Priority.PLAN
    assert bucket_for(calculate.priority_score) is Priority.FIX_NOW


async def test_the_cross_tool_surface_outranks_the_critical_package_surface(
    finding_repository, scanner_fixture, id_generator, clock
):
    """The ordering claim itself — deliberately stated AFTER the margin that produces it."""
    _, surfaces = await _section_ten_surfaces(
        finding_repository, scanner_fixture, id_generator, clock
    )

    calculate = surfaces[(None, "/calculate")]
    critical = surfaces[("criticalpkg", None)]

    assert calculate.priority_score > critical.priority_score
    assert critical.priority is Priority.PLAN
    assert calculate.priority is Priority.FIX_NOW


async def test_no_package_surface_in_the_corpus_reaches_the_top_bucket(
    finding_repository, scanner_fixture, id_generator, clock
):
    """**G64**, as an assertion rather than a note: the top bucket is closed to SCA."""
    _, surfaces = await _section_ten_surfaces(
        finding_repository, scanner_fixture, id_generator, clock
    )

    packaged = [s for s in surfaces.values() if s.package is not None]
    assert packaged, "the corpus must contain package surfaces for this to mean anything"
    assert all(s.priority is not Priority.FIX_NOW for s in packaged)
