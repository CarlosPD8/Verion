"""`ListScoredRisksUseCase` against fakes.

**No `Finding` here is hand-written**, following `test_compute_risk.py`: every one comes
through the real Trivy mapper from a committed capture and every group through
`correlation`'s real `build_match_key`/`group_by_match_key`, so shapes are production's by
construction rather than by a conformance check. **G40**'s count is untouched.

Three things here are not ordinary coverage:

- the **gate-placement** test, which proves both envelope reads sit behind the port's
  authorization and not merely after it;
- the **rank-then-page** test, which is the one a page-then-rank implementation fails and
  every other test in this file would pass;
- the **envelope built without naming `NormalizationRun`**, asserted through the values that
  survive the copy rather than through the type (**G67**).

Helpers are module-local: `tests/` is not a package, so importing across test modules is not
available and duplication is the convention here.
"""

from datetime import UTC, datetime

import pytest

from verion.modules.correlation.application.match_key_builder import build_match_key
from verion.modules.correlation.domain.matching import group_by_match_key
from verion.modules.correlation.ports.candidate_risk import CandidateRiskAccessDenied
from verion.modules.normalization.domain.mappers.trivy import map_trivy_output
from verion.modules.normalization.domain.mappers.zap import map_zap_output
from verion.modules.normalization.domain.normalization_run import (
    NormalizationRun,
    NormalizationRunStatus,
)
from verion.modules.risk_engine.application.compute_risk import ComputeRiskUseCase
from verion.modules.risk_engine.application.list_scored_risks import ListScoredRisksUseCase

PROJECT = "proj-1"
USER = "user-1"
SCAN = "scan-1"
_AT = datetime(2026, 1, 1, tzinfo=UTC)
_TRIVY_EDGES = "trivy_synthetic_edges.json"
_ZAP = "zap_scan.json"


class _FakeCandidateRisks:
    """`CandidateRiskPort` — hands back groups built here, and records its calls."""

    def __init__(self, groups):
        self._groups = groups
        self.calls = []

    async def candidate_risks(self, *, project_id, user_id):
        self.calls.append((project_id, user_id))
        return self._groups


class _DenyingCandidateRisks:
    """`CandidateRiskPort` that refuses, as it does for a caller who may not read."""

    async def candidate_risks(self, *, project_id, user_id):
        raise CandidateRiskAccessDenied(f"No readable project with id '{project_id}'")


def _run(status: NormalizationRunStatus, *, scan_id: str = SCAN) -> NormalizationRun:
    terminal = (NormalizationRunStatus.COMPLETED, NormalizationRunStatus.FAILED)
    return NormalizationRun(
        id=f"run-{scan_id}",
        scan_id=scan_id,
        project_id=PROJECT,
        status=status,
        requested_at=_AT,
        started_at=None if status is NormalizationRunStatus.PENDING else _AT,
        finished_at=_AT if status in terminal else None,
        failure_reason="OSError." if status is NormalizationRunStatus.FAILED else None,
    )


def _findings(scanner_fixture, id_generator, clock, *, with_dast: bool = False):
    """Real mapper output over committed captures.

    **`with_dast=True` is what makes group order and priority order DISAGREE**, which one
    test below depends on and the others do not. `_group_order` sorts a url-keyed group
    before a package-keyed one — `package is None` sorts first — while the highest score in
    this corpus is Trivy's `criticalpkg` at 5. Trivy alone cannot discriminate the two
    orders, because there `criticalpkg` is both alphabetically first and highest-scoring;
    the first version of the paging test asserted against exactly that and failed on its own
    premise, which is recorded here because a premise that cannot hold is worse than a
    missing test.
    """
    findings = list(
        map_trivy_output(
            project_id=PROJECT,
            scan_id=SCAN,
            raw_output=scanner_fixture(_TRIVY_EDGES),
            id_generator=id_generator,
            clock=clock,
        )
    )
    if with_dast:
        findings.extend(
            map_zap_output(
                project_id=PROJECT,
                scan_id=SCAN,
                raw_output=scanner_fixture(_ZAP),
                id_generator=id_generator,
                clock=clock,
            )
        )
    return findings


def _groups(findings):
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
                    paths_serving=None,
                ),
            )
            for finding in findings
        ]
    )


async def _use_case(finding_repository, runs, findings, groups) -> ListScoredRisksUseCase:
    for finding in findings:
        await finding_repository.upsert(finding)
    return ListScoredRisksUseCase(
        compute=ComputeRiskUseCase(
            candidate_risks=_FakeCandidateRisks(groups), findings=finding_repository
        ),
        normalization_runs=runs,
    )


# ---------------------------------------------------------------------------
# Authorization — the gate is the port's, and both envelope reads sit behind it
# ---------------------------------------------------------------------------


async def test_a_denied_caller_reaches_neither_the_findings_read_nor_the_envelope(
    exploding_finding_repository, exploding_normalization_run_repository
):
    """Both reads behind the gate, not merely after it.

    The findings side is inherited from `ComputeRiskUseCase` and pinned there. What is new
    is the run repository: moving either envelope read above the compute call would leave
    every other test in this file passing.
    """
    use_case = ListScoredRisksUseCase(
        compute=ComputeRiskUseCase(
            candidate_risks=_DenyingCandidateRisks(), findings=exploding_finding_repository
        ),
        normalization_runs=exploding_normalization_run_repository,
    )

    with pytest.raises(CandidateRiskAccessDenied):
        await use_case.execute(project_id=PROJECT, user_id=USER)


# ---------------------------------------------------------------------------
# Ranking and paging
# ---------------------------------------------------------------------------


async def test_the_items_come_back_in_priority_order(
    finding_repository, normalization_run_repository, scanner_fixture, id_generator, clock
):
    """This route's whole reason for existing, and the M5.2 listing's explicit non-claim."""
    findings = _findings(scanner_fixture, id_generator, clock)
    groups = _groups(findings)
    use_case = await _use_case(finding_repository, normalization_run_repository, findings, groups)

    risks = await use_case.execute(project_id=PROJECT, user_id=USER)

    scores = [surface.priority_score for surface in risks.items]
    assert scores == sorted(scores, reverse=True)
    # Non-vacuous: the corpus must actually contain surfaces that differ, or a constant
    # list would satisfy the assertion above.
    assert len(set(scores)) > 1


async def test_the_page_is_taken_AFTER_ranking(
    finding_repository, normalization_run_repository, scanner_fixture, id_generator, clock
):
    """**The test a page-then-rank implementation fails and the rest of this file does not.**

    Paging correlation's group order and ranking the page would return the top of an
    arbitrary order and label it a priority. A one-item page must therefore be the
    highest-scoring surface in the whole project, not the highest-scoring member of
    whichever group sorted first.

    **Seeded with DAST findings so the two orders actually disagree** — see `_findings`.
    Trivy alone cannot discriminate them, and the premise assertion below is what says so
    out loud rather than letting this test pass by coincidence.
    """
    findings = _findings(scanner_fixture, id_generator, clock, with_dast=True)
    groups = _groups(findings)
    use_case = await _use_case(finding_repository, normalization_run_repository, findings, groups)

    everything = await use_case.execute(project_id=PROJECT, user_id=USER)
    first_page = await use_case.execute(project_id=PROJECT, user_id=USER, limit=1, offset=0)

    best = max(surface.priority_score for surface in everything.items)
    assert first_page.items[0].priority_score == best
    # The premise: group order does NOT already put that surface first, so a page-then-rank
    # implementation fails here rather than passing by luck.
    top = first_page.items[0]
    assert (groups[0].key.package, groups[0].key.url) != (top.package, top.url)


async def test_total_counts_every_scored_surface_not_the_page(
    finding_repository, normalization_run_repository, scanner_fixture, id_generator, clock
):
    findings = _findings(scanner_fixture, id_generator, clock)
    groups = _groups(findings)
    use_case = await _use_case(finding_repository, normalization_run_repository, findings, groups)

    risks = await use_case.execute(project_id=PROJECT, user_id=USER, limit=2, offset=0)

    assert len(risks.items) == 2
    assert risks.total == len(groups)
    assert risks.limit == 2
    assert risks.offset == 0


# ---------------------------------------------------------------------------
# The completeness envelope (G15, ADR-0025 decision 4, inherited by ADR-0030 decision 4)
# ---------------------------------------------------------------------------


async def test_the_envelope_carries_the_latest_run_and_the_unfinished_count(
    finding_repository, normalization_run_repository, scanner_fixture, id_generator, clock
):
    """Filled field by field off the port's return value, never naming `NormalizationRun`."""
    findings = _findings(scanner_fixture, id_generator, clock)
    normalization_run_repository.seed(_run(NormalizationRunStatus.FAILED))
    use_case = await _use_case(
        finding_repository, normalization_run_repository, findings, _groups(findings)
    )

    risks = await use_case.execute(project_id=PROJECT, user_id=USER)

    assert risks.latest_run is not None
    assert risks.latest_run.scan_id == SCAN
    assert risks.latest_run.status == str(NormalizationRunStatus.FAILED)
    assert risks.latest_run.failure_reason == "OSError."
    assert risks.unfinished_runs == 1


async def test_a_completed_latest_run_does_not_hide_an_earlier_failure(
    finding_repository, normalization_run_repository, scanner_fixture, id_generator, clock
):
    """`unfinished_runs` is the load-bearing half — and worse here than on either sibling
    route, since this response presents a priority ORDER built on those findings."""
    findings = _findings(scanner_fixture, id_generator, clock)
    normalization_run_repository.seed(_run(NormalizationRunStatus.FAILED, scan_id="scan-old"))
    normalization_run_repository.seed(_run(NormalizationRunStatus.COMPLETED, scan_id="scan-new"))
    use_case = await _use_case(
        finding_repository, normalization_run_repository, findings, _groups(findings)
    )

    risks = await use_case.execute(project_id=PROJECT, user_id=USER)

    assert risks.unfinished_runs == 1


async def test_a_project_with_no_runs_reports_none_and_zero(
    finding_repository, normalization_run_repository, scanner_fixture, id_generator, clock
):
    """The clean-project reading, so the failed one above means something."""
    findings = _findings(scanner_fixture, id_generator, clock)
    use_case = await _use_case(
        finding_repository, normalization_run_repository, findings, _groups(findings)
    )

    risks = await use_case.execute(project_id=PROJECT, user_id=USER)

    assert risks.latest_run is None
    assert risks.unfinished_runs == 0
