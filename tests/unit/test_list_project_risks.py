"""`ListProjectRisksUseCase` against fakes.

Two things here are not ordinary coverage:

- the **second gate-placement** test. `CorrelateFindingsUseCase` already owns the access
  check; what this file adds is that the *envelope* reads sit behind it too, which is the
  half a composing use case can get wrong without any existing test failing.
- the **envelope built without naming `NormalizationRun`**, asserted through the values that
  survive the copy rather than through the type — ADR-0025 decision 4.
"""

from datetime import UTC, datetime

import pytest

from verion.modules.correlation.application.correlate_findings import CorrelateFindingsUseCase
from verion.modules.correlation.application.list_project_risks import ListProjectRisksUseCase
from verion.modules.correlation.domain.exceptions import ProjectAccessDenied
from verion.modules.normalization.domain.finding import Evidence, Finding, Location
from verion.modules.normalization.domain.normalization_run import (
    NormalizationRun,
    NormalizationRunStatus,
)
from verion.shared_kernel.scanner_tools import ScannerTool
from verion.shared_kernel.severity import Severity

_PROJECT = "project-1"
_USER = "user-1"
_SCAN = "scan-1"
_AT = datetime(2026, 1, 1, tzinfo=UTC)


def _finding(
    *,
    finding_id: str,
    location: Location,
    source: ScannerTool = ScannerTool.TRIVY,
    severity: Severity = Severity.HIGH,
) -> Finding:
    return Finding(
        id=finding_id,
        project_id=_PROJECT,
        source=source,
        rule_id=f"rule-{finding_id}",
        severity=severity,
        native_severity="HIGH",
        title=f"title {finding_id}",
        location=location,
        evidence=Evidence(
            id=f"ev-{finding_id}",
            finding_id=finding_id,
            scan_id=_SCAN,
            raw_payload='{"ok": true}',
            source_tool=source,
            captured_at=_AT,
        ),
    )


def _package(name: str) -> Location:
    return Location(
        file_path="requirements.txt",
        start_line=None,
        end_line=None,
        package=name,
        installed_version="1.0.0",
        url=None,
        http_method=None,
        parameter=None,
    )


def _run(status: NormalizationRunStatus, *, scan_id: str = _SCAN) -> NormalizationRun:
    terminal = (NormalizationRunStatus.COMPLETED, NormalizationRunStatus.FAILED)
    started = None if status is NormalizationRunStatus.PENDING else _AT
    finished = _AT if status in terminal else None
    return NormalizationRun(
        id=f"run-{scan_id}",
        scan_id=scan_id,
        project_id=_PROJECT,
        status=status,
        requested_at=_AT,
        started_at=started,
        finished_at=finished,
        failure_reason="OSError." if status is NormalizationRunStatus.FAILED else None,
    )


def _use_case(project_access, findings, runs) -> ListProjectRisksUseCase:
    return ListProjectRisksUseCase(
        correlate=CorrelateFindingsUseCase(project_access=project_access, findings=findings),
        normalization_runs=runs,
    )


# ---------------------------------------------------------------------------
# Authorization
# ---------------------------------------------------------------------------


async def test_a_caller_who_may_not_read_the_project_is_refused(
    project_access, finding_repository, normalization_run_repository
):
    with pytest.raises(ProjectAccessDenied):
        await _use_case(project_access, finding_repository, normalization_run_repository).execute(
            project_id=_PROJECT, user_id=_USER
        )


async def test_the_envelope_is_not_read_before_authorization(
    project_access, exploding_finding_repository, exploding_normalization_run_repository
):
    """Both reads sit behind the gate, not just the correlation one.

    The findings side is inherited from `CorrelateFindingsUseCase` and already pinned there.
    What is new is the run repository: moving either envelope read above the correlate call
    would leave every other test in this file passing.
    """
    with pytest.raises(ProjectAccessDenied):
        await _use_case(
            project_access, exploding_finding_repository, exploding_normalization_run_repository
        ).execute(project_id=_PROJECT, user_id=_USER)


# ---------------------------------------------------------------------------
# The completeness envelope (G15, ADR-0025 decision 4)
# ---------------------------------------------------------------------------


async def test_the_envelope_carries_the_latest_run_and_the_unfinished_count(
    project_access, finding_repository, normalization_run_repository
):
    project_access.permit(_PROJECT, _USER)
    normalization_run_repository.seed(_run(NormalizationRunStatus.FAILED))

    risks = await _use_case(
        project_access, finding_repository, normalization_run_repository
    ).execute(project_id=_PROJECT, user_id=_USER)

    assert risks.latest_run is not None
    assert risks.latest_run.scan_id == _SCAN
    assert risks.latest_run.status == str(NormalizationRunStatus.FAILED)
    assert risks.latest_run.failure_reason == "OSError."
    assert risks.unfinished_runs == 1


async def test_a_project_with_no_runs_reports_none_and_zero(
    project_access, finding_repository, normalization_run_repository
):
    """The clean-project reading, so the failed one above means something."""
    project_access.permit(_PROJECT, _USER)

    risks = await _use_case(
        project_access, finding_repository, normalization_run_repository
    ).execute(project_id=_PROJECT, user_id=_USER)

    assert risks.latest_run is None
    assert risks.unfinished_runs == 0


async def test_a_completed_latest_run_does_not_hide_an_earlier_failure(
    project_access, finding_repository, normalization_run_repository
):
    """`unfinished_runs` is the load-bearing half, for ADR-0022 decision 3's reason."""
    project_access.permit(_PROJECT, _USER)
    normalization_run_repository.seed(_run(NormalizationRunStatus.FAILED, scan_id="scan-old"))
    normalization_run_repository.seed(_run(NormalizationRunStatus.COMPLETED, scan_id="scan-new"))

    risks = await _use_case(
        project_access, finding_repository, normalization_run_repository
    ).execute(project_id=_PROJECT, user_id=_USER)

    assert risks.unfinished_runs == 1


# ---------------------------------------------------------------------------
# Paging and ordering
# ---------------------------------------------------------------------------


async def test_total_counts_every_group_not_the_page(
    project_access, finding_repository, normalization_run_repository
):
    project_access.permit(_PROJECT, _USER)
    for name in ("alpha", "beta", "gamma"):
        await finding_repository.upsert(_finding(finding_id=f"f-{name}", location=_package(name)))

    risks = await _use_case(
        project_access, finding_repository, normalization_run_repository
    ).execute(project_id=_PROJECT, user_id=_USER, limit=2, offset=0)

    assert len(risks.items) == 2
    assert risks.total == 3
    assert risks.limit == 2
    assert risks.offset == 0


async def test_the_order_is_the_key_order_and_not_a_severity_order(
    project_access, finding_repository, normalization_run_repository
):
    """`_group_order`'s order, which is total and deterministic and is NOT a ranking.

    Seeded so the two disagree: the `critical` finding's package sorts last. A listing that
    had quietly acquired a severity rank would put it first.
    """
    project_access.permit(_PROJECT, _USER)
    await finding_repository.upsert(
        _finding(finding_id="f-zzz", location=_package("zzz"), severity=Severity.CRITICAL)
    )
    await finding_repository.upsert(
        _finding(finding_id="f-aaa", location=_package("aaa"), severity=Severity.LOW)
    )

    risks = await _use_case(
        project_access, finding_repository, normalization_run_repository
    ).execute(project_id=_PROJECT, user_id=_USER)

    assert [group.key.package for group in risks.items] == ["aaa", "zzz"]
