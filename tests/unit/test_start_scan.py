"""`StartScanUseCase` — the route's path to a scan, authorized by the MANAGE verdict.

The mutation this file exists for is `StartScanUseCase` asking `may_read_project` instead:
a member who is not an owner would then start scans, cloning with their own GitHub token.
"""

import pytest

from verion.modules.scanning.application.start_scan import StartScanUseCase
from verion.modules.scanning.application.trigger_scan import TriggerScanUseCase
from verion.modules.scanning.domain.exceptions import ProjectAccessDenied

_PROJECT = "project-1"
_USER = "user-1"


def _use_case(project_access, scan_repository, job_queue, id_generator) -> StartScanUseCase:
    trigger = TriggerScanUseCase(
        scans=scan_repository, job_queue=job_queue, id_generator=id_generator
    )
    return StartScanUseCase(project_access=project_access, trigger_scan=trigger)


async def test_a_caller_who_may_manage_starts_a_scan(
    project_access, scan_repository, job_queue, id_generator
):
    project_access.permit_manage(_PROJECT, _USER)

    scan = await _use_case(project_access, scan_repository, job_queue, id_generator).execute(
        project_id=_PROJECT, user_id=_USER
    )

    assert scan.triggered_by == _USER
    assert job_queue.enqueued_scan_ids == [scan.id]
    assert project_access.manage_calls == [(_PROJECT, _USER)]


async def test_a_caller_who_may_only_read_is_refused(
    project_access, scan_repository, job_queue, id_generator
):
    """A member who is not an owner. Kills the use case consulting the read verdict."""
    project_access.permit(_PROJECT, _USER)

    with pytest.raises(ProjectAccessDenied):
        await _use_case(project_access, scan_repository, job_queue, id_generator).execute(
            project_id=_PROJECT, user_id=_USER
        )

    assert job_queue.enqueued_scan_ids == []


async def test_a_caller_with_no_permission_is_refused(
    project_access, scan_repository, job_queue, id_generator
):
    with pytest.raises(ProjectAccessDenied):
        await _use_case(project_access, scan_repository, job_queue, id_generator).execute(
            project_id=_PROJECT, user_id=_USER
        )

    assert job_queue.enqueued_scan_ids == []
