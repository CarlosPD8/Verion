"""`TriggerScanUseCase` — one flag, one exception (ADR-0035 decision 3).

Who may trigger is the caller's decision: `StartScanUseCase` passes a verdict and the webhook
passes `True`. What this use case owns is that a refusal writes and enqueues nothing, and
says nothing about why.
"""

import pytest

from verion.modules.scanning.application.trigger_scan import TriggerScanUseCase
from verion.modules.scanning.domain.exceptions import ProjectAccessDenied
from verion.modules.scanning.domain.scan import ScanStatus


def _use_case(scan_repository, job_queue, id_generator):
    return TriggerScanUseCase(scans=scan_repository, job_queue=job_queue, id_generator=id_generator)


async def test_an_authorized_trigger_stores_a_pending_scan_and_enqueues_it(
    scan_repository, job_queue, id_generator
):
    use_case = _use_case(scan_repository, job_queue, id_generator)

    scan = await use_case.execute("project-1", "owner-1", authorized=True)

    assert scan.project_id == "project-1"
    assert scan.triggered_by == "owner-1"
    assert scan.status is ScanStatus.PENDING
    assert scan.started_at is None
    assert scan.finished_at is None
    assert await scan_repository.get_by_id(scan.id) == scan
    assert job_queue.enqueued_scan_ids == [scan.id]


async def test_an_unauthorized_trigger_raises_and_writes_and_enqueues_nothing(
    scan_repository, job_queue, id_generator
):
    """Kills a deleted `authorized` check: the scan would be stored and its job queued."""
    use_case = _use_case(scan_repository, job_queue, id_generator)

    with pytest.raises(ProjectAccessDenied):
        await use_case.execute("project-1", "member-1", authorized=False)

    # `fake-id-1` is the first id the fake generator would mint, so it is the id any stored
    # scan would carry.
    assert await scan_repository.get_by_id("fake-id-1") is None
    assert job_queue.enqueued_scan_ids == []


async def test_the_denial_names_only_the_project_id_the_caller_supplied(
    scan_repository, job_queue, id_generator
):
    """One message for every reason a verdict says no, so the route's 404 body cannot tell
    an absent project from a refused caller. Kills a message that names the user or a
    reason."""
    use_case = _use_case(scan_repository, job_queue, id_generator)

    with pytest.raises(ProjectAccessDenied) as denied:
        await use_case.execute("project-1", "member-1", authorized=False)

    assert str(denied.value) == "No project with id 'project-1' that you may scan"
