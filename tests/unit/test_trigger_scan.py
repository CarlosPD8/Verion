import pytest

from verion.modules.scanning.application.trigger_scan import TriggerScanUseCase
from verion.modules.scanning.domain.exceptions import InsufficientPermissions, ProjectNotFound
from verion.modules.scanning.domain.scan import ScanStatus


def _use_case(scan_repository, job_queue, id_generator):
    return TriggerScanUseCase(scans=scan_repository, job_queue=job_queue, id_generator=id_generator)


async def test_triggers_a_pending_scan_and_enqueues_it(scan_repository, job_queue, id_generator):
    use_case = _use_case(scan_repository, job_queue, id_generator)

    scan = await use_case.execute(
        project_id="project-1", user_id="owner-1", project_exists=True, is_owner=True
    )

    assert scan.project_id == "project-1"
    assert scan.triggered_by == "owner-1"
    assert scan.status is ScanStatus.PENDING
    assert scan.started_at is None
    assert scan.finished_at is None
    assert await scan_repository.get_by_id(scan.id) == scan
    assert job_queue.enqueued_scan_ids == [scan.id]


async def test_raises_project_not_found_for_an_unknown_project(
    scan_repository, job_queue, id_generator
):
    use_case = _use_case(scan_repository, job_queue, id_generator)

    with pytest.raises(ProjectNotFound):
        await use_case.execute(
            project_id="does-not-exist", user_id="owner-1", project_exists=False, is_owner=False
        )

    assert job_queue.enqueued_scan_ids == []


async def test_rejects_a_member_who_is_not_an_owner(scan_repository, job_queue, id_generator):
    use_case = _use_case(scan_repository, job_queue, id_generator)

    with pytest.raises(InsufficientPermissions):
        await use_case.execute(
            project_id="project-1", user_id="member-1", project_exists=True, is_owner=False
        )

    assert job_queue.enqueued_scan_ids == []
