from verion.modules.scanning.domain.exceptions import ProjectAccessDenied
from verion.modules.scanning.domain.scan import Scan, ScanStatus
from verion.modules.scanning.ports.job_queue import JobQueuePort
from verion.modules.scanning.ports.scan_repository import ScanRepositoryPort
from verion.shared_kernel.ports import IdGeneratorPort


class TriggerScanUseCase:
    """Create a `PENDING` scan and ask for its job. It does not run the scan.

    **Who may trigger is decided by the caller, and there are two** (ADR-0035 decision 3):
    `StartScanUseCase` passes `ProjectAccessPort.may_manage_project`'s verdict, and
    `HandleGitHubWebhookUseCase` passes `True` on the strength of a verified signature. Both
    pass an owner as `user_id`, which `RunScanUseCase._checkout_repo` relies on: it clones
    with `triggered_by`'s GitHub token.

    **One flag and one exception**, because a verdict is one bool: an absent project, a
    non-member and a member who is not an owner are denied alike, and the message names only
    the project id the caller supplied.

    **The enqueue is a request, not a delivery.** Through `platform/di.py`'s `get_job_queue`
    the job is sent only after the request's transaction commits, so a worker never takes a
    job whose `Scan` row it cannot see.
    """

    def __init__(
        self,
        scans: ScanRepositoryPort,
        job_queue: JobQueuePort,
        id_generator: IdGeneratorPort,
    ) -> None:
        self._scans = scans
        self._job_queue = job_queue
        self._id_generator = id_generator

    async def execute(self, project_id: str, user_id: str, *, authorized: bool) -> Scan:
        if not authorized:
            raise ProjectAccessDenied(f"No project with id '{project_id}' that you may scan")

        scan = Scan(
            id=self._id_generator.new_id(),
            project_id=project_id,
            status=ScanStatus.PENDING,
            triggered_by=user_id,
            started_at=None,
            finished_at=None,
            failure_reason=None,
        )
        await self._scans.add(scan)
        await self._job_queue.enqueue_scan(scan.id)

        return scan
