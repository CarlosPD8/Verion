from verion.modules.scanning.domain.exceptions import InsufficientPermissions, ProjectNotFound
from verion.modules.scanning.domain.scan import Scan, ScanStatus
from verion.modules.scanning.ports.job_queue import JobQueuePort
from verion.modules.scanning.ports.scan_repository import ScanRepositoryPort
from verion.shared_kernel.ports import IdGeneratorPort


class TriggerScanUseCase:
    def __init__(
        self,
        scans: ScanRepositoryPort,
        job_queue: JobQueuePort,
        id_generator: IdGeneratorPort,
    ) -> None:
        self._scans = scans
        self._job_queue = job_queue
        self._id_generator = id_generator

    async def execute(
        self, project_id: str, user_id: str, project_exists: bool, is_owner: bool
    ) -> Scan:
        if not project_exists:
            raise ProjectNotFound(f"No project with id '{project_id}'")

        if not is_owner:
            raise InsufficientPermissions("This action requires an owner membership")

        scan = Scan(
            id=self._id_generator.new_id(),
            project_id=project_id,
            status=ScanStatus.PENDING,
            triggered_by=user_id,
            started_at=None,
            finished_at=None,
        )
        await self._scans.add(scan)
        await self._job_queue.enqueue_scan(scan.id)

        return scan
