from verion.modules.projects.ports.project_access import ProjectAccessPort
from verion.modules.scanning.domain.exceptions import ProjectAccessDenied, ScanNotFound
from verion.modules.scanning.domain.scan import Scan
from verion.modules.scanning.ports.scan_repository import ScanRepositoryPort


class GetScanUseCase:
    """One scan's status, for the caller that started it to poll (ADR-0035 decision 4).

    **Two gates, in this order, on `GetFindingEvidenceUseCase`'s precedent.** The first says
    the caller may read *this project*, and runs before the repository is read. The second
    says the scan is *in* it: without it, a member of project A could read the status and
    `failure_reason` of a scan of project B by its id. A scan of another project and an
    absent scan raise the same `ScanNotFound`.

    **Read-level, not owner-level.** A member who may not start a scan may still watch one.
    """

    def __init__(self, project_access: ProjectAccessPort, scans: ScanRepositoryPort) -> None:
        self._project_access = project_access
        self._scans = scans

    async def execute(self, *, project_id: str, user_id: str, scan_id: str) -> Scan:
        if not await self._project_access.may_read_project(project_id=project_id, user_id=user_id):
            raise ProjectAccessDenied(f"No readable project with id '{project_id}'")

        scan = await self._scans.get_by_id(scan_id)
        if scan is None or scan.project_id != project_id:
            raise ScanNotFound(f"No scan with id '{scan_id}' in project '{project_id}'")
        return scan
