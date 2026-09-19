# `projects`' PORT, and the verdict rather than the membership rows: the rule for who may
# start a scan stays in `projects` (`domain/authorization.may_manage`). ADR-0022 decision 2,
# as amended by ADR-0035 decision 2.
from verion.modules.projects.ports.project_access import ProjectAccessPort
from verion.modules.scanning.application.trigger_scan import TriggerScanUseCase
from verion.modules.scanning.domain.scan import Scan


class StartScanUseCase:
    """A user starts a scan of a project they own — M8's exit condition, first clause.

    It asks `ProjectAccessPort.may_manage_project` and hands the answer to
    `TriggerScanUseCase` as `authorized`. That is the only difference from the webhook's
    path, which derives the same flag from a verified signature (ADR-0035 decision 3).
    """

    def __init__(self, project_access: ProjectAccessPort, trigger_scan: TriggerScanUseCase) -> None:
        self._project_access = project_access
        self._trigger_scan = trigger_scan

    async def execute(self, *, project_id: str, user_id: str) -> Scan:
        authorized = await self._project_access.may_manage_project(
            project_id=project_id, user_id=user_id
        )
        return await self._trigger_scan.execute(project_id, user_id, authorized=authorized)
