from collections.abc import Callable

from verion.modules.projects.domain.context_detection import DetectionResult
from verion.modules.projects.domain.exceptions import ProjectNotFound
from verion.modules.projects.domain.security_context import SecurityContext
from verion.modules.projects.ports.project_repository import ProjectRepositoryPort
from verion.modules.projects.ports.security_context_repository import (
    SecurityContextRepositoryPort,
)
from verion.shared_kernel.ports import ClockPort, IdGeneratorPort


# Not permission-gated yet: no route calls this today, so there's no caller
# identity to check. Once this becomes reachable over HTTP (M2.2/M2.3), it
# must require OWNER permission via require_owner, same as
# ConnectRepositoryUseCase — building a project's Security Context is a
# write action on project data, same category as connecting a repo.
class BuildSecurityContextUseCase:
    def __init__(
        self,
        projects: ProjectRepositoryPort,
        security_contexts: SecurityContextRepositoryPort,
        detector: Callable[[dict[str, str]], DetectionResult],
        id_generator: IdGeneratorPort,
        clock: ClockPort,
    ) -> None:
        self._projects = projects
        self._security_contexts = security_contexts
        self._detector = detector
        self._id_generator = id_generator
        self._clock = clock

    async def execute(self, project_id: str, files: dict[str, str]) -> SecurityContext:
        project = await self._projects.get_by_id(project_id)
        if project is None:
            raise ProjectNotFound(f"No project with id '{project_id}'")

        result = self._detector(files)

        context = SecurityContext(
            id=self._id_generator.new_id(),
            project_id=project_id,
            language=result.language,
            framework=result.framework,
            database=None,
            deployment_target=result.deployment_target,
            ci_provider=result.ci_provider,
            exposure_tags=[],
            created_at=self._clock.now(),
        )
        await self._security_contexts.add(context)

        return context
