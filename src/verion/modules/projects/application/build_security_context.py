from collections.abc import Callable

from verion.modules.projects.domain.authorization import require_owner
from verion.modules.projects.domain.context_detection import DetectionResult
from verion.modules.projects.domain.exceptions import ProjectNotFound
from verion.modules.projects.domain.security_context import SecurityContext
from verion.modules.projects.ports.project_membership_repository import (
    ProjectMembershipRepositoryPort,
)
from verion.modules.projects.ports.project_repository import ProjectRepositoryPort
from verion.modules.projects.ports.security_context_repository import (
    SecurityContextRepositoryPort,
)
from verion.shared_kernel.ports import ClockPort, IdGeneratorPort


class BuildSecurityContextUseCase:
    def __init__(
        self,
        projects: ProjectRepositoryPort,
        memberships: ProjectMembershipRepositoryPort,
        security_contexts: SecurityContextRepositoryPort,
        detector: Callable[[dict[str, str]], DetectionResult],
        id_generator: IdGeneratorPort,
        clock: ClockPort,
    ) -> None:
        self._projects = projects
        self._memberships = memberships
        self._security_contexts = security_contexts
        self._detector = detector
        self._id_generator = id_generator
        self._clock = clock

    async def execute(
        self, project_id: str, user_id: str, files: dict[str, str]
    ) -> SecurityContext:
        project = await self._projects.get_by_id(project_id)
        if project is None:
            raise ProjectNotFound(f"No project with id '{project_id}'")

        membership = await self._memberships.get_by_project_and_user(project_id, user_id)
        require_owner(membership)

        result = self._detector(files)

        existing = await self._security_contexts.get_by_project_id(project_id)
        context = SecurityContext(
            # Reuses the existing row's id and created_at, on UpdateScannerConfigUseCase's
            # precedent: this is one Security Context per project being refreshed, not a
            # new record each time detect runs. The upsert keeps both columns, so minting
            # fresh ones here would return values the row does not carry.
            id=existing.id if existing is not None else self._id_generator.new_id(),
            project_id=project_id,
            language=result.language,
            framework=result.framework,
            database=None,
            deployment_target=result.deployment_target,
            ci_provider=result.ci_provider,
            # The owner's confirmed tags, carried through unchanged. The upsert's set_
            # omits the column so a re-detect cannot touch it (ADR-0039 decision 3); this
            # is what makes the RETURNED context agree with the stored row, which it
            # would not if it reported [] for a project that has tags.
            exposure_tags=list(existing.exposure_tags) if existing is not None else [],
            created_at=existing.created_at if existing is not None else self._clock.now(),
        )
        await self._security_contexts.upsert_detected(context)

        return context
