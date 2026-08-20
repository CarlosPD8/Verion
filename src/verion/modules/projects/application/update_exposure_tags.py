import dataclasses

from verion.modules.projects.domain.authorization import require_owner
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


class UpdateExposureTagsUseCase:
    def __init__(
        self,
        projects: ProjectRepositoryPort,
        memberships: ProjectMembershipRepositoryPort,
        security_contexts: SecurityContextRepositoryPort,
        id_generator: IdGeneratorPort,
        clock: ClockPort,
    ) -> None:
        self._projects = projects
        self._memberships = memberships
        self._security_contexts = security_contexts
        self._id_generator = id_generator
        self._clock = clock

    async def execute(
        self, project_id: str, user_id: str, exposure_tags: list[str]
    ) -> SecurityContext:
        project = await self._projects.get_by_id(project_id)
        if project is None:
            raise ProjectNotFound(f"No project with id '{project_id}'")

        membership = await self._memberships.get_by_project_and_user(project_id, user_id)
        require_owner(membership)

        existing = await self._security_contexts.get_by_project_id(project_id)

        # Annotation never requires detection to have run first: a context
        # made of only exposure_tags (everything else None) is valid.
        if existing is not None:
            updated = dataclasses.replace(existing, exposure_tags=exposure_tags)
            await self._security_contexts.update(updated)
            return updated

        new_context = SecurityContext(
            id=self._id_generator.new_id(),
            project_id=project_id,
            language=None,
            framework=None,
            database=None,
            deployment_target=None,
            ci_provider=None,
            exposure_tags=exposure_tags,
            created_at=self._clock.now(),
        )
        await self._security_contexts.add(new_context)
        return new_context
