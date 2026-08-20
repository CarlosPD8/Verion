from verion.modules.projects.domain.authorization import require_member
from verion.modules.projects.domain.exceptions import ProjectNotFound, SecurityContextNotFound
from verion.modules.projects.domain.security_context import SecurityContext
from verion.modules.projects.ports.project_membership_repository import (
    ProjectMembershipRepositoryPort,
)
from verion.modules.projects.ports.project_repository import ProjectRepositoryPort
from verion.modules.projects.ports.security_context_repository import (
    SecurityContextRepositoryPort,
)


class GetSecurityContextUseCase:
    def __init__(
        self,
        projects: ProjectRepositoryPort,
        memberships: ProjectMembershipRepositoryPort,
        security_contexts: SecurityContextRepositoryPort,
    ) -> None:
        self._projects = projects
        self._memberships = memberships
        self._security_contexts = security_contexts

    async def execute(self, project_id: str, user_id: str) -> SecurityContext:
        project = await self._projects.get_by_id(project_id)
        if project is None:
            raise ProjectNotFound(f"No project with id '{project_id}'")

        membership = await self._memberships.get_by_project_and_user(project_id, user_id)
        require_member(membership)

        context = await self._security_contexts.get_by_project_id(project_id)
        if context is None:
            raise SecurityContextNotFound(f"No security context for project '{project_id}'")

        return context
