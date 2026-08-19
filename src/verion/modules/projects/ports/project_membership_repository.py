from typing import Protocol

from verion.modules.projects.domain.project import ProjectMembership


class ProjectMembershipRepositoryPort(Protocol):
    async def add(self, membership: ProjectMembership) -> None: ...

    async def get_by_project_and_user(
        self, project_id: str, user_id: str
    ) -> ProjectMembership | None: ...
