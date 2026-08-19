from typing import Protocol

from verion.modules.projects.domain.project import Project


class ProjectRepositoryPort(Protocol):
    async def add(self, project: Project) -> None: ...

    async def get_by_id(self, project_id: str) -> Project | None: ...
