from typing import Protocol

from verion.modules.projects.domain.security_context import SecurityContext


class SecurityContextRepositoryPort(Protocol):
    async def add(self, context: SecurityContext) -> None: ...

    async def get_by_project_id(self, project_id: str) -> SecurityContext | None: ...
