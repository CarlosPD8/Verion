from typing import Protocol

from verion.modules.identity.domain.github_connection import GitHubConnection


class GitHubConnectionRepositoryPort(Protocol):
    async def add(self, connection: GitHubConnection) -> None: ...

    async def get_by_user_id(self, user_id: str) -> GitHubConnection | None: ...
