from typing import Protocol

from verion.modules.projects.domain.project import ConnectedRepo


class ConnectedRepoRepositoryPort(Protocol):
    async def add(self, connected_repo: ConnectedRepo) -> None: ...

    async def get_by_id(self, connected_repo_id: str) -> ConnectedRepo | None: ...
