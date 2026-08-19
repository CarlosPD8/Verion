from dataclasses import dataclass
from typing import Protocol

# Raises verion.modules.projects.domain.exceptions.GitHubApiError on any
# failure (timeout, non-2xx, rate limit) — never lets an httpx2 exception
# escape the adapter boundary. Async: real network I/O, per rule 7.


@dataclass(frozen=True)
class RepoMetadata:
    default_branch: str
    description: str


class VcsProviderPort(Protocol):
    async def fetch_repo_metadata(
        self, access_token: str, owner: str, repo: str
    ) -> RepoMetadata: ...
