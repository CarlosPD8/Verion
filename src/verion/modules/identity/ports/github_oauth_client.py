from dataclasses import dataclass
from typing import Protocol

# build_authorize_url is sync (pure URL construction, no I/O).
# exchange_code_for_identity is async — a real network call to GitHub,
# per CLAUDE.md rule 7 (outbound I/O-bound ports are async by default).
# Raises verion.modules.identity.domain.exceptions.GitHubApiError on any
# failure (timeout, non-2xx, rate limit) — never lets an httpx2 exception
# escape the adapter boundary.


@dataclass(frozen=True)
class GitHubIdentity:
    access_token: str
    username: str


class GitHubOAuthClientPort(Protocol):
    def build_authorize_url(self, state: str) -> str: ...

    async def exchange_code_for_identity(self, code: str) -> GitHubIdentity: ...
