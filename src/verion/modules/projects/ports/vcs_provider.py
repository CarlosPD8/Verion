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

    # Signatures only as of M2.1 — GitHubAdapter doesn't implement these yet.
    # Real implementation (and the context-extraction adapter that calls
    # them) lands in M2.2.
    async def list_repo_files(self, access_token: str, owner: str, repo: str) -> list[str]: ...

    async def get_file_content(
        self, access_token: str, owner: str, repo: str, path: str
    ) -> str | None: ...

    async def register_webhook(self, access_token: str, owner: str, repo: str) -> None:
        """Registers (idempotently) this app's push webhook on the given
        repo. The target URL and signing secret are adapter configuration
        (constructor-injected), not call arguments — mirrors
        SemgrepAdapter(config=...)'s existing config-via-constructor shape
        rather than threading platform config through use-case call
        signatures. M3.6."""
        ...
