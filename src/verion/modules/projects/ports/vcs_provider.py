from dataclasses import dataclass
from typing import Protocol

# Raises verion.modules.projects.domain.exceptions.GitHubApiError on any
# failure (timeout, non-2xx, rate limit) — never lets an httpx2 exception
# escape the adapter boundary. Async: real network I/O, per rule 7.


@dataclass(frozen=True)
class RepoMetadata:
    default_branch: str
    description: str


@dataclass(frozen=True)
class SourceArchive:
    """A repository's source files as read from ONE archive of one commit.

    **`commit_sha` is the commit this archive was cut from, and nothing more.** It says
    which tree these `files` came from. It does not describe anything read through the
    other methods on this port, which make their own separate requests — see **G56**.

    `files` maps a repo-relative path to its UTF-8 text, for the members the adapter's
    allowlist admits. `undecodable_files` names allowlisted members that were not valid
    UTF-8, so a caller can report them instead of losing them silently.
    """

    commit_sha: str
    files: dict[str, str]
    undecodable_files: tuple[str, ...]


class VcsProviderPort(Protocol):
    async def fetch_repo_metadata(
        self, access_token: str, owner: str, repo: str
    ) -> RepoMetadata: ...

    async def list_repo_files(self, access_token: str, owner: str, repo: str) -> list[str]: ...

    async def get_file_content(
        self, access_token: str, owner: str, repo: str, path: str
    ) -> str | None: ...

    async def fetch_source_archive(self, access_token: str, owner: str, repo: str) -> SourceArchive:
        """The default branch's source as one archive. M5.6 commit 4, ADR-0029.

        Raises `GitHubApiError` when the archive cannot be fetched,
        `SourceArchiveTooLarge` when it exceeds a size cap, and `SourceArchiveMalformed`
        when it is not the shape GitHub serves. All three are projects-domain exceptions.

        **There is deliberately no `ref` parameter.** The adapter asks for `HEAD`, the
        same tip `list_repo_files` reads, so **G52**'s trigger — *"any change giving
        `VcsProviderPort` a `ref` parameter"* — does not fire here.
        """
        ...

    async def register_webhook(self, access_token: str, owner: str, repo: str) -> None:
        """Registers (idempotently) this app's push webhook on the given
        repo. The target URL and signing secret are adapter configuration
        (constructor-injected), not call arguments — mirrors
        SemgrepAdapter(config=...)'s existing config-via-constructor shape
        rather than threading platform config through use-case call
        signatures. M3.6."""
        ...
