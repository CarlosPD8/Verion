from typing import Protocol


class RepoCheckoutPort(Protocol):
    async def checkout(self, repo_url: str, access_token: str | None) -> str:
        """Clones repo_url into a fresh local temp directory, returns its path."""
        ...

    async def cleanup(self, local_path: str) -> None:
        """Removes the temp directory created by checkout."""
        ...
