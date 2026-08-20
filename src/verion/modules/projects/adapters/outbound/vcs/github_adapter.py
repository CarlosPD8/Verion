import base64

import httpx2

from verion.modules.projects.domain.exceptions import GitHubApiError
from verion.modules.projects.ports.vcs_provider import RepoMetadata

_API_BASE = "https://api.github.com"


class GitHubAdapter:
    def __init__(self, transport: httpx2.BaseTransport | None = None) -> None:
        # Injection seam for tests (httpx2.MockTransport over fixture data);
        # None keeps real network behavior for production DI wiring.
        self._transport = transport

    async def fetch_repo_metadata(self, access_token: str, owner: str, repo: str) -> RepoMetadata:
        async with httpx2.AsyncClient(timeout=10.0, transport=self._transport) as client:
            try:
                response = await client.get(
                    f"{_API_BASE}/repos/{owner}/{repo}",
                    headers=self._headers(access_token),
                )
                response.raise_for_status()
                body = response.json()
            except httpx2.HTTPError as exc:
                raise GitHubApiError("GitHub API request failed") from exc

        return RepoMetadata(
            default_branch=body["default_branch"], description=body.get("description") or ""
        )

    async def list_repo_files(self, access_token: str, owner: str, repo: str) -> list[str]:
        async with httpx2.AsyncClient(timeout=10.0, transport=self._transport) as client:
            try:
                response = await client.get(
                    f"{_API_BASE}/repos/{owner}/{repo}/git/trees/HEAD",
                    params={"recursive": "1"},
                    headers=self._headers(access_token),
                )
                response.raise_for_status()
                body = response.json()
            except httpx2.HTTPError as exc:
                raise GitHubApiError("GitHub API request failed") from exc

        return [entry["path"] for entry in body["tree"] if entry["type"] == "blob"]

    async def get_file_content(
        self, access_token: str, owner: str, repo: str, path: str
    ) -> str | None:
        async with httpx2.AsyncClient(timeout=10.0, transport=self._transport) as client:
            try:
                response = await client.get(
                    f"{_API_BASE}/repos/{owner}/{repo}/contents/{path}",
                    headers=self._headers(access_token),
                )
                if response.status_code == 404:
                    return None
                response.raise_for_status()
                body = response.json()
            except httpx2.HTTPError as exc:
                raise GitHubApiError("GitHub API request failed") from exc

        return base64.b64decode(body["content"]).decode("utf-8")

    def _headers(self, access_token: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github+json",
        }
