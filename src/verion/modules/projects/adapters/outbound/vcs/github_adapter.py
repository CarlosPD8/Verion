import base64

import httpx2

from verion.modules.projects.domain.exceptions import GitHubApiError
from verion.modules.projects.ports.vcs_provider import RepoMetadata

_API_BASE = "https://api.github.com"


class GitHubAdapter:
    def __init__(
        self,
        transport: httpx2.BaseTransport | None = None,
        webhook_url: str | None = None,
        webhook_secret: str | None = None,
    ) -> None:
        # Injection seam for tests (httpx2.MockTransport over fixture data);
        # None keeps real network behavior for production DI wiring.
        self._transport = transport
        # webhook_url/webhook_secret are only required for register_webhook
        # (M3.6) — every other method on this adapter predates them and
        # doesn't touch either attribute.
        self._webhook_url = webhook_url
        self._webhook_secret = webhook_secret

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

    async def register_webhook(self, access_token: str, owner: str, repo: str) -> None:
        # List-then-create, not a bare POST: GitHub's docs don't state
        # whether POST /hooks dedupes an identical config.url, so this
        # queries existing hooks first and treats a config.url match as
        # already-registered (idempotent register — safe on reconnect/
        # redeploy without creating duplicate hooks).
        async with httpx2.AsyncClient(timeout=10.0, transport=self._transport) as client:
            try:
                existing = await client.get(
                    f"{_API_BASE}/repos/{owner}/{repo}/hooks",
                    headers=self._headers(access_token),
                )
                existing.raise_for_status()
                for hook in existing.json():
                    if hook.get("config", {}).get("url") == self._webhook_url:
                        return

                response = await client.post(
                    f"{_API_BASE}/repos/{owner}/{repo}/hooks",
                    headers=self._headers(access_token),
                    json={
                        "name": "web",
                        "config": {
                            "url": self._webhook_url,
                            "content_type": "json",
                            "secret": self._webhook_secret,
                            "insecure_ssl": "0",
                        },
                        "events": ["push"],
                        "active": True,
                    },
                )
                response.raise_for_status()
            except httpx2.HTTPError as exc:
                raise GitHubApiError("GitHub API request failed") from exc

    def _headers(self, access_token: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github+json",
        }
