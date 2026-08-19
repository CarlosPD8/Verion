import httpx2

from verion.modules.projects.domain.exceptions import GitHubApiError
from verion.modules.projects.ports.vcs_provider import RepoMetadata

_API_BASE = "https://api.github.com"


class GitHubAdapter:
    async def fetch_repo_metadata(self, access_token: str, owner: str, repo: str) -> RepoMetadata:
        async with httpx2.AsyncClient(timeout=10.0) as client:
            try:
                response = await client.get(
                    f"{_API_BASE}/repos/{owner}/{repo}",
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "Accept": "application/vnd.github+json",
                    },
                )
                response.raise_for_status()
                body = response.json()
            except httpx2.HTTPError as exc:
                raise GitHubApiError("GitHub API request failed") from exc

        return RepoMetadata(
            default_branch=body["default_branch"], description=body.get("description") or ""
        )
