from urllib.parse import urlencode

import httpx2

from verion.modules.identity.domain.exceptions import GitHubApiError
from verion.modules.identity.ports.github_oauth_client import GitHubIdentity

_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
_TOKEN_URL = "https://github.com/login/oauth/access_token"
_USER_URL = "https://api.github.com/user"


class GitHubOAuthClient:
    def __init__(self, client_id: str, client_secret: str, redirect_uri: str) -> None:
        self._client_id = client_id
        self._client_secret = client_secret
        self._redirect_uri = redirect_uri

    def build_authorize_url(self, state: str) -> str:
        params = urlencode(
            {
                "client_id": self._client_id,
                "redirect_uri": self._redirect_uri,
                "state": state,
                "scope": "repo",
            }
        )
        return f"{_AUTHORIZE_URL}?{params}"

    async def exchange_code_for_identity(self, code: str) -> GitHubIdentity:
        async with httpx2.AsyncClient(timeout=10.0) as client:
            try:
                token_response = await client.post(
                    _TOKEN_URL,
                    data={
                        "client_id": self._client_id,
                        "client_secret": self._client_secret,
                        "code": code,
                        "redirect_uri": self._redirect_uri,
                    },
                    headers={"Accept": "application/json"},
                )
                token_response.raise_for_status()
                token_body = token_response.json()

                access_token = token_body.get("access_token")
                if not access_token:
                    raise GitHubApiError(
                        f"GitHub token exchange did not return an access token: "
                        f"{token_body.get('error', 'unknown error')}"
                    )

                user_response = await client.get(
                    _USER_URL,
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "Accept": "application/vnd.github+json",
                    },
                )
                user_response.raise_for_status()
                username = user_response.json()["login"]
            except httpx2.HTTPError as exc:
                raise GitHubApiError("GitHub API request failed") from exc

        return GitHubIdentity(access_token=access_token, username=username)
