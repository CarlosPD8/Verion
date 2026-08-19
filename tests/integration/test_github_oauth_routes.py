from datetime import UTC, datetime, timedelta

import httpx2
import jwt
import pytest
import pytest_asyncio

from verion.modules.identity.adapters.outbound.db.repository import (
    PostgresGitHubConnectionRepository,
)
from verion.modules.identity.adapters.outbound.security.jwt_issuer import JwtAccessTokenIssuer
from verion.modules.identity.domain.exceptions import GitHubApiError
from verion.modules.identity.ports.github_oauth_client import GitHubIdentity
from verion.platform.app import app
from verion.platform.clock import SystemClock
from verion.platform.di import get_github_oauth_client
from verion.platform.settings import get_settings


def _auth_headers(user_id: str) -> dict[str, str]:
    settings = get_settings()
    issuer = JwtAccessTokenIssuer(
        secret_key=settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
        expires_minutes=settings.jwt_expires_minutes,
        clock=SystemClock(),
    )
    return {"Authorization": f"Bearer {issuer.issue(subject=user_id).value}"}


def _valid_state(user_id: str) -> str:
    settings = get_settings()
    now = datetime.now(UTC)
    return jwt.encode(
        {
            "sub": user_id,
            "purpose": "github_oauth_state",
            "iat": now,
            "exp": now + timedelta(minutes=10),
        },
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )


def _expired_state(user_id: str) -> str:
    settings = get_settings()
    now = datetime.now(UTC)
    return jwt.encode(
        {
            "sub": user_id,
            "purpose": "github_oauth_state",
            "iat": now,
            "exp": now - timedelta(minutes=1),
        },
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )


class _FakeGitHubOAuthClient:
    def __init__(self, identity: GitHubIdentity | None = None, fail: bool = False) -> None:
        self._identity = identity
        self._fail = fail

    def build_authorize_url(self, state: str) -> str:
        return f"https://github.com/login/oauth/authorize?state={state}"

    async def exchange_code_for_identity(self, code: str) -> GitHubIdentity:
        if self._fail:
            raise GitHubApiError("simulated GitHub API failure")
        return self._identity


@pytest.fixture(autouse=True)
def _clear_dependency_overrides():
    yield
    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def client():
    transport = httpx2.ASGITransport(app=app)
    async with httpx2.AsyncClient(transport=transport, base_url="http://test") as async_client:
        yield async_client


async def test_github_login_requires_authentication(client):
    response = await client.get("/auth/github/login")

    assert response.status_code == 401


async def test_github_login_redirects_to_github_authorize_url(client):
    response = await client.get("/auth/github/login", headers=_auth_headers("user-1"))

    assert response.status_code in (302, 307)
    assert "github.com/login/oauth/authorize" in response.headers["location"]


async def test_callback_success_persists_connection_and_redirects(client, db_session):
    app.dependency_overrides[get_github_oauth_client] = lambda: _FakeGitHubOAuthClient(
        identity=GitHubIdentity(access_token="gho_realtoken", username="octocat")
    )
    state = _valid_state("user-1")

    response = await client.get(f"/auth/github/callback?code=abc123&state={state}")

    assert response.status_code in (302, 307)
    location = response.headers["location"]
    assert location == get_settings().oauth_success_redirect_url
    # CLAUDE.md rule 13: the redirect must never carry the token.
    assert "gho_realtoken" not in location

    connection = await PostgresGitHubConnectionRepository(db_session).get_by_user_id("user-1")
    assert connection is not None
    assert connection.github_username == "octocat"


async def test_callback_with_invalid_state_returns_400(client):
    response = await client.get("/auth/github/callback?code=abc123&state=garbage")

    assert response.status_code == 400


async def test_callback_with_expired_state_returns_400(client):
    state = _expired_state("user-1")

    response = await client.get(f"/auth/github/callback?code=abc123&state={state}")

    assert response.status_code == 400


async def test_callback_with_oauth_denied_error_redirects_generically(client):
    response = await client.get("/auth/github/callback?error=access_denied")

    assert response.status_code in (302, 307)
    assert response.headers["location"] == (
        f"{get_settings().oauth_success_redirect_url}?error=github_oauth_denied"
    )


async def test_callback_with_github_api_error_returns_502(client):
    app.dependency_overrides[get_github_oauth_client] = lambda: _FakeGitHubOAuthClient(fail=True)
    state = _valid_state("user-1")

    response = await client.get(f"/auth/github/callback?code=abc123&state={state}")

    assert response.status_code == 502


async def test_callback_response_never_contains_the_access_token_anywhere(client):
    app.dependency_overrides[get_github_oauth_client] = lambda: _FakeGitHubOAuthClient(
        identity=GitHubIdentity(access_token="gho_supersecrettoken", username="octocat")
    )
    state = _valid_state("user-2")

    response = await client.get(f"/auth/github/callback?code=abc123&state={state}")

    assert "gho_supersecrettoken" not in response.text
    assert "gho_supersecrettoken" not in response.headers.get("location", "")
