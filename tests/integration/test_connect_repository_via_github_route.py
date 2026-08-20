from datetime import UTC, datetime

import httpx2
import pytest
import pytest_asyncio

from verion.modules.identity.adapters.outbound.db.repository import (
    PostgresGitHubConnectionRepository,
)
from verion.modules.identity.adapters.outbound.security.jwt_issuer import JwtAccessTokenIssuer
from verion.modules.identity.domain.github_connection import GitHubConnection
from verion.modules.projects.adapters.outbound.db.repository import (
    PostgresProjectMembershipRepository,
)
from verion.modules.projects.domain.exceptions import GitHubApiError
from verion.modules.projects.domain.project import ProjectMembership, Role
from verion.modules.projects.ports.vcs_provider import RepoMetadata
from verion.platform.app import app
from verion.platform.clock import SystemClock
from verion.platform.di import get_vcs_provider
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


class _FakeVcsProvider:
    def __init__(self, default_branch: str = "main", fail: bool = False) -> None:
        self._default_branch = default_branch
        self._fail = fail

    async def fetch_repo_metadata(self, access_token: str, owner: str, repo: str) -> RepoMetadata:
        if self._fail:
            raise GitHubApiError("simulated GitHub API failure")
        return RepoMetadata(default_branch=self._default_branch, description="")

    async def register_webhook(self, access_token: str, owner: str, repo: str) -> None:
        if self._fail:
            raise GitHubApiError("simulated GitHub API failure")


@pytest.fixture(autouse=True)
def _clear_dependency_overrides():
    yield
    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def client():
    transport = httpx2.ASGITransport(app=app)
    async with httpx2.AsyncClient(transport=transport, base_url="http://test") as async_client:
        yield async_client


async def _connect_github_account(db_session, user_id: str) -> None:
    await PostgresGitHubConnectionRepository(db_session).add(
        GitHubConnection(
            user_id=user_id,
            access_token="gho_storedtoken",
            github_username="octocat",
            connected_at=datetime(2026, 1, 1, tzinfo=UTC),
        )
    )
    await db_session.commit()


async def _create_project(client, user_id: str) -> str:
    response = await client.post(
        "/projects/", json={"name": "Verion"}, headers=_auth_headers(user_id)
    )
    return response.json()["id"]


async def test_connect_via_github_success_returns_real_metadata(client, db_session):
    app.dependency_overrides[get_vcs_provider] = lambda: _FakeVcsProvider(default_branch="develop")
    await _connect_github_account(db_session, "owner-1")
    project_id = await _create_project(client, "owner-1")

    response = await client.post(
        f"/projects/{project_id}/repositories/github",
        json={"owner": "example", "repo": "repo"},
        headers=_auth_headers("owner-1"),
    )

    assert response.status_code == 201
    body = response.json()
    assert body["provider"] == "github"
    assert body["url"] == "https://github.com/example/repo"
    assert body["default_branch"] == "develop"


async def test_connect_via_github_without_github_connection_returns_400(client):
    project_id = await _create_project(client, "owner-1")

    response = await client.post(
        f"/projects/{project_id}/repositories/github",
        json={"owner": "example", "repo": "repo"},
        headers=_auth_headers("owner-1"),
    )

    assert response.status_code == 400


async def test_connect_via_github_api_error_returns_502(client, db_session):
    app.dependency_overrides[get_vcs_provider] = lambda: _FakeVcsProvider(fail=True)
    await _connect_github_account(db_session, "owner-1")
    project_id = await _create_project(client, "owner-1")

    response = await client.post(
        f"/projects/{project_id}/repositories/github",
        json={"owner": "example", "repo": "repo"},
        headers=_auth_headers("owner-1"),
    )

    assert response.status_code == 502


async def test_connect_via_github_unknown_project_returns_404(client, db_session):
    app.dependency_overrides[get_vcs_provider] = lambda: _FakeVcsProvider()
    await _connect_github_account(db_session, "owner-1")

    response = await client.post(
        "/projects/does-not-exist/repositories/github",
        json={"owner": "example", "repo": "repo"},
        headers=_auth_headers("owner-1"),
    )

    assert response.status_code == 404


async def test_connect_via_github_as_non_owner_returns_403(client, db_session):
    app.dependency_overrides[get_vcs_provider] = lambda: _FakeVcsProvider()
    await _connect_github_account(db_session, "member-1")
    project_id = await _create_project(client, "owner-1")
    await PostgresProjectMembershipRepository(db_session).add(
        ProjectMembership(project_id=project_id, user_id="member-1", role=Role.MEMBER)
    )
    await db_session.commit()

    response = await client.post(
        f"/projects/{project_id}/repositories/github",
        json={"owner": "example", "repo": "repo"},
        headers=_auth_headers("member-1"),
    )

    assert response.status_code == 403


async def test_connect_via_github_response_never_contains_the_access_token(client, db_session):
    app.dependency_overrides[get_vcs_provider] = lambda: _FakeVcsProvider()
    await _connect_github_account(db_session, "owner-1")
    project_id = await _create_project(client, "owner-1")

    response = await client.post(
        f"/projects/{project_id}/repositories/github",
        json={"owner": "example", "repo": "repo"},
        headers=_auth_headers("owner-1"),
    )

    assert "gho_storedtoken" not in response.text
