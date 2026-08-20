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
    PostgresConnectedRepoRepository,
    PostgresProjectMembershipRepository,
    PostgresSecurityContextRepository,
)
from verion.modules.projects.domain.exceptions import GitHubApiError
from verion.modules.projects.domain.project import ConnectedRepo, ProjectMembership, Role
from verion.modules.projects.domain.security_context import SecurityContext
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
    def __init__(self, files: dict[str, str] | None = None, fail: bool = False) -> None:
        self._files = files or {}
        self._fail = fail

    async def list_repo_files(self, access_token: str, owner: str, repo: str) -> list[str]:
        if self._fail:
            raise GitHubApiError("simulated GitHub API failure")
        return list(self._files.keys())

    async def get_file_content(
        self, access_token: str, owner: str, repo: str, path: str
    ) -> str | None:
        if self._fail:
            raise GitHubApiError("simulated GitHub API failure")
        return self._files.get(path)


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


async def _connect_repo(
    db_session,
    project_id: str,
    provider: str = "github",
    url: str = "https://github.com/example/repo",
) -> None:
    await PostgresConnectedRepoRepository(db_session).add(
        ConnectedRepo(
            id="repo-1", project_id=project_id, provider=provider, url=url, default_branch="main"
        )
    )
    await db_session.commit()


async def test_detect_as_owner_returns_201_with_detected_context(client, db_session):
    app.dependency_overrides[get_vcs_provider] = lambda: _FakeVcsProvider(
        files={"pyproject.toml": 'dependencies = ["fastapi"]', "Dockerfile": "FROM python:3.12"}
    )
    await _connect_github_account(db_session, "owner-1")
    project_id = await _create_project(client, "owner-1")
    await _connect_repo(db_session, project_id)

    response = await client.post(
        f"/projects/{project_id}/security-context/detect", headers=_auth_headers("owner-1")
    )

    assert response.status_code == 201
    body = response.json()
    assert body["project_id"] == project_id
    assert body["language"] == "python"
    assert body["framework"] == "fastapi"
    assert body["exposure_tags"] == []
    assert set(body.keys()) == {
        "id",
        "project_id",
        "language",
        "framework",
        "database",
        "deployment_target",
        "ci_provider",
        "exposure_tags",
        "created_at",
    }


async def test_detect_as_non_owner_member_returns_403(client, db_session):
    app.dependency_overrides[get_vcs_provider] = lambda: _FakeVcsProvider(fail=True)
    await _connect_github_account(db_session, "member-1")
    project_id = await _create_project(client, "owner-1")
    await PostgresProjectMembershipRepository(db_session).add(
        ProjectMembership(project_id=project_id, user_id="member-1", role=Role.MEMBER)
    )
    await db_session.commit()

    response = await client.post(
        f"/projects/{project_id}/security-context/detect", headers=_auth_headers("member-1")
    )

    assert response.status_code == 403


async def test_detect_as_non_member_returns_403(client, db_session):
    await _connect_github_account(db_session, "stranger")
    project_id = await _create_project(client, "owner-1")

    response = await client.post(
        f"/projects/{project_id}/security-context/detect", headers=_auth_headers("stranger")
    )

    assert response.status_code == 403


async def test_detect_against_unknown_project_returns_404(client, db_session):
    await _connect_github_account(db_session, "owner-1")

    response = await client.post(
        "/projects/does-not-exist/security-context/detect", headers=_auth_headers("owner-1")
    )

    assert response.status_code == 404


async def test_detect_without_connected_repo_returns_404(client, db_session):
    await _connect_github_account(db_session, "owner-1")
    project_id = await _create_project(client, "owner-1")

    response = await client.post(
        f"/projects/{project_id}/security-context/detect", headers=_auth_headers("owner-1")
    )

    assert response.status_code == 404


async def test_detect_against_a_non_github_repo_returns_400(client, db_session):
    await _connect_github_account(db_session, "owner-1")
    project_id = await _create_project(client, "owner-1")
    await _connect_repo(
        db_session, project_id, provider="gitlab", url="https://gitlab.com/example/repo"
    )

    response = await client.post(
        f"/projects/{project_id}/security-context/detect", headers=_auth_headers("owner-1")
    )

    assert response.status_code == 400


async def test_detect_github_api_error_returns_502(client, db_session):
    app.dependency_overrides[get_vcs_provider] = lambda: _FakeVcsProvider(fail=True)
    await _connect_github_account(db_session, "owner-1")
    project_id = await _create_project(client, "owner-1")
    await _connect_repo(db_session, project_id)

    response = await client.post(
        f"/projects/{project_id}/security-context/detect", headers=_auth_headers("owner-1")
    )

    assert response.status_code == 502


async def test_get_as_owner_returns_200(client, db_session):
    project_id = await _create_project(client, "owner-1")
    await PostgresSecurityContextRepository(db_session).add(
        SecurityContext(
            id="context-1",
            project_id=project_id,
            language="python",
            framework=None,
            database=None,
            deployment_target=None,
            ci_provider=None,
            exposure_tags=[],
            created_at=datetime(2026, 1, 1, tzinfo=UTC),
        )
    )
    await db_session.commit()

    response = await client.get(
        f"/projects/{project_id}/security-context", headers=_auth_headers("owner-1")
    )

    assert response.status_code == 200
    assert response.json()["language"] == "python"


async def test_get_as_plain_member_returns_200(client, db_session):
    project_id = await _create_project(client, "owner-1")
    await PostgresProjectMembershipRepository(db_session).add(
        ProjectMembership(project_id=project_id, user_id="member-1", role=Role.MEMBER)
    )
    await PostgresSecurityContextRepository(db_session).add(
        SecurityContext(
            id="context-1",
            project_id=project_id,
            language=None,
            framework=None,
            database=None,
            deployment_target=None,
            ci_provider=None,
            exposure_tags=["public_facing"],
            created_at=datetime(2026, 1, 1, tzinfo=UTC),
        )
    )
    await db_session.commit()

    response = await client.get(
        f"/projects/{project_id}/security-context", headers=_auth_headers("member-1")
    )

    assert response.status_code == 200
    assert response.json()["exposure_tags"] == ["public_facing"]


async def test_get_as_non_member_returns_403(client):
    project_id = await _create_project(client, "owner-1")

    response = await client.get(
        f"/projects/{project_id}/security-context", headers=_auth_headers("stranger")
    )

    assert response.status_code == 403


async def test_get_against_unknown_project_returns_404(client):
    response = await client.get(
        "/projects/does-not-exist/security-context", headers=_auth_headers("owner-1")
    )

    assert response.status_code == 404


async def test_get_before_any_context_exists_returns_404(client):
    project_id = await _create_project(client, "owner-1")

    response = await client.get(
        f"/projects/{project_id}/security-context", headers=_auth_headers("owner-1")
    )

    assert response.status_code == 404


async def test_patch_as_owner_creates_a_tags_only_context_returns_200(client):
    project_id = await _create_project(client, "owner-1")

    response = await client.patch(
        f"/projects/{project_id}/security-context",
        json={"exposure_tags": ["public_facing", "handles_pii"]},
        headers=_auth_headers("owner-1"),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["exposure_tags"] == ["public_facing", "handles_pii"]
    assert body["language"] is None


async def test_patch_as_owner_updates_an_existing_context_returns_200(client, db_session):
    project_id = await _create_project(client, "owner-1")
    await PostgresSecurityContextRepository(db_session).add(
        SecurityContext(
            id="context-1",
            project_id=project_id,
            language="python",
            framework="fastapi",
            database=None,
            deployment_target="docker",
            ci_provider=None,
            exposure_tags=[],
            created_at=datetime(2026, 1, 1, tzinfo=UTC),
        )
    )
    await db_session.commit()

    response = await client.patch(
        f"/projects/{project_id}/security-context",
        json={"exposure_tags": ["public_facing"]},
        headers=_auth_headers("owner-1"),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["exposure_tags"] == ["public_facing"]
    assert body["language"] == "python"


async def test_patch_as_non_owner_returns_403(client, db_session):
    project_id = await _create_project(client, "owner-1")
    await PostgresProjectMembershipRepository(db_session).add(
        ProjectMembership(project_id=project_id, user_id="member-1", role=Role.MEMBER)
    )
    await db_session.commit()

    response = await client.patch(
        f"/projects/{project_id}/security-context",
        json={"exposure_tags": ["public_facing"]},
        headers=_auth_headers("member-1"),
    )

    assert response.status_code == 403


async def test_patch_against_unknown_project_returns_404(client):
    response = await client.patch(
        "/projects/does-not-exist/security-context",
        json={"exposure_tags": ["public_facing"]},
        headers=_auth_headers("owner-1"),
    )

    assert response.status_code == 404
