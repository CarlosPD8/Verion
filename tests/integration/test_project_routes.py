import httpx2
import pytest_asyncio

from verion.modules.identity.adapters.outbound.security.jwt_issuer import JwtAccessTokenIssuer
from verion.modules.projects.adapters.outbound.db.repository import (
    PostgresProjectMembershipRepository,
    PostgresProjectRepository,
)
from verion.modules.projects.domain.project import ProjectMembership, Role
from verion.platform.app import app
from verion.platform.clock import SystemClock
from verion.platform.settings import get_settings


def _auth_headers(user_id: str) -> dict[str, str]:
    settings = get_settings()
    issuer = JwtAccessTokenIssuer(
        secret_key=settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
        expires_minutes=settings.jwt_expires_minutes,
        clock=SystemClock(),
    )
    token = issuer.issue(subject=user_id)
    return {"Authorization": f"Bearer {token.value}"}


@pytest_asyncio.fixture
async def client():
    transport = httpx2.ASGITransport(app=app)
    async with httpx2.AsyncClient(transport=transport, base_url="http://test") as async_client:
        yield async_client


async def test_create_project_returns_201_with_auto_owner_membership(client, db_session):
    response = await client.post(
        "/projects/", json={"name": "Verion"}, headers=_auth_headers("owner-1")
    )

    assert response.status_code == 201
    body = response.json()
    assert body["owner_id"] == "owner-1"
    assert body["name"] == "Verion"

    membership = await PostgresProjectMembershipRepository(db_session).get_by_project_and_user(
        body["id"], "owner-1"
    )
    assert membership is not None
    assert membership.role is Role.OWNER


async def test_create_project_without_token_returns_401(client):
    response = await client.post("/projects/", json={"name": "Verion"})

    assert response.status_code == 401


async def test_create_project_with_invalid_token_returns_401(client):
    response = await client.post(
        "/projects/", json={"name": "Verion"}, headers={"Authorization": "Bearer garbage"}
    )

    assert response.status_code == 401


async def test_connect_repository_as_owner_returns_201(client):
    create_response = await client.post(
        "/projects/", json={"name": "Verion"}, headers=_auth_headers("owner-1")
    )
    project_id = create_response.json()["id"]

    response = await client.post(
        f"/projects/{project_id}/repositories",
        json={
            "provider": "github",
            "url": "https://github.com/example/repo",
            "default_branch": "main",
        },
        headers=_auth_headers("owner-1"),
    )

    assert response.status_code == 201
    assert response.json()["project_id"] == project_id


async def test_connect_repository_as_non_owner_member_returns_403(client, db_session):
    create_response = await client.post(
        "/projects/", json={"name": "Verion"}, headers=_auth_headers("owner-1")
    )
    project_id = create_response.json()["id"]
    project = await PostgresProjectRepository(db_session).get_by_id(project_id)
    await PostgresProjectMembershipRepository(db_session).add(
        ProjectMembership(project_id=project.id, user_id="member-1", role=Role.MEMBER)
    )

    response = await client.post(
        f"/projects/{project_id}/repositories",
        json={
            "provider": "github",
            "url": "https://github.com/example/repo",
            "default_branch": "main",
        },
        headers=_auth_headers("member-1"),
    )

    assert response.status_code == 403


async def test_connect_repository_as_non_member_returns_403(client):
    create_response = await client.post(
        "/projects/", json={"name": "Verion"}, headers=_auth_headers("owner-1")
    )
    project_id = create_response.json()["id"]

    response = await client.post(
        f"/projects/{project_id}/repositories",
        json={
            "provider": "github",
            "url": "https://github.com/example/repo",
            "default_branch": "main",
        },
        headers=_auth_headers("stranger"),
    )

    assert response.status_code == 403


async def test_connect_repository_against_unknown_project_returns_404(client):
    response = await client.post(
        "/projects/does-not-exist/repositories",
        json={
            "provider": "github",
            "url": "https://github.com/example/repo",
            "default_branch": "main",
        },
        headers=_auth_headers("owner-1"),
    )

    assert response.status_code == 404


async def test_connect_repository_without_token_returns_401(client):
    response = await client.post(
        "/projects/some-project/repositories",
        json={
            "provider": "github",
            "url": "https://github.com/example/repo",
            "default_branch": "main",
        },
    )

    assert response.status_code == 401
