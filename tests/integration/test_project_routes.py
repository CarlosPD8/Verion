import httpx2
import pytest_asyncio
from sqlalchemy import text

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


async def test_connect_repository_as_owner_returns_200(client):
    create_response = await client.post(
        "/projects/", json={"name": "Verion"}, headers=_auth_headers("owner-1")
    )
    project_id = create_response.json()["id"]

    response = await client.put(
        f"/projects/{project_id}/repositories",
        json={
            "provider": "github",
            "url": "https://github.com/example/repo",
            "default_branch": "main",
        },
        headers=_auth_headers("owner-1"),
    )

    assert response.status_code == 200
    assert response.json()["project_id"] == project_id


async def test_connect_repository_with_a_credential_in_the_url_returns_400_without_echoing_it(
    client,
):
    """Rule 12 through the real router: a 400 whose body does not carry the credential.

    That no row is stored is asserted by the unit test, not here."""
    create_response = await client.post(
        "/projects/", json={"name": "Verion"}, headers=_auth_headers("owner-1")
    )
    project_id = create_response.json()["id"]

    response = await client.put(
        f"/projects/{project_id}/repositories",
        json={
            "provider": "github",
            "url": "https://octocat:ghp_s3cret@github.com/example/repo",
            "default_branch": "main",
        },
        headers=_auth_headers("owner-1"),
    )

    assert response.status_code == 400
    assert "ghp_s3cret" not in response.text


async def test_connect_repository_as_non_owner_member_returns_403(client, db_session):
    create_response = await client.post(
        "/projects/", json={"name": "Verion"}, headers=_auth_headers("owner-1")
    )
    project_id = create_response.json()["id"]
    project = await PostgresProjectRepository(db_session).get_by_id(project_id)
    await PostgresProjectMembershipRepository(db_session).add(
        ProjectMembership(project_id=project.id, user_id="member-1", role=Role.MEMBER)
    )

    response = await client.put(
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

    response = await client.put(
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
    response = await client.put(
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
    response = await client.put(
        "/projects/some-project/repositories",
        json={
            "provider": "github",
            "url": "https://github.com/example/repo",
            "default_branch": "main",
        },
    )

    assert response.status_code == 401


async def test_connecting_a_second_time_replaces_the_first(client, db_session):
    """ADR-0039 decision 4, end to end through the real route — M8.7.

    Two owner-authorized connect calls, each individually legitimate. Before this they
    left a project on which scanning stopped (**G51**); now the second replaces the
    first. This is also what gives **G60**'s credential-bearing row the way out that
    entry says it lacks, and what M8.4's onboarding flow needs when an owner connects
    the wrong repository — without it a typo makes the project permanently disposable.

    Asserting one row is what kills the mutation that turns the upsert back into a
    plain insert; asserting the id is preserved is what kills the one that drops the
    read-first and mints a fresh id the stored row would not carry.
    """
    create_response = await client.post(
        "/projects/", json={"name": "Verion"}, headers=_auth_headers("owner-1")
    )
    project_id = create_response.json()["id"]
    payload = {"provider": "github", "default_branch": "main"}

    first = await client.put(
        f"/projects/{project_id}/repositories",
        json={**payload, "url": "https://github.com/example/wrong"},
        headers=_auth_headers("owner-1"),
    )
    second = await client.put(
        f"/projects/{project_id}/repositories",
        json={**payload, "url": "https://github.com/example/right"},
        headers=_auth_headers("owner-1"),
    )

    assert first.status_code == 200
    assert second.status_code == 200
    # The id the caller gets back is the stored one, on both calls.
    assert second.json()["id"] == first.json()["id"]
    assert second.json()["url"] == "https://github.com/example/right"

    rows = (
        await db_session.execute(
            text("SELECT id, url FROM connected_repos WHERE project_id = :p"),
            {"p": project_id},
        )
    ).all()
    assert [(row.id, row.url) for row in rows] == [
        (first.json()["id"], "https://github.com/example/right")
    ]
