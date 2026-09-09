"""The serving-declaration route pair, through the real router against real Postgres.

**The acceptance criterion for the whole of M5.5 is one test here**:
`test_declaring_then_repointing_the_target_turns_the_verdict_off`. M5.5 has no
correlation consumer by design — ADR-0028 decision 5 says so and G48 records why the
cross-module port waits for M5.6 — so `projects`' own read surface is the only thing that
can demonstrate the declaration works at all. Without that sequence this issue ships a
column nothing exercises end to end.

**How far that sequence reaches, stated here rather than only in a commit message**,
because four green steps otherwise read as proving the whole rule. `declaration_in_force`
compares **three** pairs and this sequence can falsify exactly **one** of them, the target
URL. `ConnectedRepo` has no update route anywhere in this API — `ConnectRepositoryUseCase`
and its GitHub sibling both only `add` — so `declared_repo_url` and
`declared_default_branch` cannot be made to differ from their live counterparts through
HTTP at all. Those two pairs are covered by `tests/unit/test_declare_serving.py` and
`tests/unit/test_serving_declaration.py` and by nothing here. That is the same asymmetry
ADR-0028 decision 2 and **G50** already record, arriving on a third axis.
"""

import httpx2
import pytest_asyncio

from verion.modules.identity.adapters.outbound.security.jwt_issuer import JwtAccessTokenIssuer
from verion.modules.projects.adapters.outbound.db.repository import (
    PostgresProjectMembershipRepository,
)
from verion.modules.projects.domain.project import ProjectMembership, Role
from verion.platform.app import app
from verion.platform.clock import SystemClock
from verion.platform.settings import get_settings

_TARGET = "https://staging.example.com"
_REPO_URL = "https://github.com/example/repo"
_BRANCH = "main"


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


async def _seed_project(client, db_session, *, target: str | None = _TARGET) -> str:
    """A project with a connected repository and a ZAP target, all through the routes.

    Everything a declaration is compared against is established over HTTP rather than
    through repositories, so the sequence test below is driving the same surface a real
    owner would.
    """
    response = await client.post(
        "/projects/", json={"name": "Verion"}, headers=_auth_headers("owner-1")
    )
    project_id = response.json()["id"]

    await client.post(
        f"/projects/{project_id}/repositories",
        json={"provider": "github", "url": _REPO_URL, "default_branch": _BRANCH},
        headers=_auth_headers("owner-1"),
    )
    if target is not None:
        await client.put(
            f"/projects/{project_id}/scanner-config",
            json={"enabled_tools": ["zap"], "zap_target_url": target},
            headers=_auth_headers("owner-1"),
        )
    await db_session.commit()
    return project_id


def _body(target: str = _TARGET, repo_url: str = _REPO_URL, branch: str = _BRANCH):
    return {
        "declared_target_url": target,
        "declared_repo_url": repo_url,
        "declared_default_branch": branch,
    }


async def _declare(client, project_id, user_id="owner-1", **overrides):
    return await client.put(
        f"/projects/{project_id}/serving-declaration",
        json=_body(**overrides),
        headers=_auth_headers(user_id),
    )


# --- the acceptance criterion -----------------------------------------------


async def test_declaring_then_repointing_the_target_turns_the_verdict_off(client, db_session):
    """M5.5's acceptance criterion, in four steps over the real API.

    Declare, read back in force, repoint `zap_target_url`, read back not in force — with
    **no write to the declaration between the two reads**. The row is byte-identical
    across them and only the configuration around it moved, which is what makes ADR-0028
    decision 2's rule read-time rather than a stored flag.

    See this module's docstring for which of the rule's three pairs this can falsify and
    which it cannot.
    """
    project_id = await _seed_project(client, db_session)

    declared = await _declare(client, project_id)
    assert declared.status_code == 200
    assert declared.json()["in_force"] is True

    first_read = await client.get(
        f"/projects/{project_id}/serving-declaration", headers=_auth_headers("owner-1")
    )
    assert first_read.status_code == 200
    assert first_read.json()["in_force"] is True

    repointed = await client.put(
        f"/projects/{project_id}/scanner-config",
        json={"enabled_tools": ["zap"], "zap_target_url": "https://prod.example.com"},
        headers=_auth_headers("owner-1"),
    )
    assert repointed.status_code == 200

    second_read = await client.get(
        f"/projects/{project_id}/serving-declaration", headers=_auth_headers("owner-1")
    )
    assert second_read.status_code == 200
    assert second_read.json()["in_force"] is False
    # The stored values are still the ones that were declared, which is what lets an
    # owner see WHY the verdict flipped rather than only that it did.
    assert second_read.json()["declared_target_url"] == _TARGET
    assert first_read.json()["id"] == second_read.json()["id"]


# --- the compare-and-set ----------------------------------------------------


async def test_declaring_values_that_are_not_the_current_ones_returns_409(client, db_session):
    """The compare-and-set precondition failing, named by status code.

    409 rather than 400 because the request is well-formed and the resource is simply not
    in the state it presumes — ADR-0028's 2026-09-09 amendment A. Pinned by name the way
    `test_register_duplicate_email_returns_409` pins this codebase's only other 409.
    """
    project_id = await _seed_project(client, db_session)

    response = await _declare(client, project_id, target="https://not-configured.example.com")

    assert response.status_code == 409


async def test_a_refused_declaration_leaves_nothing_to_read(client, db_session):
    """A stored-then-refused row would be the void-from-birth record the amendment exists
    to prevent, arriving by a different door."""
    project_id = await _seed_project(client, db_session)
    await _declare(client, project_id, branch="develop")

    response = await client.get(
        f"/projects/{project_id}/serving-declaration", headers=_auth_headers("owner-1")
    )

    assert response.status_code == 404


async def test_declaring_a_target_url_carrying_credentials_returns_400_and_never_echoes_it(
    client, db_session
):
    """Rule 12 on the write path. 400 rather than 409, because the URL is malformed before
    it is stale — `validate_zap_target_url` runs before the compare-and-set."""
    project_id = await _seed_project(client, db_session)

    response = await _declare(client, project_id, target="https://tokenuser:s3cr3t@example.com")

    assert response.status_code == 400
    assert "s3cr3t" not in response.text
    assert "tokenuser" not in response.text


async def test_declaring_without_a_configured_target_returns_400(client, db_session):
    project_id = await _seed_project(client, db_session, target=None)

    response = await _declare(client, project_id)

    assert response.status_code == 400


# --- authorization and absence ----------------------------------------------


async def test_a_member_cannot_declare_but_can_read(client, db_session):
    """The module's uniform split, exercised on both routes of the pair in one test so a
    change to either half is visible against the other."""
    project_id = await _seed_project(client, db_session)
    await _declare(client, project_id)
    await PostgresProjectMembershipRepository(db_session).add(
        ProjectMembership(project_id=project_id, user_id="member-1", role=Role.MEMBER)
    )
    await db_session.commit()

    declared = await _declare(client, project_id, user_id="member-1")
    read = await client.get(
        f"/projects/{project_id}/serving-declaration", headers=_auth_headers("member-1")
    )

    assert declared.status_code == 403
    assert read.status_code == 200


async def test_declaring_without_a_token_returns_401(client, db_session):
    project_id = await _seed_project(client, db_session)

    response = await client.put(f"/projects/{project_id}/serving-declaration", json=_body())

    assert response.status_code == 401


async def test_reading_without_a_token_returns_401(client, db_session):
    project_id = await _seed_project(client, db_session)

    response = await client.get(f"/projects/{project_id}/serving-declaration")

    assert response.status_code == 401


async def test_reading_before_anything_is_declared_returns_404(client, db_session):
    """Distinct from a declaration that has gone out of force, which reads 200 with
    `in_force: false`. The two call for different acts by the owner."""
    project_id = await _seed_project(client, db_session)

    response = await client.get(
        f"/projects/{project_id}/serving-declaration", headers=_auth_headers("owner-1")
    )

    assert response.status_code == 404


async def test_declaring_against_a_project_with_no_connected_repository_returns_404(
    client, db_session
):
    response = await client.post(
        "/projects/", json={"name": "Verion"}, headers=_auth_headers("owner-1")
    )
    project_id = response.json()["id"]
    await client.put(
        f"/projects/{project_id}/scanner-config",
        json={"enabled_tools": ["zap"], "zap_target_url": _TARGET},
        headers=_auth_headers("owner-1"),
    )
    await db_session.commit()

    declared = await _declare(client, project_id)

    assert declared.status_code == 404


# --- the response body ------------------------------------------------------


async def test_the_response_carries_exactly_these_fields_and_declared_by_is_one_of_them(
    client, db_session
):
    """The exact key set, so an added field fails here rather than shipping unnoticed —
    `test_security_context_routes.py`'s shape.

    **`declared_by` is asserted PRESENT, not absent**, and that is the deliberate reading:
    it is a user id rather than a credential, so rule 12 does not reach it, exactly as
    `ScannerConfigResponse`'s comment already records for
    `active_scan_consent_granted_by`. What rule 12 does reach is checked on the write path
    above, where a credential-bearing target URL is refused without being echoed.
    """
    project_id = await _seed_project(client, db_session)
    await _declare(client, project_id)

    response = await client.get(
        f"/projects/{project_id}/serving-declaration", headers=_auth_headers("owner-1")
    )

    body = response.json()
    assert set(body.keys()) == {
        "id",
        "project_id",
        "in_force",
        "declared_target_url",
        "declared_repo_url",
        "declared_default_branch",
        "declared_at",
        "declared_by",
    }
    assert body["declared_by"] == "owner-1"
    assert body["project_id"] == project_id
