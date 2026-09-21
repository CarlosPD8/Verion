"""`POST /projects/{id}/scans` and `GET /projects/{id}/scans/{scan_id}`, end to end (M8.8).

Real Postgres, real Redis, and the real wiring for the two things this file exists to prove:

- **Authorization.** Nothing overrides `get_project_access`, so the verdict comes from the real
  `PostgresProjectAccessReader` over real membership rows (G65). The mutation the POST tests
  are built to kill is "a non-owner member gets 202 instead of 404".
- **Commit ordering.** Only `get_arq_pool` is overridden, with a real pool, so every POST
  runs through the real `AfterCommitJobQueue` and `get_db_session`'s after-commit hook
  (ADR-0035 decision 5).

Every job a test enqueues is removed from the shared Redis queue at teardown, as the webhook
route tests do, so a later burst worker never takes a job whose row was wiped.
"""

from datetime import UTC, datetime
from typing import Any

import httpx2
import pytest
import pytest_asyncio
from arq.connections import RedisSettings, create_pool
from arq.constants import default_queue_name, job_key_prefix
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from verion.modules.identity.adapters.outbound.db.repository import (
    PostgresGitHubConnectionRepository,
)
from verion.modules.identity.adapters.outbound.security.jwt_issuer import JwtAccessTokenIssuer
from verion.modules.identity.domain.github_connection import GitHubConnection
from verion.modules.projects.adapters.outbound.db.repository import (
    PostgresConnectedRepoRepository,
    PostgresProjectMembershipRepository,
    PostgresProjectRepository,
    PostgresScannerConfigRepository,
)
from verion.modules.projects.domain.project import ConnectedRepo, Project, ProjectMembership, Role
from verion.modules.projects.domain.scanner_config import ScannerConfig
from verion.modules.scanning.adapters.outbound.db.models import ScanModel
from verion.modules.scanning.adapters.outbound.scanners.semgrep_adapter import SemgrepAdapter
from verion.modules.scanning.adapters.outbound.vcs.git_repo_checkout import GitRepoCheckout
from verion.modules.scanning.domain.exceptions import RepoCheckoutFailed
from verion.platform.app import app
from verion.platform.clock import SystemClock
from verion.platform.di import get_arq_pool
from verion.platform.settings import get_settings
from verion.platform.worker import run_scan
from verion.shared_kernel.scanner_tools import ScannerTool

_PROJECT = "project-scans"
_OTHER_PROJECT = "project-scans-other"
_ABSENT = "project-scans-absent"
_OWNER = "user-owner"
_MEMBER = "user-member"
_STRANGER = "user-stranger"
_AT = datetime(2026, 1, 1, tzinfo=UTC)

_ACCEPTED_KEYS = {"id", "status"}
_SCAN_KEYS = {"id", "status", "failure_reason"}


def _auth(user_id: str) -> dict[str, str]:
    settings = get_settings()
    issuer = JwtAccessTokenIssuer(
        secret_key=settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
        expires_minutes=settings.jwt_expires_minutes,
        clock=SystemClock(),
    )
    return {"Authorization": f"Bearer {issuer.issue(subject=user_id).value}"}


@pytest_asyncio.fixture(autouse=True)
async def _clear_dependency_overrides():
    yield
    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def client():
    transport = httpx2.ASGITransport(app=app)
    async with httpx2.AsyncClient(transport=transport, base_url="http://test") as async_client:
        yield async_client


class _SpyPool:
    """The real arq pool, plus a look at the database at the moment of each enqueue.

    `enqueue_job` opens a SECOND session on the test engine and records whether the scan row
    it is about to queue is visible there, then delegates. That is the observation the
    commit-ordering test needs: it happens at the enqueue itself rather than after a timed
    wait, so an enqueue inside the transaction sees nothing every time.
    """

    def __init__(self, pool: Any, engine: AsyncEngine) -> None:
        self._pool = pool
        self._engine = engine
        self.visible_at_enqueue: dict[str, bool] = {}

    async def enqueue_job(self, function: str, *args: Any, **kwargs: Any) -> Any:
        scan_id = kwargs["_job_id"]
        async with AsyncSession(self._engine) as second:
            row = await second.execute(select(ScanModel.id).where(ScanModel.id == scan_id))
            self.visible_at_enqueue[scan_id] = row.first() is not None
        return await self._pool.enqueue_job(function, *args, **kwargs)


@pytest_asyncio.fixture
async def queue(engine: AsyncEngine):
    """A real pool behind `get_arq_pool`, wrapped by `_SpyPool`; cleans its jobs up."""
    pool = await create_pool(RedisSettings.from_dsn(get_settings().redis_url))
    spy = _SpyPool(pool, engine)
    app.dependency_overrides[get_arq_pool] = lambda: spy
    yield spy
    for scan_id in spy.visible_at_enqueue:
        await pool.delete(job_key_prefix + scan_id)
        await pool.zrem(default_queue_name, scan_id)
    await pool.aclose()


async def _seed_project(db_session, project_id: str = _PROJECT) -> None:
    """An owner and a plain MEMBER. No producer in `src/` writes a MEMBER (G75), so the row
    is written directly: it is the case the authorization mutation lives in."""
    await PostgresProjectRepository(db_session).add(
        Project(id=project_id, owner_id=_OWNER, name=f"Project {project_id}", created_at=_AT)
    )
    memberships = PostgresProjectMembershipRepository(db_session)
    await memberships.add(ProjectMembership(project_id=project_id, user_id=_OWNER, role=Role.OWNER))
    await memberships.add(
        ProjectMembership(project_id=project_id, user_id=_MEMBER, role=Role.MEMBER)
    )
    await db_session.commit()


async def _scan_count(db_session) -> int:
    return (await db_session.execute(select(func.count()).select_from(ScanModel))).scalar_one()


async def _queue_length(queue: _SpyPool) -> int:
    return int(await queue._pool.zcard(default_queue_name))


def _post(client, project_id: str, user: str):
    return client.post(f"/projects/{project_id}/scans", headers=_auth(user))


def _get(client, project_id: str, scan_id: str, user: str):
    return client.get(f"/projects/{project_id}/scans/{scan_id}", headers=_auth(user))


# ---------------------------------------------------------------------------
# POST — ADR-0035 decisions 1 and 2
# ---------------------------------------------------------------------------


async def test_an_unauthenticated_request_is_rejected(client, db_session, queue):
    await _seed_project(db_session)

    response = await client.post(f"/projects/{_PROJECT}/scans")

    assert response.status_code == 401


async def test_an_owner_starts_a_scan_and_gets_202_with_its_id_and_status(
    client, db_session, queue
):
    """Kills a widened response schema (the key set is equal, not a superset) and a wrong
    status code."""
    await _seed_project(db_session)

    response = await _post(client, _PROJECT, _OWNER)

    assert response.status_code == 202
    body = response.json()
    assert body.keys() == _ACCEPTED_KEYS
    assert body["status"] == "pending"
    row = (
        await db_session.execute(select(ScanModel).where(ScanModel.id == body["id"]))
    ).scalar_one()
    assert row.project_id == _PROJECT
    assert row.triggered_by == _OWNER
    assert await queue._pool.zscore(default_queue_name, body["id"]) is not None


async def test_a_member_who_is_not_an_owner_gets_404_and_no_scan(client, db_session, queue):
    """**The authorization mutation**: a non-owner member must not get 202.

    Killed if `StartScanUseCase` asks `may_read_project`, if `may_manage` degrades to
    "a membership exists", or if the route bypasses the use case.
    """
    await _seed_project(db_session)
    queued_before = await _queue_length(queue)

    response = await _post(client, _PROJECT, _MEMBER)

    assert response.status_code == 404
    assert await _scan_count(db_session) == 0
    assert await _queue_length(queue) == queued_before


async def test_absent_project_non_member_and_non_owner_are_indistinguishable(
    client, db_session, queue
):
    """Status AND body, across all three denials, and nothing written or queued after them.

    The message echoes the caller's own path id, on the findings routes' precedent, so each
    body is compared against one template filled with that request's path id. Kills a 403
    mapping and any message that varies by reason.
    """
    await _seed_project(db_session)
    queued_before = await _queue_length(queue)

    denials = {
        "absent project": (_ABSENT, await _post(client, _ABSENT, _OWNER)),
        "non-member": (_PROJECT, await _post(client, _PROJECT, _STRANGER)),
        "non-owner member": (_PROJECT, await _post(client, _PROJECT, _MEMBER)),
    }

    for label, (path_id, response) in denials.items():
        assert response.status_code == 404, label
        assert response.json() == {"detail": f"No project with id '{path_id}' that you may scan"}, (
            label
        )
    assert await _scan_count(db_session) == 0
    assert await _queue_length(queue) == queued_before


async def test_the_job_is_enqueued_only_after_the_scan_row_is_committed(client, db_session, queue):
    """ADR-0035 decision 5. At the moment the job is sent, a SECOND session must already see
    the scan row: only a committed row is visible to another connection.

    Kills `get_job_queue` returning a bare `ArqJobQueue`, which enqueues inside
    `TriggerScanUseCase`, before `get_db_session` commits: the second session then sees
    nothing, every time.
    """
    await _seed_project(db_session)

    response = await _post(client, _PROJECT, _OWNER)

    scan_id = response.json()["id"]
    assert queue.visible_at_enqueue == {scan_id: True}


# ---------------------------------------------------------------------------
# GET — ADR-0035 decision 4
# ---------------------------------------------------------------------------


async def test_an_owner_reads_the_scan_it_started(client, db_session, queue):
    """Straight after the 202, which since ADR-0008's M8.8 amendment means committed. Kills
    a widened response schema."""
    await _seed_project(db_session)
    scan_id = (await _post(client, _PROJECT, _OWNER)).json()["id"]

    response = await _get(client, _PROJECT, scan_id, _OWNER)

    assert response.status_code == 200
    assert response.json() == {"id": scan_id, "status": "pending", "failure_reason": None}
    assert response.json().keys() == _SCAN_KEYS


async def test_a_plain_member_reads_a_scan(client, db_session, queue):
    """A member who may not start a scan may watch one. Kills the GET using the manage
    verdict."""
    await _seed_project(db_session)
    scan_id = (await _post(client, _PROJECT, _OWNER)).json()["id"]

    response = await _get(client, _PROJECT, scan_id, _MEMBER)

    assert response.status_code == 200


async def test_non_member_and_absent_project_are_indistinguishable_on_read(
    client, db_session, queue
):
    await _seed_project(db_session)
    scan_id = (await _post(client, _PROJECT, _OWNER)).json()["id"]

    forbidden = await _get(client, _PROJECT, scan_id, _STRANGER)
    absent = await _get(client, _ABSENT, scan_id, _OWNER)

    assert forbidden.status_code == absent.status_code == 404
    assert forbidden.json() == {"detail": f"No readable project with id '{_PROJECT}'"}
    assert absent.json() == {"detail": f"No readable project with id '{_ABSENT}'"}


async def test_a_scan_of_another_project_is_404_like_an_absent_scan(client, db_session, queue):
    """The owner of both projects asks for project 2's scan through project 1's path. Kills
    a deleted project-match check, which would answer 200 with the other project's scan."""
    await _seed_project(db_session)
    await _seed_project(db_session, project_id=_OTHER_PROJECT)
    other_scan = (await _post(client, _OTHER_PROJECT, _OWNER)).json()["id"]

    foreign = await _get(client, _PROJECT, other_scan, _OWNER)
    absent = await _get(client, _PROJECT, "scan-that-does-not-exist", _OWNER)

    assert foreign.status_code == absent.status_code == 404
    assert foreign.json() == {"detail": f"No scan with id '{other_scan}' in project '{_PROJECT}'"}
    assert absent.json() == {
        "detail": f"No scan with id 'scan-that-does-not-exist' in project '{_PROJECT}'"
    }


async def test_failure_reason_carries_neither_the_token_nor_the_checkout_path(
    client, db_session, queue
):
    """Rule 12, at the route that returns `failure_reason` (ADR-0035 decision 4).

    A real failed clone, through the real worker job: the project's connected repository
    does not exist, the owner's GitHub token is a known secret, and `run_scan` runs the
    checkout and commits the FAILED scan. The GET must then carry neither the token nor the
    `verion-scan-` checkout path that git's stderr opens with.

    **This covers those two named patterns and nothing else.** `failure_reason` is redacted
    by a deny-list, and anything else git prints passes through it: **G89**.

    **What it kills, measured:** removing the checkout-directory redaction. It does NOT kill
    removing the token redaction, and cannot: the token reaches git through the environment,
    never argv, and GitHub's "not found" stderr never echoes it, so the token assertion holds
    whatever `_redact` does. That redaction is defence in depth, and its kill is
    `test_git_repo_checkout.py::test_redact_scrubs_a_token_out_of_captured_output`. The token
    assertion stays here as the end-to-end regression check rule 12 asks for at this sink.
    """
    secret_token = "super-secret-token-m88"
    await _seed_project(db_session)
    await PostgresConnectedRepoRepository(db_session).upsert(
        ConnectedRepo(
            id="repo-scans",
            project_id=_PROJECT,
            provider="github",
            url="https://github.com/octocat/this-repo-does-not-exist-verion-test",
            default_branch="main",
        )
    )
    await PostgresGitHubConnectionRepository(db_session).add(
        GitHubConnection(
            user_id=_OWNER,
            access_token=secret_token,
            github_username="octocat",
            connected_at=_AT,
        )
    )
    # Semgrep only, so no Trivy adapter is needed in the worker context below.
    await PostgresScannerConfigRepository(db_session).upsert(
        ScannerConfig(
            id="config-scans",
            project_id=_PROJECT,
            enabled_tools=(ScannerTool.SEMGREP,),
            zap_target_url=None,
            updated_at=_AT,
        )
    )
    await db_session.commit()
    scan_id = (await _post(client, _PROJECT, _OWNER)).json()["id"]

    worker_ctx = {
        # Never reached: the checkout fails first. The registry needs a real entry.
        "scanners": {ScannerTool.SEMGREP: SemgrepAdapter(config=get_settings().semgrep_ruleset)},
        "repo_checkout": GitRepoCheckout(),
    }
    with pytest.raises(RepoCheckoutFailed):
        await run_scan(worker_ctx, scan_id)

    response = await _get(client, _PROJECT, scan_id, _MEMBER)

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "failed"
    assert body["failure_reason"] is not None
    assert "git clone of" in body["failure_reason"]
    assert secret_token not in response.text
    assert "verion-scan-" not in response.text
