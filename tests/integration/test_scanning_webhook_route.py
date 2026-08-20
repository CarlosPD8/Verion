import hashlib
import hmac
import json
from datetime import UTC, datetime

import httpx2
import pytest_asyncio
from arq.connections import RedisSettings, create_pool
from arq.constants import default_queue_name, job_key_prefix
from sqlalchemy import func, select

from verion.modules.projects.adapters.outbound.db.repository import (
    PostgresConnectedRepoRepository,
    PostgresProjectRepository,
)
from verion.modules.projects.domain.project import ConnectedRepo, Project
from verion.modules.scanning.adapters.outbound.db.models import ScanModel
from verion.modules.scanning.adapters.outbound.queue.arq_job_queue import ArqJobQueue
from verion.platform.app import app
from verion.platform.di import get_handle_github_webhook_use_case, get_job_queue
from verion.platform.settings import get_settings

_WEBHOOK_PATH = "/scanning/webhooks/github"


def _sign(payload: bytes, secret: str) -> str:
    digest = hmac.new(secret.encode("utf-8"), msg=payload, digestmod=hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def _push_payload(owner: str, repo: str) -> bytes:
    return json.dumps(
        {"ref": "refs/heads/main", "repository": {"name": repo, "owner": {"login": owner}}}
    ).encode("utf-8")


def _signed_headers(payload: bytes, delivery_id: str, event: str = "push") -> dict[str, str]:
    return {
        "X-Hub-Signature-256": _sign(payload, get_settings().github_webhook_secret),
        "X-GitHub-Delivery": delivery_id,
        "X-GitHub-Event": event,
        "Content-Type": "application/json",
    }


class _SpyHandleGitHubWebhookUseCase:
    def __init__(self) -> None:
        self.execute_calls = 0

    async def execute(self, delivery_id: str, event_type: str, payload: dict):
        self.execute_calls += 1
        return None


@pytest_asyncio.fixture(autouse=True)
async def _clear_dependency_overrides():
    yield
    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def client():
    transport = httpx2.ASGITransport(app=app)
    async with httpx2.AsyncClient(transport=transport, base_url="http://test") as async_client:
        yield async_client


@pytest_asyncio.fixture
async def real_job_queue():
    # ASGITransport never runs the app's lifespan (it only ever sends an
    # "http" ASGI scope — no "lifespan" scope), so app.state.arq_redis is
    # never populated under TestClient/AsyncClient. Constructing a real pool
    # directly and overriding get_job_queue with it keeps this test's Redis
    # interaction genuinely real without needing lifespan machinery in
    # tests — the lifespan wiring itself is covered separately (see
    # test_app_lifespan.py).
    pool = await create_pool(RedisSettings.from_dsn(get_settings().redis_url))
    app.dependency_overrides[get_job_queue] = lambda: ArqJobQueue(pool)
    yield pool
    await pool.aclose()


async def _seed_connected_project(
    db_session, owner: str, repo: str, project_id: str, owner_id: str
) -> None:
    await PostgresProjectRepository(db_session).add(
        Project(id=project_id, owner_id=owner_id, name="Verion", created_at=datetime.now(UTC))
    )
    await PostgresConnectedRepoRepository(db_session).add(
        ConnectedRepo(
            id=f"{project_id}-repo",
            project_id=project_id,
            provider="github",
            url=f"https://github.com/{owner}/{repo}",
            default_branch="main",
        )
    )
    await db_session.commit()


async def _scan_count(db_session) -> int:
    result = await db_session.execute(select(func.count()).select_from(ScanModel))
    return result.scalar_one()


async def test_invalid_signature_returns_401_and_never_calls_the_use_case(client, db_session):
    spy = _SpyHandleGitHubWebhookUseCase()
    app.dependency_overrides[get_handle_github_webhook_use_case] = lambda: spy
    payload = _push_payload("octocat", "Hello-World")

    response = await client.post(
        _WEBHOOK_PATH,
        content=payload,
        headers={
            "X-Hub-Signature-256": "sha256=" + "0" * 64,
            "X-GitHub-Delivery": "delivery-invalid",
            "X-GitHub-Event": "push",
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 401
    assert spy.execute_calls == 0
    assert await _scan_count(db_session) == 0


async def test_the_webhook_secret_never_appears_in_the_401_response_body(client, real_job_queue):
    # Rule 12: no credential/secret field may appear in a response body
    # beyond what's explicitly designed to expose it. verify_signature only
    # ever returns a bool, and the 401 handler only ever raises a static
    # detail string — this proves that end to end through the real route,
    # not just by inspecting the source. real_job_queue is required even
    # though this path 401s before the use case runs — see the comment on
    # test_unconnected_repo_returns_404_and_creates_no_scan for why.
    payload = _push_payload("octocat", "Hello-World")

    response = await client.post(
        _WEBHOOK_PATH,
        content=payload,
        headers={
            "X-Hub-Signature-256": "sha256=" + "0" * 64,
            "X-GitHub-Delivery": "delivery-invalid",
            "X-GitHub-Event": "push",
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 401
    assert get_settings().github_webhook_secret not in response.text


async def test_missing_signature_header_returns_401_and_never_calls_the_use_case(
    client, db_session
):
    spy = _SpyHandleGitHubWebhookUseCase()
    app.dependency_overrides[get_handle_github_webhook_use_case] = lambda: spy
    payload = _push_payload("octocat", "Hello-World")

    response = await client.post(
        _WEBHOOK_PATH,
        content=payload,
        headers={
            "X-GitHub-Delivery": "delivery-invalid",
            "X-GitHub-Event": "push",
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 401
    assert spy.execute_calls == 0


async def test_valid_signature_for_a_connected_repo_triggers_a_real_scan_end_to_end(
    client, db_session, real_job_queue
):
    await _seed_connected_project(db_session, "octocat", "verion-demo", "project-e2e", "owner-1")
    payload = _push_payload("octocat", "verion-demo")

    response = await client.post(
        _WEBHOOK_PATH, content=payload, headers=_signed_headers(payload, "delivery-e2e-1")
    )

    assert response.status_code == 202
    assert get_settings().github_webhook_secret not in response.text
    assert await _scan_count(db_session) == 1
    scan = (await db_session.execute(select(ScanModel))).scalar_one()
    assert scan.project_id == "project-e2e"
    assert scan.triggered_by == "owner-1"
    assert await real_job_queue.zscore(default_queue_name, scan.id) is not None
    await real_job_queue.delete(job_key_prefix + scan.id)
    await real_job_queue.zrem(default_queue_name, scan.id)


async def test_a_redelivered_delivery_id_does_not_trigger_a_second_scan(
    client, db_session, real_job_queue
):
    await _seed_connected_project(db_session, "octocat", "verion-demo", "project-e2e", "owner-1")
    payload = _push_payload("octocat", "verion-demo")
    headers = _signed_headers(payload, "delivery-e2e-redelivered")
    first = await client.post(_WEBHOOK_PATH, content=payload, headers=headers)
    assert first.status_code == 202

    second = await client.post(_WEBHOOK_PATH, content=payload, headers=headers)

    assert second.status_code == 200
    assert await _scan_count(db_session) == 1
    scan = (await db_session.execute(select(ScanModel))).scalar_one()
    # Cleanup: this test's own DB rows are wiped by conftest's autouse
    # _clean_all_tables, but the arq job landed in the *shared* Redis queue,
    # which isn't per-test-isolated — an un-cleaned job here would later be
    # picked up by an unrelated worker test against a scan_id whose row no
    # longer exists, same cleanup discipline as the enqueue test above and
    # test_arq_job_queue.py's own finally block.
    await real_job_queue.delete(job_key_prefix + scan.id)
    await real_job_queue.zrem(default_queue_name, scan.id)


async def test_unconnected_repo_returns_404_and_creates_no_scan(client, db_session, real_job_queue):
    # real_job_queue is required here even though this path never reaches
    # TriggerScanUseCase: FastAPI resolves the full HandleGitHubWebhookUseCase
    # dependency tree (including JobQueueDep) at request-dispatch time,
    # before the handler body ever runs — not lazily, only if that code
    # path is taken.
    payload = _push_payload("octocat", "not-connected-anywhere")

    response = await client.post(
        _WEBHOOK_PATH,
        content=payload,
        headers=_signed_headers(payload, "delivery-unconnected"),
    )

    assert response.status_code == 404
    assert await _scan_count(db_session) == 0
