"""G27's acceptance, end to end (M5.6 commit 4): detect → store → correlate → gate.

Everything is real except GitHub: Postgres, the migrations, the routers, `platform/di.py`'s
wiring — `get_route_map_port` is NOT overridden, so correlation reads the map through
`PostgresRouteMapReader` — and `GitHubAdapter` itself, including its tarball parser.
Only `get_vcs_provider` is overridden, to give that real adapter a `MockTransport`.

**What this module proves: the PIPELINE.** A context build fetches the archive, extracts
routes, and stores them. A Risk listing then reads the stored map and derives a route path
for the Semgrep finding. The derivation happens only while the serving declaration is in
force.

**What it does NOT prove: that GitHub serves what we think it serves.** The transport serves
the committed capture in `fixtures/github_tarball/`, so this module takes the archive's format
as given. That claim belongs to `test_github_adapter.py`'s real-capture tests alone, per that
fixture's README. Calling this module "end to end" without this paragraph would quietly make
it the fetch contract too, and undo the README's division of labour one file away.

The `requirements.txt` the use case detects the framework from is the capture's own, served
through the contents API. So the framework key and the archive are one tree here, as they are
for the real demo target at `c68caa7`. In production they are two separate reads of the tip
(**G56**).
"""

import base64
import io
import tarfile
import zlib
from datetime import UTC, datetime
from pathlib import Path

import httpx2
import pytest
import pytest_asyncio

from verion.modules.identity.adapters.outbound.db.repository import (
    PostgresGitHubConnectionRepository,
)
from verion.modules.identity.adapters.outbound.security.jwt_issuer import JwtAccessTokenIssuer
from verion.modules.identity.domain.github_connection import GitHubConnection
from verion.modules.normalization.adapters.outbound.db.repository import PostgresFindingRepository
from verion.modules.normalization.domain.finding import Evidence, Finding, Location
from verion.modules.projects.adapters.outbound.db.repository import (
    PostgresConnectedRepoRepository,
    PostgresRouteMapRepository,
    PostgresScannerConfigRepository,
    PostgresServingDeclarationRepository,
)
from verion.modules.projects.adapters.outbound.vcs.github_adapter import GitHubAdapter
from verion.modules.projects.domain.project import ConnectedRepo
from verion.modules.projects.domain.route_extraction import RouteMap, UnreadTree
from verion.modules.projects.domain.scanner_config import ScannerConfig
from verion.modules.projects.domain.serving_declaration import ServingDeclaration
from verion.platform.app import app
from verion.platform.clock import SystemClock
from verion.platform.di import get_vcs_provider
from verion.platform.settings import get_settings
from verion.shared_kernel.scanner_tools import ScannerTool
from verion.shared_kernel.severity import Severity

_CAPTURE = (
    Path(__file__).parent / "fixtures" / "github_tarball" / "verion-demo-target-c68caa7.tar.gz"
).read_bytes()
_CAPTURE_SHA = "c68caa7aba8db8ae64da6dd2b4e1b8a05ecd1850"
_OWNER = "owner-1"
_REPO_URL = "https://github.com/CarlosPD8/verion-demo-target"
_TARGET = "http://target.example:8080/"
_AT = datetime(2026, 1, 1, tzinfo=UTC)
_API_REPO = "/repos/CarlosPD8/verion-demo-target"
_CODELOAD_URL = "https://codeload.github.com/CarlosPD8/verion-demo-target/legacy.tar.gz/HEAD"


def _capture_blobs() -> dict[str, bytes]:
    """The capture's regular files, repo-relative, to serve the trees and contents APIs from.

    Read here with `tarfile` so the manifest the use case detects on and the archive it then
    fetches are one tree, as they are for the real demo target at `c68caa7`.
    """
    raw = zlib.decompress(_CAPTURE, 31)
    blobs: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        top = archive.getmembers()[0].name
        for member in archive.getmembers():
            extracted = archive.extractfile(member) if member.isreg() else None
            if extracted is not None:
                blobs[member.name.removeprefix(f"{top}/")] = extracted.read()
    return blobs


_BLOBS = _capture_blobs()


class _ChunkedBody(httpx2.AsyncByteStream):
    """Chunked like codeload's body. Duplicated from `test_github_adapter.py` on purpose:
    `tests/` is not a package, so module-local helpers are this suite's convention."""

    def __init__(self, body: bytes) -> None:
        self._body = body

    async def __aiter__(self):
        for start in range(0, len(self._body), 64 * 1024):
            yield self._body[start : start + 64 * 1024]


def _github(*, codeload_status: int = 200) -> GitHubAdapter:
    def handler(request: httpx2.Request) -> httpx2.Response:
        if request.url.host == "codeload.github.com":
            return httpx2.Response(codeload_status, stream=_ChunkedBody(_CAPTURE))
        path = request.url.path
        if path == f"{_API_REPO}/git/trees/HEAD":
            return httpx2.Response(
                200, json={"tree": [{"path": blob, "type": "blob"} for blob in _BLOBS]}
            )
        if path.startswith(f"{_API_REPO}/contents/"):
            content = _BLOBS.get(path.removeprefix(f"{_API_REPO}/contents/"))
            if content is None:
                return httpx2.Response(404, json={"message": "Not Found"})
            return httpx2.Response(200, json={"content": base64.b64encode(content).decode()})
        if path == f"{_API_REPO}/tarball/HEAD":
            return httpx2.Response(302, headers={"Location": _CODELOAD_URL})
        return httpx2.Response(500, json={"message": f"unexpected fixture request {path}"})

    return GitHubAdapter(transport=httpx2.MockTransport(handler))


def _auth_headers(user_id: str) -> dict[str, str]:
    settings = get_settings()
    issuer = JwtAccessTokenIssuer(
        secret_key=settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
        expires_minutes=settings.jwt_expires_minutes,
        clock=SystemClock(),
    )
    return {"Authorization": f"Bearer {issuer.issue(subject=user_id).value}"}


@pytest.fixture(autouse=True)
def _clear_dependency_overrides():
    yield
    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def client():
    transport = httpx2.ASGITransport(app=app)
    async with httpx2.AsyncClient(transport=transport, base_url="http://test") as async_client:
        yield async_client


async def _declared_project(client, db_session) -> str:
    """A project whose serving declaration is IN FORCE against real rows, before any detect."""
    await PostgresGitHubConnectionRepository(db_session).add(
        GitHubConnection(
            user_id=_OWNER,
            access_token="gho_storedtoken",
            github_username="octocat",
            connected_at=_AT,
        )
    )
    await db_session.commit()
    created = await client.post("/projects/", json={"name": "Demo"}, headers=_auth_headers(_OWNER))
    project_id = created.json()["id"]

    await PostgresConnectedRepoRepository(db_session).add(
        ConnectedRepo(
            id="repo-1",
            project_id=project_id,
            provider="github",
            url=_REPO_URL,
            default_branch="main",
        )
    )
    await _configure_target(db_session, project_id, _TARGET)
    await PostgresServingDeclarationRepository(db_session).upsert(
        ServingDeclaration(
            id="declaration-1",
            project_id=project_id,
            declared_target_url=_TARGET,
            declared_repo_url=_REPO_URL,
            declared_default_branch="main",
            declared_at=_AT,
            declared_by=_OWNER,
        )
    )
    await db_session.commit()
    return project_id


async def _configure_target(db_session, project_id: str, target: str) -> None:
    await PostgresScannerConfigRepository(db_session).upsert(
        ScannerConfig(
            id="config-1",
            project_id=project_id,
            enabled_tools=(ScannerTool.SEMGREP, ScannerTool.ZAP),
            zap_target_url=target,
            updated_at=_AT,
        )
    )
    await db_session.commit()


async def _seed_the_sink_findings(db_session, project_id: str) -> None:
    """Semgrep's `eval` at `app.py:28`, and ZAP's alert at `/calculate`, as the corpora have them.

    Line 28 is the real capture's `result = eval(expr)`, inside `calculate`'s span (14–31).
    """
    for finding_id, source, location in (
        ("sast", ScannerTool.SEMGREP, Location(file_path="app.py", start_line=28, end_line=28)),
        ("dast", ScannerTool.ZAP, Location(url="http://target.example:8080/calculate?expr=2*3")),
    ):
        await PostgresFindingRepository(db_session).upsert(
            Finding(
                id=finding_id,
                project_id=project_id,
                source=source,
                rule_id=f"rule-{finding_id}",
                severity=Severity.HIGH,
                native_severity="HIGH",
                title=f"title {finding_id}",
                location=location,
                evidence=Evidence(
                    id=f"evidence-{finding_id}",
                    finding_id=finding_id,
                    scan_id="scan-1",
                    raw_payload="{}",
                    source_tool=source,
                    captured_at=_AT,
                ),
            )
        )
    await db_session.commit()


async def _groups(client, project_id: str) -> dict[tuple[str, ...], dict[str, str | None]]:
    response = await client.get(f"/projects/{project_id}/risks", headers=_auth_headers(_OWNER))
    assert response.status_code == 200
    return {tuple(sorted(item["finding_ids"])): item["match"] for item in response.json()["items"]}


async def test_a_built_context_produces_the_cross_tool_group_while_the_declaration_is_in_force(
    client, db_session
):
    """**G27's positive half.** The first derived SAST↔DAST group production can produce."""
    app.dependency_overrides[get_vcs_provider] = lambda: _github()
    project_id = await _declared_project(client, db_session)

    detected = await client.post(
        f"/projects/{project_id}/security-context/detect", headers=_auth_headers(_OWNER)
    )
    await _seed_the_sink_findings(db_session, project_id)

    assert detected.status_code == 201
    assert detected.json()["framework"] == "flask"
    assert await _groups(client, project_id) == {
        ("dast", "sast"): {"package": None, "url": "/calculate"}
    }
    # Carried through storage, not re-derived: the commit the map's archive was cut from.
    record = await PostgresRouteMapRepository(db_session).get_by_project_id(project_id)
    assert record is not None
    assert record.source_archive_commit_sha == _CAPTURE_SHA


async def test_the_same_built_map_produces_no_group_once_the_declaration_is_out_of_force(
    client, db_session
):
    """**G27's negative half.** The identical pipeline, with the declaration voided by
    repointing the target after declaring (ADR-0028 decision 2's reconfiguration).

    The map is asserted populated, so the missing group is the gate's doing and not an empty
    map's — without that assertion this test would pass if detect had stored nothing.
    """
    app.dependency_overrides[get_vcs_provider] = lambda: _github()
    project_id = await _declared_project(client, db_session)
    detected = await client.post(
        f"/projects/{project_id}/security-context/detect", headers=_auth_headers(_OWNER)
    )
    await _seed_the_sink_findings(db_session, project_id)

    await _configure_target(db_session, project_id, "http://elsewhere.example:8080/")

    assert detected.status_code == 201
    record = await PostgresRouteMapRepository(db_session).get_by_project_id(project_id)
    assert record is not None
    assert [route.path for route in record.route_map.routes] == ["/", "/calculate"]
    assert await _groups(client, project_id) == {
        ("dast",): {"package": None, "url": "/calculate"},
        ("sast",): {"package": None, "url": None},
    }


async def test_a_failed_archive_download_is_stored_as_such_and_derives_nothing(client, db_session):
    """The failure is distinguishable from "no routes", and the context build still succeeds.

    **Effectively permanent for this project** — re-running detect would duplicate its
    `security_contexts` row (G55) — which is why this test does not retry.
    """
    app.dependency_overrides[get_vcs_provider] = lambda: _github(codeload_status=500)
    project_id = await _declared_project(client, db_session)

    detected = await client.post(
        f"/projects/{project_id}/security-context/detect", headers=_auth_headers(_OWNER)
    )
    await _seed_the_sink_findings(db_session, project_id)

    assert detected.status_code == 201
    record = await PostgresRouteMapRepository(db_session).get_by_project_id(project_id)
    assert record is not None
    assert record.route_map == RouteMap.not_read(UnreadTree.FETCH_FAILED)
    assert record.source_archive_commit_sha is None
    assert await _groups(client, project_id) == {
        ("dast",): {"package": None, "url": "/calculate"},
        ("sast",): {"package": None, "url": None},
    }
