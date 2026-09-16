"""Seed one demo project for the frontend by REPLAYING a committed real scan.

The screen in `frontend/` needs a project that has been scanned, normalized and correlated.
A live scan is not reachable from a laptop: scans are triggered only by the GitHub webhook,
there is no GitHub token for a local run, and the worker's ZAP wiring rejects a local target
at the SSRF gate (ADR-0013). So this script replays one.

**What is real:**

- the scanner output — the committed capture of `verion-demo-target` at `c68caa7`, three
  tools from one Scan and one checkout (`tests/fixtures/scanners/README.md`);
- the project and security-context detect routes, called through the ASGI app;
- `GitHubAdapter` and its tarball parser, and route extraction;
- `RunScanUseCase`, `NormalizeScanUseCase`, and correlation and scoring at read time;
- every repository, against the database `Settings.database_url` points at.

**What is replaced:** GitHub (served from the committed tarball in
`tests/integration/fixtures/github_tarball/`, exactly as
`tests/integration/test_derived_group_end_to_end.py` serves it), the git checkout, and the
scanner subprocesses, whose committed output is replayed. The ZAP target host is the capture's
redacted `target.example`.

**G19 does not bite here, and that is by construction.** A generator invents values and has
to guess production's shape; this script invents no finding value at all. Every finding comes
from real scanner output through the real normalization code.

Demo credentials, created on the first run and reused after it:

    email:    demo@verion.example
    password: verion-demo-password

Each run creates a NEW project and prints its id — there is no route that lists a user's
projects, so that id is what the frontend's sign-in form needs.

**Integration tests delete these rows.** `tests/integration/conftest.py`'s autouse
`_clean_all_tables` empties every table after each integration test, and the test engine uses
the same `Settings.database_url`. Re-run this script after `uv run pytest`.

Usage (Postgres up and migrated; Redis and the API server are not needed):

    uv run python scripts/seed_demo_project.py
"""

from __future__ import annotations

import asyncio
import base64
import io
import tarfile
import zlib
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import httpx2

from verion.modules.identity.adapters.outbound.db.repository import (
    PostgresGitHubConnectionRepository,
)
from verion.modules.identity.domain.github_connection import GitHubConnection
from verion.modules.normalization.adapters.outbound.db.repository import (
    PostgresFindingRepository,
    PostgresNormalizationRunRepository,
)
from verion.modules.normalization.application.normalize_scan import NormalizeScanUseCase
from verion.modules.projects.adapters.outbound.db.repository import (
    PostgresConnectedRepoRepository,
    PostgresScannerConfigRepository,
    PostgresServingDeclarationRepository,
)
from verion.modules.projects.adapters.outbound.vcs.github_adapter import GitHubAdapter
from verion.modules.projects.domain.project import ConnectedRepo
from verion.modules.projects.domain.scanner_config import ScannerConfig
from verion.modules.projects.domain.serving_declaration import ServingDeclaration
from verion.modules.scanning.adapters.outbound.db.repository import (
    PostgresScanRepository,
    PostgresScanResultRepository,
)
from verion.modules.scanning.application.run_scan import RunScanUseCase
from verion.modules.scanning.domain.raw_scan_result import RawScanResult
from verion.modules.scanning.domain.scan import Scan, ScanStatus
from verion.modules.scanning.domain.scan_options import ScanOptions
from verion.modules.scanning.domain.scanner_target_kind import ScannerTargetKind
from verion.platform.app import app
from verion.platform.clock import SystemClock
from verion.platform.db import session_factory
from verion.platform.di import get_vcs_provider
from verion.platform.id_generator import UuidIdGenerator
from verion.shared_kernel.scanner_tools import ScannerTool

DEMO_EMAIL = "demo@verion.example"
DEMO_PASSWORD = "verion-demo-password"

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SCANNER_CAPTURES = _REPO_ROOT / "tests" / "fixtures" / "scanners"
_TARBALL = (
    _REPO_ROOT / "tests/integration/fixtures/github_tarball/verion-demo-target-c68caa7.tar.gz"
).read_bytes()
_REPO_URL = "https://github.com/CarlosPD8/verion-demo-target"
_TARGET = "http://target.example:8080/"
_API_REPO = "/repos/CarlosPD8/verion-demo-target"
_CODELOAD_URL = "https://codeload.github.com/CarlosPD8/verion-demo-target/legacy.tar.gz/HEAD"


def _tarball_blobs() -> dict[str, bytes]:
    raw = zlib.decompress(_TARBALL, 31)
    blobs: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        top = archive.getmembers()[0].name
        for member in archive.getmembers():
            extracted = archive.extractfile(member) if member.isreg() else None
            if extracted is not None:
                blobs[member.name.removeprefix(f"{top}/")] = extracted.read()
    return blobs


class _ChunkedBody(httpx2.AsyncByteStream):
    def __init__(self, body: bytes) -> None:
        self._body = body

    async def __aiter__(self):
        for start in range(0, len(self._body), 64 * 1024):
            yield self._body[start : start + 64 * 1024]


def _replayed_github() -> GitHubAdapter:
    blobs = _tarball_blobs()

    def handler(request: httpx2.Request) -> httpx2.Response:
        if request.url.host == "codeload.github.com":
            return httpx2.Response(200, stream=_ChunkedBody(_TARBALL))
        path = request.url.path
        if path == f"{_API_REPO}/git/trees/HEAD":
            return httpx2.Response(
                200, json={"tree": [{"path": blob, "type": "blob"} for blob in blobs]}
            )
        if path.startswith(f"{_API_REPO}/contents/"):
            content = blobs.get(path.removeprefix(f"{_API_REPO}/contents/"))
            if content is None:
                return httpx2.Response(404, json={"message": "Not Found"})
            return httpx2.Response(200, json={"content": base64.b64encode(content).decode()})
        if path == f"{_API_REPO}/tarball/HEAD":
            return httpx2.Response(302, headers={"Location": _CODELOAD_URL})
        return httpx2.Response(500, json={"message": f"unexpected replay request {path}"})

    return GitHubAdapter(transport=httpx2.MockTransport(handler))


class _ReplayedScanner:
    """Returns a committed real capture instead of running the tool."""

    def __init__(self, tool: ScannerTool, target_kind: ScannerTargetKind, capture: str) -> None:
        self.tool = tool
        self.target_kind = target_kind
        self._raw_output = (_SCANNER_CAPTURES / capture).read_text(encoding="utf-8")

    async def run(self, target: str, options: ScanOptions) -> RawScanResult:
        return RawScanResult(tool=self.tool, raw_output=self._raw_output)


class _ReplayedCheckout:
    async def checkout(self, repo_url: str, access_token: str | None) -> str:
        return "/tmp/verion-demo-replay"

    async def cleanup(self, local_path: str) -> None:
        return None


async def _sign_in(client: httpx2.AsyncClient) -> tuple[str, dict[str, str]]:
    credentials = {"email": DEMO_EMAIL, "password": DEMO_PASSWORD}
    registered = await client.post("/auth/register", json=credentials)
    if registered.status_code not in (201, 409):
        raise SystemExit(f"register failed: {registered.status_code} {registered.text}")
    login = await client.post("/auth/login", json=credentials)
    if login.status_code != 200:
        raise SystemExit(f"login failed: {login.status_code} {login.text}")
    body = login.json()
    return body["user"]["id"], {"Authorization": f"Bearer {body['access_token']}"}


async def _declare_project(project_id: str, owner_id: str) -> None:
    """Connect the repository, configure the three tools and declare the target serves it.

    The declaration is what lets correlation derive `/calculate` for Semgrep's finding
    (ADR-0028, ADR-0029), so SAST and DAST land on one surface.
    """
    now = datetime.now(UTC)
    async with session_factory() as session:
        if await PostgresGitHubConnectionRepository(session).get_by_user_id(owner_id) is None:
            await PostgresGitHubConnectionRepository(session).add(
                GitHubConnection(
                    user_id=owner_id, access_token="", github_username="demo", connected_at=now
                )
            )
        await PostgresConnectedRepoRepository(session).add(
            ConnectedRepo(
                id=str(uuid4()),
                project_id=project_id,
                provider="github",
                url=_REPO_URL,
                default_branch="main",
            )
        )
        await PostgresScannerConfigRepository(session).upsert(
            ScannerConfig(
                id=str(uuid4()),
                project_id=project_id,
                enabled_tools=(ScannerTool.SEMGREP, ScannerTool.TRIVY, ScannerTool.ZAP),
                zap_target_url=_TARGET,
                updated_at=now,
            )
        )
        await PostgresServingDeclarationRepository(session).upsert(
            ServingDeclaration(
                id=str(uuid4()),
                project_id=project_id,
                declared_target_url=_TARGET,
                declared_repo_url=_REPO_URL,
                declared_default_branch="main",
                declared_at=now,
                declared_by=owner_id,
            )
        )
        await session.commit()


async def _replay_scan(project_id: str, owner_id: str) -> str:
    scan_id = str(uuid4())
    async with session_factory() as session:
        await PostgresScanRepository(session).add(
            Scan(
                id=scan_id,
                project_id=project_id,
                status=ScanStatus.PENDING,
                triggered_by=owner_id,
                started_at=None,
                finished_at=None,
                failure_reason=None,
            )
        )
        await session.commit()
        await RunScanUseCase(
            scans=PostgresScanRepository(session),
            scan_results=PostgresScanResultRepository(session),
            scanners={
                ScannerTool.SEMGREP: _ReplayedScanner(
                    ScannerTool.SEMGREP, ScannerTargetKind.REPO_PATH, "semgrep_scan.json"
                ),
                ScannerTool.TRIVY: _ReplayedScanner(
                    ScannerTool.TRIVY, ScannerTargetKind.REPO_PATH, "trivy_scan.json"
                ),
                ScannerTool.ZAP: _ReplayedScanner(
                    ScannerTool.ZAP, ScannerTargetKind.URL, "zap_scan.json"
                ),
            },
            repo_checkout=_ReplayedCheckout(),
            connected_repos=PostgresConnectedRepoRepository(session),
            github_connections=PostgresGitHubConnectionRepository(session),
            scanner_configs=PostgresScannerConfigRepository(session),
            normalization_runs=PostgresNormalizationRunRepository(session),
            id_generator=UuidIdGenerator(),
            clock=SystemClock(),
        ).execute(scan_id)
        await session.commit()

    async with session_factory() as session:
        runs = PostgresNormalizationRunRepository(session)
        run = await runs.claim(scan_id=scan_id, now=SystemClock().now())
        if run is None:
            raise SystemExit(f"no claimable normalization run for scan {scan_id}")
        await session.commit()
        await NormalizeScanUseCase(
            scan_results=PostgresScanResultRepository(session),
            findings=PostgresFindingRepository(session),
            normalization_runs=runs,
            id_generator=UuidIdGenerator(),
            clock=SystemClock(),
        ).execute(run)
        await session.commit()
    return scan_id


async def main() -> None:
    app.dependency_overrides[get_vcs_provider] = _replayed_github
    transport = httpx2.ASGITransport(app=app)
    async with httpx2.AsyncClient(transport=transport, base_url="http://seed") as client:
        owner_id, headers = await _sign_in(client)
        created = await client.post(
            "/projects/", json={"name": "verion-demo-target"}, headers=headers
        )
        project_id = created.json()["id"]
        await _declare_project(project_id, owner_id)

        detected = await client.post(
            f"/projects/{project_id}/security-context/detect", headers=headers
        )
        if detected.status_code != 201:
            raise SystemExit(f"detect failed: {detected.status_code} {detected.text}")

        await _replay_scan(project_id, owner_id)

        scored = await client.get(f"/projects/{project_id}/scored-risks?limit=200", headers=headers)
        data = scored.json()

    print(f"Seeded {data['total']} ranked Risks from the replayed capture:")
    for item in data["items"]:
        reasoning = item["reasoning"]
        terms = " + ".join(
            str(reasoning[name]["value"]) for name in ("severity", "exposure", "corroboration")
        )
        surface = item["match"]["package"] or item["match"]["url"]
        print(f"  {item['priority']:<8} {terms} = {item['priority_score']}  {surface}")
    print()
    print(f"Sign in as {DEMO_EMAIL} / {DEMO_PASSWORD}")
    print(f"Project id: {project_id}")


if __name__ == "__main__":
    asyncio.run(main())
