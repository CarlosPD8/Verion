import contextlib
import json
import threading
from collections.abc import Iterator
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from uuid import uuid4

from verion.modules.identity.adapters.outbound.db.repository import (
    PostgresGitHubConnectionRepository,
)
from verion.modules.identity.domain.github_connection import GitHubConnection
from verion.modules.projects.adapters.outbound.db.repository import (
    PostgresConnectedRepoRepository,
    PostgresProjectRepository,
    PostgresScannerConfigRepository,
)
from verion.modules.projects.domain.project import ConnectedRepo, Project
from verion.modules.projects.domain.scanner_config import ScannerConfig
from verion.modules.scanning.adapters.outbound.db.repository import (
    PostgresScanRepository,
    PostgresScanResultRepository,
)
from verion.modules.scanning.adapters.outbound.dns.system_dns_resolver import SystemDnsResolver
from verion.modules.scanning.adapters.outbound.scanners.semgrep_adapter import SemgrepAdapter
from verion.modules.scanning.adapters.outbound.scanners.trivy_adapter import TrivyAdapter
from verion.modules.scanning.adapters.outbound.scanners.zap_adapter import ZapAdapter
from verion.modules.scanning.adapters.outbound.vcs.git_repo_checkout import GitRepoCheckout
from verion.modules.scanning.application.run_scan import RunScanUseCase
from verion.modules.scanning.domain.scan import Scan, ScanStatus
from verion.modules.scanning.domain.scan_result import ScanResultStatus
from verion.modules.scanning.domain.scanner_target_kind import ScannerTargetKind
from verion.platform.clock import SystemClock
from verion.platform.id_generator import UuidIdGenerator
from verion.platform.settings import get_settings
from verion.shared_kernel.scanner_tools import ScannerTool

# Same public repo M3.2/M3.3/M3.4's own tests already use.
_REPO_URL = "https://github.com/octocat/Hello-World"


class _MinimalTargetHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 (http.server's required method name)
        body = b"<html><body><h1>verion multi-scanner fixture</h1></body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass  # keep pytest output free of per-request access logs


@contextlib.contextmanager
def _local_target_server() -> Iterator[int]:
    # 0.0.0.0, not 127.0.0.1 — see test_zap_adapter.py's own note: a
    # loopback-only bind is unreachable from the container via
    # --add-host ...:host-gateway on the Linux CI runner.
    server = ThreadingHTTPServer(("0.0.0.0", 0), _MinimalTargetHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        thread.join(timeout=5)


class _AlwaysFailingScanner:
    """A stand-in for ZAP in the partial-failure test.

    Deliberately a fake in a file otherwise built on real adapters: making a
    real ZAP container fail on demand means either waiting out its 300s timeout
    or pointing it at an unreachable port, and neither buys anything this
    assertion needs. What is being proven here is the *dispatcher's* behaviour
    when one scanner fails, and the dispatcher cannot tell the difference. The
    real-adapter coverage is the first test in this file.
    """

    tool = ScannerTool.ZAP
    target_kind = ScannerTargetKind.URL

    async def run(self, target: str):
        raise RuntimeError("simulated scanner failure")


async def _seed_project(db_session, run_id: str, enabled_tools, zap_target_url):
    project = Project(
        id=f"project-multi-{run_id}",
        owner_id=f"owner-multi-{run_id}",
        name="Widgets",
        created_at=datetime.now(UTC),
    )
    await PostgresProjectRepository(db_session).add(project)
    await PostgresConnectedRepoRepository(db_session).add(
        ConnectedRepo(
            id=f"repo-multi-{run_id}",
            project_id=project.id,
            provider="github",
            url=_REPO_URL,
            default_branch="master",
        )
    )
    # Empty token, deliberately — same reasoning as the other scanning
    # integration tests: GitRepoCheckout only attaches an auth header when
    # access_token is truthy, and a fake non-empty token makes GitHub reject
    # even a public, unauthenticated clone with 401.
    await PostgresGitHubConnectionRepository(db_session).add(
        GitHubConnection(
            user_id=project.owner_id,
            access_token="",
            github_username="octocat",
            connected_at=datetime.now(UTC),
        )
    )
    await PostgresScannerConfigRepository(db_session).upsert(
        ScannerConfig(
            id=f"config-multi-{run_id}",
            project_id=project.id,
            enabled_tools=enabled_tools,
            zap_target_url=zap_target_url,
            updated_at=datetime.now(UTC),
        )
    )
    scan = Scan(
        id=f"scan-multi-{run_id}",
        project_id=project.id,
        status=ScanStatus.PENDING,
        triggered_by=project.owner_id,
        started_at=None,
        finished_at=None,
        failure_reason=None,
    )
    await PostgresScanRepository(db_session).add(scan)
    await db_session.commit()
    return scan


def _use_case(db_session, scanners) -> RunScanUseCase:
    return RunScanUseCase(
        scans=PostgresScanRepository(db_session),
        scan_results=PostgresScanResultRepository(db_session),
        scanners=scanners,
        repo_checkout=GitRepoCheckout(),
        connected_repos=PostgresConnectedRepoRepository(db_session),
        github_connections=PostgresGitHubConnectionRepository(db_session),
        scanner_configs=PostgresScannerConfigRepository(db_session),
        id_generator=UuidIdGenerator(),
        clock=SystemClock(),
    )


async def test_one_trigger_produces_results_for_three_real_tools(db_session):
    """M3.7's acceptance criterion, with all three real adapters.

    ZAP is in here rather than being left to test_zap_adapter.py on purpose:
    it is the only URL-kind scanner, so with Semgrep and Trivy alone both
    scanners receive the same target type and the REPO_PATH-vs-URL split —
    one of this issue's four design decisions — is never exercised against
    real tools. A fake proves the dispatcher routes the right value; only this
    proves a real ZAP container accepts what it is handed while a real Semgrep
    process accepts something structurally different in the same run.

    Slow (~15s) and justified by that: it is the single test covering the most
    delicate part of the issue. See CLAUDE.md's testing requirements for the
    tracked suite runtime and its thresholds.
    """
    run_id = uuid4().hex[:12]
    with _local_target_server() as port:
        target_url = f"http://host.docker.internal:{port}/"
        scan = await _seed_project(
            db_session,
            run_id,
            enabled_tools=(ScannerTool.SEMGREP, ScannerTool.TRIVY, ScannerTool.ZAP),
            zap_target_url=target_url,
        )
        use_case = _use_case(
            db_session,
            {
                ScannerTool.SEMGREP: SemgrepAdapter(config=get_settings().semgrep_ruleset),
                ScannerTool.TRIVY: TrivyAdapter(skip_db_update=True),
                # allow_private_targets=True is ADR-013's documented test-only
                # escape hatch: no CI-reachable public target exists, and the
                # gate itself is covered by test_zap_adapter_ssrf_gate.py.
                ScannerTool.ZAP: ZapAdapter(
                    dns_resolver=SystemDnsResolver(), allow_private_targets=True
                ),
            },
        )

        await use_case.execute(scan.id)
        await db_session.commit()

    updated_scan = await PostgresScanRepository(db_session).get_by_id(scan.id)
    assert updated_scan.status is ScanStatus.COMPLETED
    assert updated_scan.failure_reason is None

    results = await PostgresScanResultRepository(db_session).get_by_scan_id(scan.id)
    by_tool = {result.tool: result for result in results}
    assert sorted(by_tool) == ["semgrep", "trivy", "zap"]
    # Every tool produced real, parseable output — the repo-path pair and the
    # URL one alike, which is the heterogeneous-dispatch claim.
    for result in results:
        assert result.status is ScanResultStatus.SUCCEEDED
        assert isinstance(json.loads(result.raw_output), dict)


async def test_a_failing_scanner_leaves_the_succeeding_scanners_output_intact(db_session):
    """PRODUCT_SPEC.md §12 end to end, through real persistence.

    The assertion that matters for M4 is the last block: not that both rows
    exist, but that the data M4 will read distinguishes the trustworthy rows
    from the failed one without ambiguity.
    """
    run_id = uuid4().hex[:12]
    scan = await _seed_project(
        db_session,
        run_id,
        enabled_tools=(ScannerTool.SEMGREP, ScannerTool.TRIVY, ScannerTool.ZAP),
        zap_target_url="http://host.docker.internal:1/",
    )
    use_case = _use_case(
        db_session,
        {
            ScannerTool.SEMGREP: SemgrepAdapter(config=get_settings().semgrep_ruleset),
            ScannerTool.TRIVY: TrivyAdapter(skip_db_update=True),
            ScannerTool.ZAP: _AlwaysFailingScanner(),
        },
    )

    # No pytest.raises: a tool failing is a recorded outcome, not a job
    # failure. Raising would hand the scan back to arq for a retry that
    # re-runs every scanner and could discard what already succeeded.
    await use_case.execute(scan.id)
    await db_session.commit()

    updated_scan = await PostgresScanRepository(db_session).get_by_id(scan.id)
    assert updated_scan.status is ScanStatus.PARTIAL
    # Per-tool reasons carry the detail; the Scan-level field stays reserved
    # for failures where nothing ran at all.
    assert updated_scan.failure_reason is None

    repository = PostgresScanResultRepository(db_session)

    # This is the query M4 will use, and it is the whole point of the decision.
    trustworthy = await repository.get_succeeded_by_scan_id(scan.id)
    assert sorted(result.tool for result in trustworthy) == ["semgrep", "trivy"]
    for result in trustworthy:
        # Guaranteed by the CHECK constraint, not by convention — which is what
        # lets M4's mappers take `str` rather than `str | None`.
        assert result.raw_output is not None
        assert isinstance(json.loads(result.raw_output), dict)

    # The failed tool is recorded, not absent: M4 can tell "zap was attempted
    # and failed" apart from "zap was never enabled".
    everything = await repository.get_by_scan_id(scan.id)
    assert len(everything) == 3
    failed = next(result for result in everything if result.tool == "zap")
    assert failed.status is ScanResultStatus.FAILED
    assert failed.raw_output is None
    assert "simulated scanner failure" in failed.failure_reason
