import json
from datetime import UTC, datetime
from uuid import uuid4

from verion.modules.identity.adapters.outbound.db.repository import (
    PostgresGitHubConnectionRepository,
)
from verion.modules.identity.domain.github_connection import GitHubConnection
from verion.modules.normalization.adapters.outbound.db.repository import (
    PostgresNormalizationRunRepository,
)
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
from verion.modules.scanning.adapters.outbound.scanners.trivy_adapter import TrivyAdapter
from verion.modules.scanning.adapters.outbound.vcs.git_repo_checkout import GitRepoCheckout
from verion.modules.scanning.application.run_scan import RunScanUseCase
from verion.modules.scanning.domain.scan import Scan, ScanStatus
from verion.platform.clock import SystemClock
from verion.platform.id_generator import UuidIdGenerator
from verion.shared_kernel.scanner_tools import ScannerTool

# Same public repo M3.2/M3.3's own walking-skeleton tests already use.
_REPO_URL = "https://github.com/octocat/Hello-World"


# This is the load-bearing proof of M3.4's actual architectural claim: the
# unmodified RunScanUseCase, GitRepoCheckout, and repository adapters — the
# exact same classes test_worker_run_scan.py exercises with SemgrepAdapter —
# work with a second ScannerPort implementation injected in their place. The
# only line that differs from that file's own setup is the `scanner=` kwarg
# below. Deliberately bypasses arq/platform/worker.py entirely (per M3.4's
# scope: no worker composition changes), unlike test_worker_run_scan.py which
# dispatches through a real arq worker.
async def test_run_scan_use_case_completes_with_trivy_adapter_injected(db_session):
    run_id = uuid4().hex[:12]
    project = Project(
        id=f"project-trivy-{run_id}",
        owner_id=f"owner-trivy-{run_id}",
        name="Widgets",
        created_at=datetime.now(UTC),
    )
    await PostgresProjectRepository(db_session).add(project)
    connected_repo = ConnectedRepo(
        id=f"repo-trivy-{run_id}",
        project_id=project.id,
        provider="github",
        url=_REPO_URL,
        default_branch="master",
    )
    await PostgresConnectedRepoRepository(db_session).add(connected_repo)
    # Empty token, deliberately — same reasoning as test_worker_run_scan.py's
    # own setup: GitRepoCheckout only attaches an auth header when
    # access_token is truthy, and a fake non-empty token would make GitHub
    # reject even this public, unauthenticated clone with 401.
    github_connection = GitHubConnection(
        user_id=project.owner_id,
        access_token="",
        github_username="octocat",
        connected_at=datetime.now(UTC),
    )
    await PostgresGitHubConnectionRepository(db_session).add(github_connection)
    scan = Scan(
        id=f"scan-trivy-{run_id}",
        project_id=project.id,
        status=ScanStatus.PENDING,
        triggered_by=project.owner_id,
        started_at=None,
        finished_at=None,
        failure_reason=None,
    )
    await PostgresScanRepository(db_session).add(scan)
    # Trivy only. Without a config row this project would get the
    # Semgrep+Trivy default, and this test is about one adapter being
    # substitutable, not about dispatch breadth (that is
    # test_multi_scanner_dispatch.py's job).
    await PostgresScannerConfigRepository(db_session).upsert(
        ScannerConfig(
            id=f"config-trivy-{run_id}",
            project_id=project.id,
            enabled_tools=(ScannerTool.TRIVY,),
            zap_target_url=None,
            updated_at=datetime.now(UTC),
        )
    )
    await db_session.commit()

    use_case = RunScanUseCase(
        scans=PostgresScanRepository(db_session),
        scan_results=PostgresScanResultRepository(db_session),
        # The only line that differs from test_worker_run_scan.py's setup.
        scanners={ScannerTool.TRIVY: TrivyAdapter(skip_db_update=True)},
        repo_checkout=GitRepoCheckout(),
        connected_repos=PostgresConnectedRepoRepository(db_session),
        github_connections=PostgresGitHubConnectionRepository(db_session),
        scanner_configs=PostgresScannerConfigRepository(db_session),
        # Same session as every repository above: the ScanResult rows and
        # the normalization handoff row commit together (ADR-0017 decision 2).
        normalization_runs=PostgresNormalizationRunRepository(db_session),
        id_generator=UuidIdGenerator(),
        clock=SystemClock(),
    )
    await use_case.execute(scan.id)
    await db_session.commit()

    updated_scan = await PostgresScanRepository(db_session).get_by_id(scan.id)
    assert updated_scan.status is ScanStatus.COMPLETED
    assert updated_scan.started_at is not None
    assert updated_scan.finished_at is not None
    assert updated_scan.failure_reason is None

    results = await PostgresScanResultRepository(db_session).get_by_scan_id(scan.id)
    assert len(results) == 1
    assert results[0].tool == "trivy"
    assert isinstance(json.loads(results[0].raw_output), dict)
