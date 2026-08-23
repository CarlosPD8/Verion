import json
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from arq.connections import RedisSettings, create_pool
from arq.worker import create_worker

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
from verion.modules.scanning.adapters.outbound.queue.arq_job_queue import ArqJobQueue
from verion.modules.scanning.adapters.outbound.scanners.semgrep_adapter import SemgrepAdapter
from verion.modules.scanning.adapters.outbound.vcs.git_repo_checkout import GitRepoCheckout
from verion.modules.scanning.application.run_scan import RunScanUseCase
from verion.modules.scanning.domain.exceptions import RepoCheckoutFailed
from verion.modules.scanning.domain.scan import Scan, ScanStatus
from verion.platform.clock import SystemClock
from verion.platform.id_generator import UuidIdGenerator
from verion.platform.settings import get_settings
from verion.platform.worker import WorkerSettings
from verion.shared_kernel.scanner_tools import ScannerTool

# A real, public repo — same one M3.2's walking skeleton test already uses.
_REPO_URL = "https://github.com/octocat/Hello-World"


async def test_worker_processes_a_real_enqueued_scan_job_end_to_end(db_session):
    # Unique per run, not a fixed literal: arq dedupes enqueue_job by job_id
    # (job_id == scan_id, per ArqJobQueue) against its own result cache
    # (default keep_result=3600s) — re-running this test with the same
    # scan_id within that window would silently no-op the second enqueue.
    run_id = uuid4().hex[:12]
    project = Project(
        id=f"project-worker-{run_id}",
        owner_id=f"owner-worker-{run_id}",
        name="Widgets",
        created_at=datetime.now(UTC),
    )
    await PostgresProjectRepository(db_session).add(project)
    connected_repo = ConnectedRepo(
        id=f"repo-worker-{run_id}",
        project_id=project.id,
        provider="github",
        url=_REPO_URL,
        default_branch="master",
    )
    await PostgresConnectedRepoRepository(db_session).add(connected_repo)
    # Empty token, deliberately: proves the GitHubConnection lookup/wiring
    # works end to end without attaching a real Authorization header to a
    # request against a real, public repo — GitHub rejects an *invalid*
    # token with 401 even for a repo that needs no auth at all, so a fake
    # non-empty token would break this test. GitRepoCheckout only attaches
    # the auth header when access_token is truthy.
    github_connection = GitHubConnection(
        user_id=project.owner_id,
        access_token="",
        github_username="octocat",
        connected_at=datetime.now(UTC),
    )
    await PostgresGitHubConnectionRepository(db_session).add(github_connection)
    scan = Scan(
        id=f"scan-worker-{run_id}",
        project_id=project.id,
        status=ScanStatus.PENDING,
        triggered_by=project.owner_id,
        started_at=None,
        finished_at=None,
        failure_reason=None,
    )
    await PostgresScanRepository(db_session).add(scan)
    # Semgrep only. The worker now registers all three adapters, so without a
    # config row this project would take the Semgrep+Trivy default and this
    # test would silently start paying for a Trivy run it does not assert on.
    # Dispatch breadth is test_multi_scanner_dispatch.py's subject; this test
    # is about the arq round trip.
    await PostgresScannerConfigRepository(db_session).upsert(
        ScannerConfig(
            id=f"config-worker-{run_id}",
            project_id=project.id,
            enabled_tools=(ScannerTool.SEMGREP,),
            zap_target_url=None,
            updated_at=datetime.now(UTC),
        )
    )
    # Committed, not just flushed: the worker job runs in a separate session
    # over a separate connection — it can only see rows this transaction has
    # actually committed.
    await db_session.commit()

    pool = await create_pool(RedisSettings.from_dsn(get_settings().redis_url))
    try:
        await ArqJobQueue(pool).enqueue_scan(scan.id)

        worker = create_worker(WorkerSettings, burst=True, redis_pool=pool)
        try:
            await worker.run_check()
        finally:
            await worker.close()
    finally:
        await pool.aclose()

    updated_scan = await PostgresScanRepository(db_session).get_by_id(scan.id)
    assert updated_scan.status is ScanStatus.COMPLETED
    assert updated_scan.started_at is not None
    assert updated_scan.finished_at is not None
    assert updated_scan.failure_reason is None

    results = await PostgresScanResultRepository(db_session).get_by_scan_id(scan.id)
    assert len(results) == 1
    assert results[0].tool == "semgrep"
    assert isinstance(json.loads(results[0].raw_output), dict)


# Rule 12: no credential may appear in an exception message, an API response,
# or a log — extended here to Scan.failure_reason, a persistence sink this
# issue introduces that didn't exist before. git_repo_checkout.py already
# redacts the token at RepoCheckoutFailed-construction time (see
# test_git_repo_checkout.py's own rule-12 tests), but that test doesn't know
# failure_reason exists. This is the regression check colocated with this
# new sink specifically, per rule 12's "ships an explicit test... colocated
# with that module's other security-relevant tests" instruction.
async def test_no_access_token_leaks_into_the_persisted_failure_reason(db_session):
    run_id = uuid4().hex[:12]
    project = Project(
        id=f"project-leak-{run_id}",
        owner_id=f"owner-leak-{run_id}",
        name="Widgets",
        created_at=datetime.now(UTC),
    )
    await PostgresProjectRepository(db_session).add(project)
    connected_repo = ConnectedRepo(
        id=f"repo-leak-{run_id}",
        project_id=project.id,
        provider="github",
        # Guaranteed checkout failure — real repo-not-found error from a real
        # git subprocess, same target test_git_repo_checkout.py's own rule-12
        # test already uses.
        url="https://github.com/octocat/this-repo-does-not-exist-verion-test",
        default_branch="main",
    )
    await PostgresConnectedRepoRepository(db_session).add(connected_repo)
    secret_token = "super-secret-token"
    github_connection = GitHubConnection(
        user_id=project.owner_id,
        access_token=secret_token,
        github_username="octocat",
        connected_at=datetime.now(UTC),
    )
    await PostgresGitHubConnectionRepository(db_session).add(github_connection)
    scan = Scan(
        id=f"scan-leak-{run_id}",
        project_id=project.id,
        status=ScanStatus.PENDING,
        triggered_by=project.owner_id,
        started_at=None,
        finished_at=None,
        failure_reason=None,
    )
    await PostgresScanRepository(db_session).add(scan)
    await PostgresScannerConfigRepository(db_session).upsert(
        ScannerConfig(
            id=f"config-leak-{run_id}",
            project_id=project.id,
            enabled_tools=(ScannerTool.SEMGREP,),
            zap_target_url=None,
            updated_at=datetime.now(UTC),
        )
    )
    await db_session.commit()

    use_case = RunScanUseCase(
        scans=PostgresScanRepository(db_session),
        scan_results=PostgresScanResultRepository(db_session),
        # Never reached — checkout fails first — but the registry needs a
        # real entry to construct RunScanUseCase.
        scanners={ScannerTool.SEMGREP: SemgrepAdapter(config=get_settings().semgrep_ruleset)},
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

    with pytest.raises(RepoCheckoutFailed):
        await use_case.execute(scan.id)
    await db_session.commit()

    updated_scan = await PostgresScanRepository(db_session).get_by_id(scan.id)
    assert updated_scan.status is ScanStatus.FAILED
    assert updated_scan.failure_reason is not None
    assert secret_token not in updated_scan.failure_reason
