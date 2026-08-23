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
from verion.modules.normalization.domain.normalization_run import NormalizationRunStatus
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
from verion.modules.scanning.domain.raw_scan_result import RawScanResult
from verion.modules.scanning.domain.scan import Scan, ScanStatus
from verion.modules.scanning.domain.scanner_target_kind import ScannerTargetKind
from verion.platform.clock import SystemClock
from verion.platform.id_generator import UuidIdGenerator
from verion.platform.settings import get_settings
from verion.platform.worker import WorkerSettings, run_scan
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

        # WorkerSettings minus cron_jobs. M4.4 added a 5-minute sweep to the
        # real settings, and arq schedules cron inside the worker heartbeat — so
        # a burst that happened to straddle a 5-minute boundary would run a REAL
        # sweep against the shared test database and re-enqueue normalize_scan
        # for whatever stale rows other tests left behind. Low probability, fully
        # non-deterministic, and it would look like a flaky assertion in this
        # test rather than like what it is. The sweep has its own coverage in
        # test_normalization_sweep.py; what this test is about is the job round
        # trip, so the cron is simply not part of its subject.
        # Derived by COPYING WorkerSettings' attributes rather than subclassing
        # it: arq reads settings off the class's own `__dict__`, so a subclass
        # inherits nothing and `create_worker` fails with "at least one function
        # or cron_job must be registered". Copying also means a future attribute
        # on WorkerSettings is carried here automatically instead of silently
        # diverging.
        settings_without_cron = {
            name: value for name, value in vars(WorkerSettings).items() if not name.startswith("__")
        }
        settings_without_cron["cron_jobs"] = []

        worker = create_worker(
            type("WorkerSettingsWithoutCron", (), settings_without_cron),
            burst=True,
            redis_pool=pool,
        )
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

    # M4.4: the pipeline now continues past this point, through the real arq
    # round trip and inside this same burst — `run_scan` commits, enqueues
    # `normalize_scan` after the commit, and the worker picks it up. This is the
    # only place in the suite where that whole chain runs against a real Redis, a
    # real clone and a real Semgrep, and it costs nothing extra because it rides
    # on a test that was already paying for all three.
    #
    # `completed` rather than `pending` is the assertion: `pending` is what this
    # row was left at for four issues while the consumer did not exist (ADR-0017
    # decision 2's deferral), so it is exactly the value that would come back if
    # the enqueue, the job registration or the claim were wired wrong.
    run = await PostgresNormalizationRunRepository(db_session).get_by_scan_id(scan.id)
    assert run is not None
    assert run.status is NormalizationRunStatus.COMPLETED
    assert run.started_at is not None
    assert run.finished_at is not None
    assert run.failure_reason is None


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


class _UnreachableRedis:
    """Stands in for `ctx["redis"]` when Redis is down.

    `ArqNormalizationQueue` calls `enqueue_job` on whatever it is handed, so
    raising there reproduces an outage at exactly the point the real adapter
    would hit one.
    """

    async def enqueue_job(self, *args, **kwargs):
        raise ConnectionError("simulated Redis outage")


# A lost enqueue must not be an error path (ADR-0017 decision 2, ADR-0021). The
# normalization_runs row committed alongside the ScanResult rows IS the durable
# record of owed work; the enqueue is a latency optimization on top of it, and
# the sweep recovers anything dropped. Raising here would make Redis a
# correctness dependency of a scan that has already committed, and would hand
# arq a retry that re-runs every enabled scanner (ADR-016 decision 1) to fix a
# message that was never the record.
#
# This is the test the `except Exception: return` in worker.py points at. Without
# it that catch is one "let's not swallow exceptions" refactor away from turning
# a Redis blip into a failed scan — which is the G8 failure shape with a person
# in the tool's place, and the reason the comment there says the fix is a metric
# and NOT a raise.
async def test_a_lost_enqueue_leaves_the_scan_committed_and_the_handoff_row_pending(db_session):
    run_id = uuid4().hex[:12]
    scan = await _seed_scan_for_fake_run(db_session, run_id)

    ctx = {
        "scanners": {ScannerTool.SEMGREP: _AlwaysSucceedsScanner()},
        "repo_checkout": _NoopCheckout(),
        "redis": _UnreachableRedis(),
    }
    # Returns normally. No pytest.raises — that IS the first assertion.
    await run_scan(ctx, scan.id)

    updated = await PostgresScanRepository(db_session).get_by_id(scan.id)
    assert updated.status is ScanStatus.COMPLETED
    results = await PostgresScanResultRepository(db_session).get_by_scan_id(scan.id)
    assert [result.tool for result in results] == ["semgrep"]
    # Still owed, and still recoverable — this is what the sweep will collect.
    run = await PostgresNormalizationRunRepository(db_session).get_by_scan_id(scan.id)
    assert run is not None
    assert run.status is NormalizationRunStatus.PENDING


class _AlwaysSucceedsScanner:
    tool = ScannerTool.SEMGREP
    target_kind = ScannerTargetKind.REPO_PATH

    async def run(self, target: str) -> RawScanResult:
        return RawScanResult(tool=self.tool, raw_output='{"results": []}')


class _NoopCheckout:
    async def checkout(self, repo_url: str, access_token: str | None) -> str:
        return "/tmp/verion-enqueue-fixture"

    async def cleanup(self, local_path: str) -> None:
        return None


async def _seed_scan_for_fake_run(db_session, run_id: str) -> Scan:
    project = Project(
        id=f"project-enq-{run_id}",
        owner_id=f"owner-enq-{run_id}",
        name="Widgets",
        created_at=datetime.now(UTC),
    )
    await PostgresProjectRepository(db_session).add(project)
    await PostgresConnectedRepoRepository(db_session).add(
        ConnectedRepo(
            id=f"repo-enq-{run_id}",
            project_id=project.id,
            provider="github",
            url=_REPO_URL,
            default_branch="master",
        )
    )
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
            id=f"config-enq-{run_id}",
            project_id=project.id,
            enabled_tools=(ScannerTool.SEMGREP,),
            zap_target_url=None,
            updated_at=datetime.now(UTC),
        )
    )
    scan = Scan(
        id=f"scan-enq-{run_id}",
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
