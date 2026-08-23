"""The scan → normalize handoff against real Postgres (ADR-0017).

Deliberately not container-bound in the sense CLAUDE.md's runtime baseline
tracks: Postgres is a service container started before the workflow's `steps:`
run, so the `Tests (pytest …)` step pays only connection and query time. The
scanners here are in-process fakes — this test is about the handoff record and
its constraints, and `test_multi_scanner_dispatch.py` already owns the real
three-scanner run.
"""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

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
from verion.modules.scanning.application.run_scan import RunScanUseCase
from verion.modules.scanning.domain.exceptions import ScannerExecutionFailed
from verion.modules.scanning.domain.raw_scan_result import RawScanResult
from verion.modules.scanning.domain.scan import Scan, ScanStatus
from verion.modules.scanning.domain.scanner_target_kind import ScannerTargetKind
from verion.platform.clock import SystemClock
from verion.platform.id_generator import UuidIdGenerator
from verion.shared_kernel.scanner_tools import ScannerTool


class _FakeScanner:
    """In-process stand-in — this test is about the handoff row, not about any
    real tool's output."""

    def __init__(self, tool: ScannerTool, fail: bool = False) -> None:
        self.tool = tool
        self.target_kind = ScannerTargetKind.REPO_PATH
        self._fail = fail

    async def run(self, target: str) -> RawScanResult:
        if self._fail:
            raise ScannerExecutionFailed("simulated scanner failure")
        return RawScanResult(tool=self.tool, raw_output='{"results": []}')


class _FakeRepoCheckout:
    async def checkout(self, repo_url: str, access_token: str | None) -> str:
        return "/tmp/verion-handoff-fixture"

    async def cleanup(self, local_path: str) -> None:
        return None


async def _seed(db_session, run_id: str) -> Scan:
    project = Project(
        id=f"project-handoff-{run_id}",
        owner_id=f"owner-handoff-{run_id}",
        name="Widgets",
        created_at=datetime.now(UTC),
    )
    await PostgresProjectRepository(db_session).add(project)
    await PostgresConnectedRepoRepository(db_session).add(
        ConnectedRepo(
            id=f"repo-handoff-{run_id}",
            project_id=project.id,
            provider="github",
            url="https://github.com/octocat/Hello-World",
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
            id=f"config-handoff-{run_id}",
            project_id=project.id,
            enabled_tools=(ScannerTool.SEMGREP, ScannerTool.TRIVY),
            zap_target_url=None,
            updated_at=datetime.now(UTC),
        )
    )
    scan = Scan(
        id=f"scan-handoff-{run_id}",
        project_id=project.id,
        status=ScanStatus.PENDING,
        triggered_by=project.owner_id,
        started_at=None,
        finished_at=None,
        failure_reason=None,
    )
    await PostgresScanRepository(db_session).add(scan)
    return scan


def _use_case(db_session, scanners) -> RunScanUseCase:
    return RunScanUseCase(
        scans=PostgresScanRepository(db_session),
        scan_results=PostgresScanResultRepository(db_session),
        scanners=scanners,
        repo_checkout=_FakeRepoCheckout(),
        connected_repos=PostgresConnectedRepoRepository(db_session),
        github_connections=PostgresGitHubConnectionRepository(db_session),
        scanner_configs=PostgresScannerConfigRepository(db_session),
        normalization_runs=PostgresNormalizationRunRepository(db_session),
        id_generator=UuidIdGenerator(),
        clock=SystemClock(),
    )


async def test_a_partial_scan_leaves_a_pending_handoff_row_without_reading_scan_status(
    db_session,
):
    """M4.0's headline assertion, end to end against real Postgres.

    The load-bearing part is the last block: everything a future sweep needs is
    reachable from `normalization_runs` and `scan_results` alone. Reading
    `Scan.status` to decide whether to normalize would put a pipeline
    downstream of a derived, human-facing summary — ADR-016 decision 2's whole
    point, violated by the back door.
    """
    run_id = uuid4().hex[:12]
    scan = await _seed(db_session, run_id)
    use_case = _use_case(
        db_session,
        {
            ScannerTool.SEMGREP: _FakeScanner(ScannerTool.SEMGREP),
            ScannerTool.TRIVY: _FakeScanner(ScannerTool.TRIVY, fail=True),
        },
    )

    await use_case.execute(scan.id)
    await db_session.commit()

    run = await PostgresNormalizationRunRepository(db_session).get_by_scan_id(scan.id)
    assert run is not None
    assert run.status is NormalizationRunStatus.PENDING
    assert run.scan_id == scan.id
    assert run.started_at is None
    assert run.finished_at is None
    assert run.failure_reason is None

    # The scan really is PARTIAL — so this is the case that would have been
    # skipped if normalization only ran on COMPLETED.
    updated = await PostgresScanRepository(db_session).get_by_id(scan.id)
    assert updated.status is ScanStatus.PARTIAL

    # What a sweep will select on, and the only two tables it needs. No query
    # in this path touches `scans`.
    pending = await db_session.execute(
        text("SELECT scan_id FROM normalization_runs WHERE status = 'pending'")
    )
    assert scan.id in [row[0] for row in pending]
    trustworthy = await PostgresScanResultRepository(db_session).get_succeeded_by_scan_id(scan.id)
    assert [result.tool for result in trustworthy] == ["semgrep"]


async def test_requesting_the_same_scan_twice_is_a_no_op_not_an_integrity_error(db_session):
    """The retry path, against the real constraint.

    A second request must neither raise nor overwrite: DO UPDATE would reset a
    running or completed row back to pending. Asserted by mutating the row to
    `completed` first — if the insert were DO UPDATE, the second request would
    silently undo that and re-queue an already-normalized scan.
    """
    run_id = uuid4().hex[:12]
    scan = await _seed(db_session, run_id)
    repository = PostgresNormalizationRunRepository(db_session)
    requested_at = datetime.now(UTC)
    await repository.request(id=f"n1-{run_id}", scan_id=scan.id, requested_at=requested_at)
    await db_session.execute(
        text("UPDATE normalization_runs SET status = 'completed' WHERE scan_id = :scan_id"),
        {"scan_id": scan.id},
    )

    await repository.request(id=f"n2-{run_id}", scan_id=scan.id, requested_at=datetime.now(UTC))

    run = await repository.get_by_scan_id(scan.id)
    assert run.id == f"n1-{run_id}"
    assert run.status is NormalizationRunStatus.COMPLETED
    rows = await db_session.execute(
        text("SELECT count(*) FROM normalization_runs WHERE scan_id = :scan_id"),
        {"scan_id": scan.id},
    )
    assert rows.scalar_one() == 1


@pytest.mark.parametrize("status", list(NormalizationRunStatus))
async def test_every_domain_status_is_accepted_by_the_check_constraint(db_session, status):
    """Not a test of the CHECK — a test that the enum and the CHECK agree on the
    same strings.

    That coupling is the one place this can break silently: the adapter persists
    `str(status)`, and a member added to the enum without being added to
    `ck_normalization_runs_status` would fail only at runtime, on the transition
    that first used it.
    """
    run_id = uuid4().hex[:12]
    failure_reason = "'boom'" if status is NormalizationRunStatus.FAILED else "NULL"

    await db_session.execute(
        text(
            "INSERT INTO normalization_runs"
            " (id, scan_id, status, requested_at, started_at, finished_at, failure_reason)"
            f" VALUES (:id, :scan_id, :status, now(), NULL, NULL, {failure_reason})"
        ),
        {"id": f"n-{run_id}", "scan_id": f"scan-{run_id}", "status": str(status)},
    )

    stored = await db_session.execute(
        text("SELECT status FROM normalization_runs WHERE id = :id"), {"id": f"n-{run_id}"}
    )
    assert stored.scalar_one() == status.value


# The domain dataclass rejects these two shapes as well (test_normalization_run.py).
# These go around it with raw SQL on purpose: the CHECK is what makes the
# invariant true for *any* writer, not only for code that constructs the entity
# first — which matters because a future migration or a manual fix is exactly
# the writer that would not.


async def test_the_database_rejects_an_unknown_status(db_session):
    run_id = uuid4().hex[:12]

    with pytest.raises(IntegrityError, match="ck_normalization_runs_status"):
        await db_session.execute(
            text(
                "INSERT INTO normalization_runs"
                " (id, scan_id, status, requested_at, started_at, finished_at, failure_reason)"
                " VALUES (:id, :scan_id, 'normalising', now(), NULL, NULL, NULL)"
            ),
            {"id": f"bad1-{run_id}", "scan_id": f"scan-{run_id}"},
        )
    await db_session.rollback()


async def test_the_database_rejects_a_non_failed_row_carrying_a_failure_reason(db_session):
    run_id = uuid4().hex[:12]

    with pytest.raises(IntegrityError, match="ck_normalization_runs_failure_reason_shape"):
        await db_session.execute(
            text(
                "INSERT INTO normalization_runs"
                " (id, scan_id, status, requested_at, started_at, finished_at, failure_reason)"
                " VALUES (:id, :scan_id, 'completed', now(), NULL, NULL, 'boom')"
            ),
            {"id": f"bad2-{run_id}", "scan_id": f"scan-{run_id}"},
        )
    await db_session.rollback()
