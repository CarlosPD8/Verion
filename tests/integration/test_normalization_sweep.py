"""The reconciliation sweep against real Postgres (M4.4, ADR-0021).

**The first test in this file is the one that matters**, and it is the reason
this file exists rather than the sweep being covered by unit tests alone.
ADR-0017 decision 2 states an invariant, not a query detail: *the sweep selects on
`normalization_runs` alone and must never read `Scan.status`*. A sweep filtering
on `scan.status IN (COMPLETED, PARTIAL)` would violate ADR-016 decision 2 by the
back door — the job reads `get_succeeded_by_scan_id` correctly while the thing
deciding *whether to run the job at all* sits downstream of a derived,
human-facing summary.

Asserting on the SQL text would not prove that: it passes a rewrite that changes
behaviour and fails a rename that does not. What proves it is a fixture the
invariant permits and every violation forbids — a `pending` row whose `scan_id`
names a scan that does not exist. That is legal by construction, since `scan_id`
carries no foreign key (ADR-0017 decision 1; G11 records the consequence), and
ANY implementation that reads `scans` — a join, a subquery, an `IN`, a second
port call, a `WHERE` on status — returns zero rows for it.
"""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from sqlalchemy import text

from verion.modules.normalization.adapters.outbound.db.repository import (
    PostgresNormalizationRunRepository,
)
from verion.modules.normalization.application.sweep_pending_normalizations import (
    SweepPendingNormalizationsUseCase,
)
from verion.modules.normalization.domain.normalization_run import NormalizationRunStatus
from verion.platform.clock import SystemClock

_STALE_AFTER = timedelta(seconds=900)


class _RecordingQueue:
    def __init__(self) -> None:
        self.enqueued: list[str] = []

    async def enqueue_normalization(self, scan_id: str) -> None:
        self.enqueued.append(scan_id)


async def _insert_run(
    db_session,
    *,
    scan_id: str,
    status: str,
    age: timedelta,
    started: bool = False,
    failure_reason: str | None = None,
) -> None:
    """Raw SQL so a row can be placed at any age without waiting for one.

    Timestamps are computed in Python rather than as `now() - :age` in SQL:
    asyncpg infers a bound parameter's type from the expression's context, so an
    interval sitting where a `timestamptz` column is expected is rejected outright
    rather than being read as an interval.
    """
    requested_at = datetime.now(UTC) - age
    await db_session.execute(
        text(
            "INSERT INTO normalization_runs"
            " (id, scan_id, project_id, status, requested_at, started_at, finished_at,"
            "  failure_reason)"
            " VALUES (:id, :scan_id, :project_id, :status,"
            "  :requested_at, :started_at, :finished_at, :failure_reason)"
        ),
        {
            "id": f"r-{scan_id}",
            "scan_id": scan_id,
            "project_id": f"p-{scan_id}",
            "status": status,
            "requested_at": requested_at,
            "started_at": requested_at if started else None,
            "finished_at": datetime.now(UTC) if status in ("completed", "failed") else None,
            "failure_reason": failure_reason,
        },
    )
    await db_session.commit()


def _sweep(db_session, queue, batch_size: int = 200) -> SweepPendingNormalizationsUseCase:
    return SweepPendingNormalizationsUseCase(
        normalization_runs=PostgresNormalizationRunRepository(db_session),
        queue=queue,
        clock=SystemClock(),
        stale_after=_STALE_AFTER,
        batch_size=batch_size,
    )


async def test_the_sweep_never_reads_scan_status(db_session):
    """ADR-0017 decision 2's invariant, proved behaviourally.

    The row below refers to a `scan_id` with **no row in `scans` at all**. Every
    implementation that reaches into `scans` by any route returns nothing for it;
    the correct one returns it, because the row's own existence already carries
    what such a join would have established (ADR-0017 decision 3's invariant: a
    `normalization_runs` row exists iff `ScanResult` rows were persisted).

    This is deliberately not an assertion about the SQL string. A test that read
    the statement's text would pass a rewrite that changed behaviour and fail a
    rename that did not.
    """
    orphan = f"s-orphan-{uuid4().hex[:12]}"
    await _insert_run(db_session, scan_id=orphan, status="pending", age=timedelta(hours=1))
    # Belt and braces: assert the premise, so this test cannot quietly stop
    # testing what it says if a foreign key is ever added.
    scans = await db_session.execute(
        text("SELECT count(*) FROM scans WHERE id = :id"), {"id": orphan}
    )
    assert scans.scalar_one() == 0

    queue = _RecordingQueue()
    enqueued = await _sweep(db_session, queue).execute()

    assert enqueued >= 1
    assert orphan in queue.enqueued


async def test_a_scan_whose_every_tool_failed_is_still_swept(db_session):
    """ADR-0017 decision 3's degenerate case, at the sweep.

    A scan with `Scan.status == FAILED` still persisted `ScanResult` rows, so it
    still has a handoff row and still owes normalization — which produces zero
    findings, and that is the correct outcome. A sweep that filtered on the scan's
    status would skip exactly this case, which is the one where skipping is least
    visible.
    """
    scan_id = f"s-allfail-{uuid4().hex[:12]}"
    await _insert_run(db_session, scan_id=scan_id, status="pending", age=timedelta(hours=1))
    await db_session.execute(
        text(
            "INSERT INTO scans (id, project_id, status, triggered_by, started_at,"
            " finished_at, failure_reason)"
            " VALUES (:id, :project_id, 'failed', :user, now(), now(), NULL)"
        ),
        {"id": scan_id, "project_id": f"p-{scan_id}", "user": f"user-{scan_id}"},
    )
    await db_session.commit()

    queue = _RecordingQueue()
    await _sweep(db_session, queue).execute()

    assert scan_id in queue.enqueued


async def test_a_stalled_running_row_is_recovered(db_session):
    """The deviation from ADR-0017's anticipated `WHERE status = 'pending'`.

    A worker killed after its claim committed leaves this row and nothing else
    would ever pick it up. The opposite risk — re-enqueuing a live job — is
    harmless (arq's job-id dedup makes it a no-op, and the work is idempotent by
    construction), and `test_sweep_settings.py` pins the `job_timeout <
    stale_after` relationship that keeps it in the harmless direction.
    """
    scan_id = f"s-stall-{uuid4().hex[:12]}"
    await _insert_run(
        db_session, scan_id=scan_id, status="running", age=timedelta(hours=1), started=True
    )

    queue = _RecordingQueue()
    await _sweep(db_session, queue).execute()

    assert scan_id in queue.enqueued


async def test_a_fresh_row_and_a_terminal_row_are_both_left_alone(db_session):
    """Two exclusions with different reasons, asserted together because the
    failure mode of getting either wrong is the same: a batch slot spent forever.

    Fresh — its job is probably still queued, and the sweep is a backstop rather
    than the trigger. Completed — terminal, so the claim would refuse it anyway.
    """
    fresh = f"s-fresh-{uuid4().hex[:12]}"
    done = f"s-done-{uuid4().hex[:12]}"
    await _insert_run(db_session, scan_id=fresh, status="pending", age=timedelta(seconds=60))
    await _insert_run(
        db_session, scan_id=done, status="completed", age=timedelta(hours=1), started=True
    )

    queue = _RecordingQueue()
    await _sweep(db_session, queue).execute()

    assert fresh not in queue.enqueued
    assert done not in queue.enqueued


async def test_a_re_claim_preserves_the_original_start_time(db_session):
    """Both claims run on one session, so this observes the TRANSITION and not
    the locking — named accordingly.

    An earlier draft called this `…_serializes_and_only_one_worker_wins_…`, which
    it cannot show: there is no second connection here, `FOR UPDATE` has nothing
    to serialize against, and "only one wins" is not even the intended behaviour
    (a second claim against a RUNNING row succeeds by design — that is what lets
    the sweep recover a stalled job). What it does establish is that `start` is
    idempotent in the field that matters: `started_at` is set once and a re-claim
    does not reset it, mirroring `RunScanUseCase`'s `scan.started_at or now()`.

    Genuine concurrent-claim behaviour would need two connections and a barrier,
    and is not covered anywhere — the reason it is tolerable is that the work
    itself is idempotent by construction (ADR-0020), so two winners cost duplicate
    effort rather than duplicate rows.
    """
    scan_id = f"s-claim-{uuid4().hex[:12]}"
    await _insert_run(db_session, scan_id=scan_id, status="pending", age=timedelta(hours=1))
    runs = PostgresNormalizationRunRepository(db_session)

    first = await runs.claim(scan_id=scan_id, now=SystemClock().now())
    await db_session.commit()
    second = await runs.claim(scan_id=scan_id, now=SystemClock().now())
    await db_session.commit()

    assert first.status is NormalizationRunStatus.RUNNING
    assert second is not None
    assert second.started_at == first.started_at


async def test_claiming_a_completed_run_returns_none(db_session):
    """The job's short-circuit for a redelivered message — `RunScanUseCase`'s
    `== COMPLETED` guard, expressed in SQL because two workers can reach it at
    once."""
    scan_id = f"s-term-{uuid4().hex[:12]}"
    await _insert_run(
        db_session, scan_id=scan_id, status="completed", age=timedelta(hours=1), started=True
    )

    claimed = await PostgresNormalizationRunRepository(db_session).claim(
        scan_id=scan_id, now=SystemClock().now()
    )

    assert claimed is None


async def test_claiming_a_scan_with_no_row_returns_none(db_session):
    """A scan that failed before persisting anything has no handoff row, by
    ADR-0017 decision 3's invariant. The job must treat that as "nothing to do",
    not as an error."""
    claimed = await PostgresNormalizationRunRepository(db_session).claim(
        scan_id=f"s-absent-{uuid4().hex[:12]}", now=SystemClock().now()
    )

    assert claimed is None


async def test_a_failed_run_is_claimable_so_arq_s_retry_is_not_decorative(db_session):
    """The transient half of the failure taxonomy depends on this.

    `NormalizeScanUseCase` writes `failed` and re-raises so arq retries; if
    `failed` were terminal, that retry would reach `claim`, get `None`, and return
    — a retry that silently does nothing. Re-claiming also clears
    `failure_reason`, because a RUNNING row carrying one is rejected by both the
    domain guard and `ck_normalization_runs_failure_reason_shape`.
    """
    scan_id = f"s-fail-{uuid4().hex[:12]}"
    await _insert_run(
        db_session,
        scan_id=scan_id,
        status="failed",
        age=timedelta(hours=1),
        started=True,
        failure_reason="transient DB error",
    )

    reclaimed = await PostgresNormalizationRunRepository(db_session).claim(
        scan_id=scan_id, now=SystemClock().now()
    )
    await db_session.commit()

    assert reclaimed is not None
    assert reclaimed.status is NormalizationRunStatus.RUNNING
    assert reclaimed.failure_reason is None
