"""`SweepPendingNormalizationsUseCase` against in-memory ports (M4.4).

What is deliberately NOT asserted here: that the sweep never reads `Scan.status`.
This tree has no `scans` table to read, so any assertion about it would be
satisfied by construction — the definition of a vacuous test. That invariant is
proved behaviourally in `tests/integration/test_normalization_sweep.py`, against
real Postgres, by sweeping a row whose `scan_id` names no scan at all.
"""

from datetime import UTC, datetime, timedelta

from verion.modules.normalization.application.sweep_pending_normalizations import (
    SweepPendingNormalizationsUseCase,
)
from verion.modules.normalization.domain.normalization_run import NormalizationRun

_NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
_STALE_AFTER = timedelta(seconds=900)
_LONG_AGO = _NOW - timedelta(hours=1)


def _run(scan_id: str, requested_at: datetime) -> NormalizationRun:
    return NormalizationRun.requested(
        id=f"run-{scan_id}",
        scan_id=scan_id,
        project_id="project-1",
        requested_at=requested_at,
    )


def _sweep(runs, queue, clock_factory, batch_size: int = 200):
    return SweepPendingNormalizationsUseCase(
        normalization_runs=runs,
        queue=queue,
        clock=clock_factory(fixed_now=_NOW),
        stale_after=_STALE_AFTER,
        batch_size=batch_size,
    )


async def test_a_stale_pending_run_is_re_enqueued(
    normalization_run_repository, normalization_queue, clock_factory
):
    normalization_run_repository.seed(_run("scan-old", _LONG_AGO))

    enqueued = await _sweep(
        normalization_run_repository, normalization_queue, clock_factory
    ).execute()

    assert enqueued == 1
    assert normalization_queue.enqueued == ["scan-old"]


async def test_a_fresh_pending_run_is_left_alone(
    normalization_run_repository, normalization_queue, clock_factory
):
    """The enqueue in `run_scan` is what makes normalization prompt; the sweep is
    a backstop. Sweeping a row whose job is probably still in the queue would make
    the backstop the trigger."""
    normalization_run_repository.seed(_run("scan-new", _NOW - timedelta(seconds=60)))

    enqueued = await _sweep(
        normalization_run_repository, normalization_queue, clock_factory
    ).execute()

    assert enqueued == 0
    assert normalization_queue.enqueued == []


async def test_a_stale_running_run_is_re_enqueued(
    normalization_run_repository, normalization_queue, clock_factory
):
    """The deviation from ADR-0017's anticipated `WHERE status = 'pending'`.

    A worker killed after its claim committed leaves exactly this row.
    Pending-only, nothing would ever recover it — the silent permanent loss the
    record exists to prevent. See `test_sweep_settings.py` for what keeps the
    opposite failure (re-enqueuing a live job) harmless.
    """
    normalization_run_repository.seed(_run("scan-stalled", _LONG_AGO).start(_LONG_AGO))

    enqueued = await _sweep(
        normalization_run_repository, normalization_queue, clock_factory
    ).execute()

    assert enqueued == 1
    assert normalization_queue.enqueued == ["scan-stalled"]


async def test_a_completed_run_is_never_re_enqueued(
    normalization_run_repository, normalization_queue, clock_factory
):
    """`completed` is terminal. Re-enqueuing one would have no effect — the claim
    would return `None` — but it would consume a batch slot forever, since
    `requested_at` only gets older."""
    normalization_run_repository.seed(
        _run("scan-done", _LONG_AGO).start(_LONG_AGO).complete(_NOW - timedelta(minutes=50))
    )

    enqueued = await _sweep(
        normalization_run_repository, normalization_queue, clock_factory
    ).execute()

    assert enqueued == 0
    assert normalization_queue.enqueued == []


async def test_a_failed_run_is_not_swept_either(
    normalization_run_repository, normalization_queue, clock_factory
):
    """`failed` is re-CLAIMABLE (so arq's retry works) but not re-ENQUEUEABLE by
    the sweep, and the two are different questions.

    A deterministic failure — the `collapse_by_identity` skip — would fail
    identically on every tick, so sweeping it would be an infinite retry loop at
    5-minute intervals. Recovery from a failed run is a human reading
    `failure_reason`, which is why that field exists.
    """
    normalization_run_repository.seed(
        _run("scan-failed", _LONG_AGO).start(_LONG_AGO).fail(_NOW - timedelta(minutes=50), "boom")
    )

    enqueued = await _sweep(
        normalization_run_repository, normalization_queue, clock_factory
    ).execute()

    assert enqueued == 0
    assert normalization_queue.enqueued == []


async def test_the_batch_is_bounded_and_takes_the_oldest_first(
    normalization_run_repository, normalization_queue, clock_factory
):
    """Oldest-first so a backlog drains in the order work was owed. The bound is
    what stops one tick turning a large table into an unbounded write burst; the
    next tick takes the rest."""
    for minutes in (10, 30, 20, 40):
        normalization_run_repository.seed(
            _run(f"scan-{minutes}", _NOW - timedelta(hours=1, minutes=minutes))
        )

    enqueued = await _sweep(
        normalization_run_repository, normalization_queue, clock_factory, batch_size=2
    ).execute()

    assert enqueued == 2
    assert normalization_queue.enqueued == ["scan-40", "scan-30"]
