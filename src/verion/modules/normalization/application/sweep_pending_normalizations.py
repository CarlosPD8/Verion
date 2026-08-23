from datetime import timedelta

from verion.modules.normalization.ports.normalization_queue import NormalizationQueuePort
from verion.modules.normalization.ports.normalization_run_repository import (
    NormalizationRunRepositoryPort,
)
from verion.shared_kernel.ports import ClockPort


class SweepPendingNormalizationsUseCase:
    """Re-enqueue normalization for scans whose work is owed and not progressing.

    The recovery half of ADR-0017 decision 2's outbox. The
    `normalization_runs` row is written in the same Postgres transaction as the
    `ScanResult` rows, so it survives whatever happens to the Redis message; this
    is what turns that durability into an actual retry rather than a row nobody
    ever reads.

    **It selects on `normalization_runs` alone and never reads `Scan.status`** —
    ADR-0017 decision 2 states that as an invariant, not a query detail, and
    `get_stale`'s docstring carries the reasoning. It is proved behaviourally by
    sweeping a row whose `scan_id` names no scan at all.

    **It enqueues; it does not normalize.** One code path produces findings, and
    it is the job. A sweep that normalized inline would be a second writer with
    its own transaction lifecycle, its own failure semantics and no `job_timeout`.

    **Nothing here guards against racing a live job, because three other things
    already do**, and duplicating that logic in a `WHERE` clause would be the
    fourth place to keep it right:

    - `arq.cron`'s `unique=True` default gives each tick a job id unique to its
      intended execution time, so N workers running this cron produce one run.
    - `ArqNormalizationQueue` enqueues with `_job_id="normalize:<scan_id>"`, and
      arq refuses an id that is already queued or in flight — so re-enqueuing a
      live job is a no-op.
    - The job's own `claim` is a conditional, row-locked transition, and the work
      it does is idempotent by construction (ADR-0020).

    So the worst case of an over-eager sweep is a wasted no-op enqueue, while the
    worst case of an under-eager one is a scan that is never normalized. The
    staleness threshold below is chosen on exactly that asymmetry.

    **One case is deliberately outside that asymmetry and is not covered here:
    a `failed` run.** `get_stale` excludes it, because the deterministic failure
    ADR-0021 decision 5 describes would fail identically on every tick — an
    infinite retry loop at five-minute intervals. But `failed` is also where a
    *transient* failure lands once arq exhausts `max_tries`, and that one is
    genuinely lost until a human reads `failure_reason`. The two are
    indistinguishable after the fact, which is why this is registered as **G15**
    rather than patched here.
    """

    def __init__(
        self,
        normalization_runs: NormalizationRunRepositoryPort,
        queue: NormalizationQueuePort,
        clock: ClockPort,
        stale_after: timedelta,
        batch_size: int,
    ) -> None:
        self._normalization_runs = normalization_runs
        self._queue = queue
        self._clock = clock
        self._stale_after = stale_after
        self._batch_size = batch_size

    async def execute(self) -> int:
        """Enqueue every stale run, oldest first. Returns how many were enqueued.

        The count is returned rather than logged because `src/` has no logging and
        this issue does not add any — it exists so a test can assert on what a tick
        did, and so a future metric has something to read.
        """
        stale = await self._normalization_runs.get_stale(
            older_than=self._clock.now() - self._stale_after, limit=self._batch_size
        )
        for run in stale:
            await self._queue.enqueue_normalization(run.scan_id)
        return len(stale)
