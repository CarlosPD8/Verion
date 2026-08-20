from arq.connections import ArqRedis

_RUN_SCAN_JOB = "run_scan"


class ArqJobQueue:
    """Wraps an already-created arq pool — never creates one itself.

    Pool creation/closing is the caller's responsibility (same shape as
    PostgresScanRepository taking an already-created AsyncSession rather
    than a DSN), so this adapter has no lazy-init race and no opinion on
    the pool's lifecycle.
    """

    def __init__(self, pool: ArqRedis) -> None:
        self._pool = pool

    async def enqueue_scan(self, scan_id: str) -> None:
        # scan_id doubles as the arq job id: one job per scan, and it makes
        # a future status lookup (Job(job_id=scan_id, ...)) trivial for M3.3.
        await self._pool.enqueue_job(_RUN_SCAN_JOB, scan_id, _job_id=scan_id)
