from arq.connections import ArqRedis

# The arq job name, which arq matches on rather than on Python identity — it must
# stay identical to `platform/worker.py`'s `normalize_scan` function name, the
# same coupling ArqJobQueue documents for `run_scan`.
_NORMALIZE_SCAN_JOB = "normalize_scan"

# The job-id prefix, and it is load-bearing rather than decoration.
# `ArqJobQueue.enqueue_scan` already uses the BARE `scan_id` as its job id, so an
# unprefixed id here would collide with the scan's own job: arq refuses to
# enqueue a job whose id already exists, and normalization would be silently
# dropped for every scan — recovered only by the sweep, fifteen minutes late,
# forever.
_JOB_ID_PREFIX = "normalize:"


class ArqNormalizationQueue:
    """Wraps an already-created arq pool — never creates one itself.

    Same shape and same reasoning as `ArqJobQueue`, with one difference in where
    the pool comes from: this adapter is constructed inside the *worker* process,
    where arq injects its own pool as `ctx["redis"]`. The worker has no
    `app.state.arq_redis` — that belongs to the API process — so a pool created
    here would be a second connection pool per job.
    """

    def __init__(self, pool: ArqRedis) -> None:
        self._pool = pool

    async def enqueue_normalization(self, scan_id: str) -> None:
        # One job per scan, deduplicated by id. That is what makes the sweep safe
        # to run against work that is already queued or in flight: re-enqueuing an
        # existing job id is a no-op rather than a second run, which is the first
        # of the three things stopping a sweep from racing a live job (ADR-0021).
        await self._pool.enqueue_job(
            _NORMALIZE_SCAN_JOB, scan_id, _job_id=f"{_JOB_ID_PREFIX}{scan_id}"
        )
