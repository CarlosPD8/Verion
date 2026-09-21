from arq.connections import ArqRedis

# The arq job name, which arq matches on rather than on Python identity — it must stay identical
# to `platform/worker.py`'s `generate_brief` function name, the same coupling `ArqJobQueue` and
# `ArqNormalizationQueue` both document.
_GENERATE_BRIEF_JOB = "generate_brief"

# The job-id prefix, load-bearing for `ArqNormalizationQueue`'s reason. `ArqJobQueue.enqueue_scan`
# uses a BARE `scan_id` as its job id, so every id in this project's single arq keyspace that is
# not prefixed is competing with scan ids. A generation id is a fresh UUID and would not collide
# in practice, but "would not collide in practice" is the kind of invariant nothing checks, and
# the prefix costs one string.
_JOB_ID_PREFIX = "brief:"


class ArqBriefGenerationQueue:
    """Wraps an already-created arq pool — never creates one itself.

    Same shape and same reasoning as `ArqJobQueue` and `ArqNormalizationQueue`: pool
    creation and closing is the caller's responsibility, so this adapter has no lazy-init race
    and no opinion on the pool's lifecycle.

    **This is the project's THIRD such wrapper**, and the duplication is noted in **G99** rather
    than fixed here. It is not that entry's subject — these carry no invariant, unlike
    `AfterCommitJobQueue`, which is why G99 names them and is about the other one.
    """

    def __init__(self, pool: ArqRedis) -> None:
        self._pool = pool

    async def enqueue_brief_generation(self, generation_id: str) -> None:
        # One job per generation, deduplicated by id. A repeat POST mints a NEW generation id
        # (ADR-0033 decision 3 makes it a regeneration, not a no-op), so this dedup never
        # collapses two legitimate requests — it only absorbs a redelivery of one.
        await self._pool.enqueue_job(
            _GENERATE_BRIEF_JOB, generation_id, _job_id=f"{_JOB_ID_PREFIX}{generation_id}"
        )
