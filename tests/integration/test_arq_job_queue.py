from arq.connections import RedisSettings, create_pool
from arq.constants import default_queue_name, job_key_prefix

from verion.modules.scanning.adapters.outbound.queue.arq_job_queue import ArqJobQueue
from verion.platform.settings import get_settings


async def test_enqueues_a_scan_job_onto_the_redis_queue():
    pool = await create_pool(RedisSettings.from_dsn(get_settings().redis_url))
    try:
        queue = ArqJobQueue(pool)

        await queue.enqueue_scan("scan-1")

        assert await pool.zscore(default_queue_name, "scan-1") is not None
    finally:
        await pool.delete(job_key_prefix + "scan-1")
        await pool.zrem(default_queue_name, "scan-1")
        await pool.aclose()
