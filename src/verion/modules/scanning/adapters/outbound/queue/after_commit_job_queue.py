from sqlalchemy.ext.asyncio import AsyncSession

from verion.modules.scanning.ports.job_queue import JobQueuePort
from verion.platform.db import after_commit


class AfterCommitJobQueue:
    """`JobQueuePort` that sends a scan's job only after the request's transaction commits.

    `TriggerScanUseCase` writes the `Scan` and then enqueues, inside one transaction it does
    not own. Enqueued there, a worker could take the job before the row is committed, find
    no scan, raise, and never be retried (ADR-0035 decision 5, G87). So this adapter defers
    the real enqueue to `platform/db.py`'s `after_commit`, on `platform/worker.py`'s
    normalization-handoff precedent: enqueue after the commit, in the layer that owns it.

    With the session function-scoped (ADR-0008's M8.8 amendment) the order is commit, then
    enqueue, then the response, so a 202 means the row exists and the job is queued.
    """

    def __init__(self, inner: JobQueuePort, session: AsyncSession) -> None:
        self._inner = inner
        self._session = session

    async def enqueue_scan(self, scan_id: str) -> None:
        async def send() -> None:
            await self._inner.enqueue_scan(scan_id)

        after_commit(self._session, send)
