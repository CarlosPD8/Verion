from sqlalchemy.ext.asyncio import AsyncSession

from verion.modules.brief.ports.brief_generation_queue import BriefGenerationQueuePort
from verion.platform.db import after_commit


class AfterCommitBriefGenerationQueue:
    """`BriefGenerationQueuePort` that sends the job only after the request's transaction commits.

    `RequestSecurityBriefUseCase` writes the `BriefGeneration` row and then asks for the job,
    inside one transaction it does not own. Enqueued there, a worker could take the job before
    the row is committed, find nothing, and never be retried (ADR-0035 decision 5, **G87**). So
    this defers the real enqueue to `platform/db.py`'s `after_commit`, and the order is commit,
    then enqueue, then the response — which is what makes a 202 mean the row exists and the job
    is queued (ADR-0038 decision 3).

    **This is the SECOND copy of that rule, and it is registered as G99.** `scanning`'s
    `AfterCommitJobQueue` is the first, and this is a retype rather than a reuse — not because
    `cross-module-brief` forbids importing `verion.modules.scanning.adapters`, though it does,
    but because that class is **typed to one port and one method name** (`JobQueuePort`,
    `enqueue_scan`). A module enqueueing anything else could not reuse it whatever the contracts
    said; the contract removes the fallback, it does not create the duplication. G99 carries the
    correction and names `platform/`, beside the `after_commit` hook, as where a generic
    parameterised version would live.
    """

    def __init__(self, inner: BriefGenerationQueuePort, session: AsyncSession) -> None:
        self._inner = inner
        self._session = session

    async def enqueue_brief_generation(self, generation_id: str) -> None:
        async def send() -> None:
            await self._inner.enqueue_brief_generation(generation_id)

        after_commit(self._session, send)
