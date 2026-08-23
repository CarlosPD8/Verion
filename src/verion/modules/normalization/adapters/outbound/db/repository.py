from datetime import datetime

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from verion.modules.normalization.adapters.outbound.db.models import NormalizationRunModel
from verion.modules.normalization.domain.normalization_run import (
    NormalizationRun,
    NormalizationRunStatus,
)


def _to_domain(model: NormalizationRunModel) -> NormalizationRun:
    return NormalizationRun(
        id=model.id,
        scan_id=model.scan_id,
        status=NormalizationRunStatus(model.status),
        requested_at=model.requested_at,
        started_at=model.started_at,
        finished_at=model.finished_at,
        failure_reason=model.failure_reason,
    )


class PostgresNormalizationRunRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def request(self, *, id: str, scan_id: str, requested_at: datetime) -> None:
        # Constructed, not written straight from the primitives: this is what
        # makes NormalizationRun.__post_init__ reachable on the production write
        # path, so the invariant genuinely holds in two places rather than only
        # in the CHECK constraint (ADR-0017 decision 1).
        run = NormalizationRun.requested(id=id, scan_id=scan_id, requested_at=requested_at)
        # ON CONFLICT DO NOTHING, and specifically not DO UPDATE: a row already
        # existing means a retry re-requested a run that is already recorded,
        # which is the correct end state either way. DO UPDATE would reset a
        # running/completed row back to pending and re-normalize a scan that was
        # already normalized. The alternative, INSERT + catching IntegrityError,
        # is what ADR-014 rejected for WebhookDeliveryRepository — it leaves the
        # session in a failed-transaction state, which fights worker.py's
        # commit-in-`finally` lifecycle even harder than it fought the
        # request-scoped session's.
        statement = (
            insert(NormalizationRunModel)
            .values(
                id=run.id,
                scan_id=run.scan_id,
                status=str(run.status),
                requested_at=run.requested_at,
                started_at=run.started_at,
                finished_at=run.finished_at,
                failure_reason=run.failure_reason,
            )
            .on_conflict_do_nothing(constraint="uq_normalization_runs_scan_id")
        )
        await self._session.execute(statement)
        # Surfaces a constraint failure here rather than inside worker.py's
        # commit-in-`finally`, which matters for ADR-0017 decision 2's ordering:
        # this write has to fail *before* the Scan is marked COMPLETED.
        await self._session.flush()

    async def get_by_scan_id(self, scan_id: str) -> NormalizationRun | None:
        result = await self._session.execute(
            select(NormalizationRunModel).where(NormalizationRunModel.scan_id == scan_id)
        )
        model = result.scalars().one_or_none()
        return _to_domain(model) if model is not None else None
