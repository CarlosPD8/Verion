from typing import Any

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from verion.modules.history.adapters.outbound.db.models import RiskEventModel, RiskModel
from verion.modules.history.domain.risk import (
    Risk,
    RiskDismissal,
    RiskEvent,
    RiskEventKind,
    Snapshot,
)


def _latest_events(project_id: str) -> Any:
    """Each of the project's records' highest-ordinal event, as a subquery.

    `DISTINCT ON (risk_id)` ordered by `ordinal DESC`, on `uq_risk_events_risk_id_ordinal`'s
    index. The ordinal, never `occurred_at`, decides which event is latest (ADR-0036 decision 7).
    """
    return (
        select(RiskEventModel)
        .join(RiskModel, RiskModel.id == RiskEventModel.risk_id)
        .where(RiskModel.project_id == project_id)
        .distinct(RiskEventModel.risk_id)
        .order_by(RiskEventModel.risk_id, RiskEventModel.ordinal.desc())
        .subquery("latest")
    )


def _risk(model: RiskModel) -> Risk:
    return Risk(id=model.id, project_id=model.project_id, finding_ids=tuple(model.finding_ids))


def _event(model: RiskEventModel) -> RiskEvent:
    return RiskEvent(
        id=model.id,
        risk_id=model.risk_id,
        ordinal=model.ordinal,
        # Reconstructed at the boundary, never left a bare str.
        kind=RiskEventKind(model.kind),
        actor_user_id=model.actor_user_id,
        reason=model.reason,
        occurred_at=model.occurred_at,
    )


class PostgresRiskDismissalRepository:
    """`RiskDismissalRepositoryPort` over Postgres. Flushes, never commits: the request's
    session does (`platform/db.py`).

    **Two statements write, and neither ever updates a row.** `add` inserts a record and its
    first event. `append_event` inserts one event, or nothing. That is **G37**'s resolution in
    this adapter's terms: there is no `SET` clause for user state to be clobbered by.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, risk: Risk, first_event: RiskEvent) -> None:
        self._session.add(
            RiskModel(id=risk.id, project_id=risk.project_id, finding_ids=list(risk.finding_ids))
        )
        # The record first, so the event's foreign key is satisfied.
        await self._session.flush()
        self._session.add(self._event_model(first_event))
        await self._session.flush()

    async def append_event(self, event: RiskEvent) -> bool:
        # ON CONFLICT DO NOTHING rather than catching IntegrityError, which would leave the
        # session in a failed transaction (ADR-0014, ADR-0017). No row back means the ordinal
        # was taken by a concurrent append.
        result = await self._session.execute(
            insert(RiskEventModel)
            .values(
                id=event.id,
                risk_id=event.risk_id,
                ordinal=event.ordinal,
                kind=str(event.kind),
                actor_user_id=event.actor_user_id,
                reason=event.reason,
                occurred_at=event.occurred_at,
            )
            .on_conflict_do_nothing(constraint="uq_risk_events_risk_id_ordinal")
            .returning(RiskEventModel.id)
        )
        return result.scalar_one_or_none() is not None

    async def get(self, *, project_id: str, risk_id: str) -> RiskDismissal | None:
        record = (
            await self._session.execute(
                select(RiskModel).where(RiskModel.id == risk_id, RiskModel.project_id == project_id)
            )
        ).scalar_one_or_none()
        if record is None:
            return None
        latest = (
            await self._session.execute(
                select(RiskEventModel)
                .where(RiskEventModel.risk_id == risk_id)
                .order_by(RiskEventModel.ordinal.desc())
                .limit(1)
            )
        ).scalar_one()
        return RiskDismissal(risk=_risk(record), latest=_event(latest))

    async def snapshots_for_project(self, project_id: str) -> list[Snapshot]:
        latest = aliased(RiskEventModel, _latest_events(project_id))
        rows = await self._session.execute(
            select(RiskModel.id, RiskModel.finding_ids, latest.kind, latest.occurred_at).join(
                latest, latest.risk_id == RiskModel.id
            )
        )
        return [
            Snapshot(
                risk_id=risk_id,
                finding_ids=tuple(finding_ids),
                state=RiskEventKind(kind),
                state_since=occurred_at,
            )
            for risk_id, finding_ids, kind, occurred_at in rows
        ]

    async def list_for_project(
        self, *, project_id: str, limit: int, offset: int
    ) -> list[RiskDismissal]:
        latest = aliased(RiskEventModel, _latest_events(project_id))
        first = aliased(RiskEventModel)
        rows = await self._session.execute(
            select(RiskModel, latest)
            .join(latest, latest.risk_id == RiskModel.id)
            .join(first, (first.risk_id == RiskModel.id) & (first.ordinal == 1))
            .where(RiskModel.project_id == project_id)
            # Newest dismissal first. `risks` has no timestamp of its own, so the order is the
            # first event's; `id` after it makes the order total across pages.
            .order_by(first.occurred_at.desc(), RiskModel.id.asc())
            .limit(limit)
            .offset(offset)
        )
        return [RiskDismissal(risk=_risk(record), latest=_event(event)) for record, event in rows]

    async def count_for_project(self, project_id: str) -> int:
        result = await self._session.execute(
            select(func.count()).select_from(RiskModel).where(RiskModel.project_id == project_id)
        )
        return result.scalar_one()

    @staticmethod
    def _event_model(event: RiskEvent) -> RiskEventModel:
        return RiskEventModel(
            id=event.id,
            risk_id=event.risk_id,
            ordinal=event.ordinal,
            kind=str(event.kind),
            actor_user_id=event.actor_user_id,
            reason=event.reason,
            occurred_at=event.occurred_at,
        )
