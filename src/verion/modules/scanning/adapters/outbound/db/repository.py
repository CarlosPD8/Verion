from typing import TYPE_CHECKING, Any, cast

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

if TYPE_CHECKING:
    from sqlalchemy import CursorResult

from verion.modules.scanning.adapters.outbound.db.models import (
    ScanModel,
    ScanResultModel,
    WebhookDeliveryModel,
)
from verion.modules.scanning.domain.exceptions import ScanNotFound
from verion.modules.scanning.domain.scan import Scan, ScanStatus
from verion.modules.scanning.domain.scan_result import ScanResult, ScanResultStatus


def _scan_to_domain(model: ScanModel) -> Scan:
    return Scan(
        id=model.id,
        project_id=model.project_id,
        status=ScanStatus(model.status),
        triggered_by=model.triggered_by,
        started_at=model.started_at,
        finished_at=model.finished_at,
        failure_reason=model.failure_reason,
    )


def _scan_from_domain(scan: Scan) -> ScanModel:
    return ScanModel(
        id=scan.id,
        project_id=scan.project_id,
        status=str(scan.status),
        triggered_by=scan.triggered_by,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        failure_reason=scan.failure_reason,
    )


class PostgresScanRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, scan: Scan) -> None:
        self._session.add(_scan_from_domain(scan))
        await self._session.flush()

    async def get_by_id(self, scan_id: str) -> Scan | None:
        model = await self._session.get(ScanModel, scan_id)
        return _scan_to_domain(model) if model is not None else None

    async def update(self, scan: Scan) -> None:
        model = await self._session.get(ScanModel, scan.id)
        if model is None:
            # Not defensive padding: RunScanUseCase's failure path calls update()
            # to persist FAILED + failure_reason. Dereferencing None here would
            # raise an opaque AttributeError *from inside the failure handler*,
            # masking the original exception it was trying to record — the exact
            # persisted-failure visibility M3.3 was built to protect.
            raise ScanNotFound(f"No scan with id '{scan.id}'")
        model.status = str(scan.status)
        model.started_at = scan.started_at
        model.finished_at = scan.finished_at
        model.failure_reason = scan.failure_reason
        await self._session.flush()


def _scan_result_to_domain(model: ScanResultModel) -> ScanResult:
    return ScanResult(
        id=model.id,
        scan_id=model.scan_id,
        tool=model.tool,
        status=ScanResultStatus(model.status),
        raw_output=model.raw_output,
        failure_reason=model.failure_reason,
    )


class PostgresScanResultRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def upsert(self, scan_result: ScanResult) -> None:
        # ON CONFLICT DO UPDATE on the (scan_id, tool) unique constraint —
        # this is the concrete mechanism behind the worker's retry-safety
        # guarantee: a redelivered job re-running the same tool overwrites
        # its own prior row instead of accumulating a duplicate.
        statement = (
            insert(ScanResultModel)
            .values(
                id=scan_result.id,
                scan_id=scan_result.scan_id,
                tool=scan_result.tool,
                status=str(scan_result.status),
                raw_output=scan_result.raw_output,
                failure_reason=scan_result.failure_reason,
            )
            .on_conflict_do_update(
                constraint="uq_scan_results_scan_id_tool",
                # All three together, never raw_output alone: a retry that
                # turns a previously-succeeding tool into a failing one would
                # otherwise leave the old output sitting under a FAILED status,
                # which the table's CHECK constraint forbids anyway — it would
                # fail loudly, but only after the write was already wrong.
                set_={
                    "status": str(scan_result.status),
                    "raw_output": scan_result.raw_output,
                    "failure_reason": scan_result.failure_reason,
                },
            )
        )
        await self._session.execute(statement)
        await self._session.flush()

    async def get_by_scan_id(self, scan_id: str) -> list[ScanResult]:
        result = await self._session.execute(
            select(ScanResultModel).where(ScanResultModel.scan_id == scan_id)
        )
        return [_scan_result_to_domain(model) for model in result.scalars()]

    async def get_succeeded_by_scan_id(self, scan_id: str) -> list[ScanResult]:
        # Filtered in SQL, not in Python after get_by_scan_id: this is M4's
        # entry point, and it should not have to pull a failed scanner's row
        # across the wire to discard it.
        result = await self._session.execute(
            select(ScanResultModel).where(
                ScanResultModel.scan_id == scan_id,
                ScanResultModel.status == str(ScanResultStatus.SUCCEEDED),
            )
        )
        return [_scan_result_to_domain(model) for model in result.scalars()]


class PostgresWebhookDeliveryRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def record_if_new(self, delivery_id: str) -> bool:
        # ON CONFLICT DO NOTHING + rowcount, not INSERT + catch IntegrityError:
        # an IntegrityError puts the session in a failed-transaction state
        # that needs its own rollback before the caller's session can be
        # reused, which would fight the request-scoped session's own
        # commit/rollback lifecycle (platform/db.py's get_db_session). This
        # stays race-safe on the same unique-constraint mechanism without
        # that entanglement.
        statement = (
            insert(WebhookDeliveryModel)
            .values(delivery_id=delivery_id)
            .on_conflict_do_nothing(index_elements=["delivery_id"])
        )
        result = await self._session.execute(statement)
        await self._session.flush()
        # session.execute() is typed as returning Result[Any], which doesn't
        # declare rowcount — it's on CursorResult, the concrete type a DML
        # statement actually returns at runtime. A typing gap in SQLAlchemy's
        # overloads, not a wrong call.
        return bool(cast("CursorResult[Any]", result).rowcount == 1)
