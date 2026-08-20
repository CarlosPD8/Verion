from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from verion.modules.scanning.adapters.outbound.db.models import ScanModel, ScanResultModel
from verion.modules.scanning.domain.scan import Scan, ScanStatus
from verion.modules.scanning.domain.scan_result import ScanResult


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
        model.status = str(scan.status)
        model.started_at = scan.started_at
        model.finished_at = scan.finished_at
        model.failure_reason = scan.failure_reason
        await self._session.flush()


def _scan_result_to_domain(model: ScanResultModel) -> ScanResult:
    return ScanResult(
        id=model.id, scan_id=model.scan_id, tool=model.tool, raw_output=model.raw_output
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
                raw_output=scan_result.raw_output,
            )
            .on_conflict_do_update(
                constraint="uq_scan_results_scan_id_tool",
                set_={"raw_output": scan_result.raw_output},
            )
        )
        await self._session.execute(statement)
        await self._session.flush()

    async def get_by_scan_id(self, scan_id: str) -> list[ScanResult]:
        result = await self._session.execute(
            select(ScanResultModel).where(ScanResultModel.scan_id == scan_id)
        )
        return [_scan_result_to_domain(model) for model in result.scalars()]
