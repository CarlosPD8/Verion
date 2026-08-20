from sqlalchemy.ext.asyncio import AsyncSession

from verion.modules.scanning.adapters.outbound.db.models import ScanModel
from verion.modules.scanning.domain.scan import Scan, ScanStatus


def _scan_to_domain(model: ScanModel) -> Scan:
    return Scan(
        id=model.id,
        project_id=model.project_id,
        status=ScanStatus(model.status),
        triggered_by=model.triggered_by,
        started_at=model.started_at,
        finished_at=model.finished_at,
    )


def _scan_from_domain(scan: Scan) -> ScanModel:
    return ScanModel(
        id=scan.id,
        project_id=scan.project_id,
        status=str(scan.status),
        triggered_by=scan.triggered_by,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
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
