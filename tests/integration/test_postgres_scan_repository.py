from datetime import UTC, datetime

from verion.modules.scanning.adapters.outbound.db.repository import PostgresScanRepository
from verion.modules.scanning.domain.scan import Scan, ScanStatus


def _scan(scan_id: str = "scan-1") -> Scan:
    return Scan(
        id=scan_id,
        project_id="project-1",
        status=ScanStatus.PENDING,
        triggered_by="owner-1",
        started_at=None,
        finished_at=None,
    )


async def test_round_trips_a_scan_through_postgres(db_session):
    repository = PostgresScanRepository(db_session)
    scan = _scan()

    await repository.add(scan)

    assert await repository.get_by_id(scan.id) == scan


async def test_round_trips_a_scan_with_timestamps_through_postgres(db_session):
    repository = PostgresScanRepository(db_session)
    scan = Scan(
        id="scan-2",
        project_id="project-1",
        status=ScanStatus.RUNNING,
        triggered_by="owner-1",
        started_at=datetime(2026, 1, 1, tzinfo=UTC),
        finished_at=None,
    )

    await repository.add(scan)

    assert await repository.get_by_id(scan.id) == scan


async def test_get_scan_by_id_returns_none_when_missing(db_session):
    repository = PostgresScanRepository(db_session)

    assert await repository.get_by_id("does-not-exist") is None
