from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from verion.modules.scanning.adapters.outbound.db.repository import (
    PostgresScanRepository,
    PostgresScanResultRepository,
)
from verion.modules.scanning.domain.scan import Scan, ScanStatus
from verion.modules.scanning.domain.scan_result import ScanResult, ScanResultStatus


async def _seed_scan(db_session, run_id: str) -> Scan:
    scan = Scan(
        id=f"scan-results-{run_id}",
        project_id=f"project-results-{run_id}",
        status=ScanStatus.RUNNING,
        triggered_by=f"owner-results-{run_id}",
        started_at=datetime.now(UTC),
        finished_at=None,
        failure_reason=None,
    )
    await PostgresScanRepository(db_session).add(scan)
    return scan


async def test_round_trips_a_succeeded_and_a_failed_result(db_session):
    run_id = uuid4().hex[:12]
    scan = await _seed_scan(db_session, run_id)
    repository = PostgresScanResultRepository(db_session)
    succeeded = ScanResult.succeeded(
        id=f"r1-{run_id}", scan_id=scan.id, tool="semgrep", raw_output='{"results": []}'
    )
    failed = ScanResult.failed(
        id=f"r2-{run_id}", scan_id=scan.id, tool="zap", failure_reason="timed out"
    )

    await repository.upsert(succeeded)
    await repository.upsert(failed)

    stored = {result.tool: result for result in await repository.get_by_scan_id(scan.id)}
    assert stored["semgrep"] == succeeded
    assert stored["zap"] == failed


async def test_get_succeeded_excludes_the_failed_rows(db_session):
    """M4's entry point, filtered in SQL. The failed row is still present via
    get_by_scan_id — excluded from this query, not deleted."""
    run_id = uuid4().hex[:12]
    scan = await _seed_scan(db_session, run_id)
    repository = PostgresScanResultRepository(db_session)
    await repository.upsert(
        ScanResult.succeeded(id=f"r1-{run_id}", scan_id=scan.id, tool="semgrep", raw_output="{}")
    )
    await repository.upsert(
        ScanResult.failed(id=f"r2-{run_id}", scan_id=scan.id, tool="trivy", failure_reason="boom")
    )

    trustworthy = await repository.get_succeeded_by_scan_id(scan.id)

    assert [result.tool for result in trustworthy] == ["semgrep"]
    assert all(result.raw_output is not None for result in trustworthy)
    assert len(await repository.get_by_scan_id(scan.id)) == 2


async def test_a_retry_that_turns_success_into_failure_clears_the_stale_output(db_session):
    """The reason the upsert writes status/raw_output/failure_reason together.

    Updating raw_output alone would leave the previous run's output sitting
    under a FAILED status — a row M4 would read as trustworthy-looking data
    attached to a tool that just failed.
    """
    run_id = uuid4().hex[:12]
    scan = await _seed_scan(db_session, run_id)
    repository = PostgresScanResultRepository(db_session)
    await repository.upsert(
        ScanResult.succeeded(
            id=f"r1-{run_id}", scan_id=scan.id, tool="semgrep", raw_output='{"old": true}'
        )
    )

    await repository.upsert(
        ScanResult.failed(
            id=f"r2-{run_id}", scan_id=scan.id, tool="semgrep", failure_reason="now failing"
        )
    )

    results = await repository.get_by_scan_id(scan.id)
    # Upsert on (scan_id, tool): one row, not two.
    assert len(results) == 1
    assert results[0].status is ScanResultStatus.FAILED
    assert results[0].raw_output is None
    assert results[0].failure_reason == "now failing"
    assert await repository.get_succeeded_by_scan_id(scan.id) == []


# The domain dataclass rejects these shapes too (test_scan_result.py). These
# two go around it with raw SQL on purpose: the CHECK constraint is what makes
# get_succeeded_by_scan_id's non-null-raw_output guarantee true for *any*
# writer, not just for code that happens to construct a ScanResult first —
# which is the premise M4's mappers will be typed against.


async def test_the_database_rejects_a_succeeded_row_without_output(db_session):
    run_id = uuid4().hex[:12]
    scan = await _seed_scan(db_session, run_id)
    await db_session.flush()

    with pytest.raises(IntegrityError, match="ck_scan_results_outcome_shape"):
        await db_session.execute(
            text(
                "INSERT INTO scan_results (id, scan_id, tool, status, raw_output, failure_reason)"
                " VALUES (:id, :scan_id, 'semgrep', 'succeeded', NULL, NULL)"
            ),
            {"id": f"bad1-{run_id}", "scan_id": scan.id},
        )
    await db_session.rollback()


async def test_the_database_rejects_a_failed_row_carrying_output(db_session):
    run_id = uuid4().hex[:12]
    scan = await _seed_scan(db_session, run_id)
    await db_session.flush()

    with pytest.raises(IntegrityError, match="ck_scan_results_outcome_shape"):
        await db_session.execute(
            text(
                "INSERT INTO scan_results (id, scan_id, tool, status, raw_output, failure_reason)"
                " VALUES (:id, :scan_id, 'zap', 'failed', '{}', 'boom')"
            ),
            {"id": f"bad2-{run_id}", "scan_id": scan.id},
        )
    await db_session.rollback()
