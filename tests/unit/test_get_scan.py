"""`GetScanUseCase` — two gates, in order (ADR-0035 decision 4).

The verdict runs before the repository is read, and the scan must belong to the path's
project. Each test names the mutation it kills.
"""

from datetime import UTC, datetime

import pytest

from verion.modules.scanning.application.get_scan import GetScanUseCase
from verion.modules.scanning.domain.exceptions import ProjectAccessDenied, ScanNotFound
from verion.modules.scanning.domain.scan import Scan, ScanStatus

_PROJECT = "project-1"
_OTHER_PROJECT = "project-2"
_USER = "user-1"


class _ExplodingScanRepository:
    """Every read raises. Proves the verdict ran BEFORE the repository was touched, on
    `ExplodingFindingRepository`'s precedent."""

    async def add(self, scan: Scan) -> None:
        raise AssertionError("the repository was written")

    async def get_by_id(self, scan_id: str) -> Scan | None:
        raise AssertionError("the repository was read before authorization")

    async def update(self, scan: Scan) -> None:
        raise AssertionError("the repository was written")


def _scan(scan_id: str, project_id: str) -> Scan:
    return Scan(
        id=scan_id,
        project_id=project_id,
        status=ScanStatus.FAILED,
        triggered_by="owner-1",
        started_at=datetime(2026, 1, 1, tzinfo=UTC),
        finished_at=datetime(2026, 1, 1, tzinfo=UTC),
        failure_reason="No GitHub connection for user 'owner-1'",
    )


async def test_a_reader_gets_the_scan(project_access, scan_repository):
    project_access.permit(_PROJECT, _USER)
    await scan_repository.add(_scan("scan-1", _PROJECT))

    scan = await GetScanUseCase(project_access, scan_repository).execute(
        project_id=_PROJECT, user_id=_USER, scan_id="scan-1"
    )

    assert scan.id == "scan-1"
    assert scan.failure_reason == "No GitHub connection for user 'owner-1'"


async def test_a_non_reader_is_refused_before_the_repository_is_read(project_access):
    """Kills the verdict moved below the read: the exploding repository would raise first."""
    with pytest.raises(ProjectAccessDenied):
        await GetScanUseCase(project_access, _ExplodingScanRepository()).execute(
            project_id=_PROJECT, user_id=_USER, scan_id="scan-1"
        )


async def test_a_scan_of_another_project_is_not_found(project_access, scan_repository):
    """A reader of project 1 asking for project 2's scan through project 1's path. Kills a
    deleted project-match check, which would return the other project's scan."""
    project_access.permit(_PROJECT, _USER)
    await scan_repository.add(_scan("scan-2", _OTHER_PROJECT))

    with pytest.raises(ScanNotFound):
        await GetScanUseCase(project_access, scan_repository).execute(
            project_id=_PROJECT, user_id=_USER, scan_id="scan-2"
        )


async def test_an_absent_scan_is_not_found(project_access, scan_repository):
    project_access.permit(_PROJECT, _USER)

    with pytest.raises(ScanNotFound):
        await GetScanUseCase(project_access, scan_repository).execute(
            project_id=_PROJECT, user_id=_USER, scan_id="scan-absent"
        )
