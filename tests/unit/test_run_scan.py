from datetime import UTC, datetime

import pytest

from verion.modules.identity.domain.github_connection import GitHubConnection
from verion.modules.projects.domain.project import ConnectedRepo
from verion.modules.scanning.application.run_scan import RunScanUseCase
from verion.modules.scanning.domain.exceptions import (
    ConnectedRepoNotFound,
    GitHubConnectionNotFound,
    RepoCheckoutFailed,
    ScannerExecutionFailed,
    UnsupportedRepoProvider,
)
from verion.modules.scanning.domain.scan import Scan, ScanStatus
from verion.modules.scanning.domain.scan_result import ScanResult

_PROJECT_ID = "project-1"
_SCAN_ID = "scan-1"
_OWNER_ID = "owner-1"
_REPO_URL = "https://github.com/acme/widgets"
_ACCESS_TOKEN = "gh-token-1"


def _use_case(
    scan_repository,
    scan_result_repository,
    scanner,
    repo_checkout,
    connected_repo_repository,
    github_connection_repository,
    id_generator,
    clock,
) -> RunScanUseCase:
    return RunScanUseCase(
        scans=scan_repository,
        scan_results=scan_result_repository,
        scanner=scanner,
        repo_checkout=repo_checkout,
        connected_repos=connected_repo_repository,
        github_connections=github_connection_repository,
        id_generator=id_generator,
        clock=clock,
    )


def _pending_scan(scan_id: str = _SCAN_ID) -> Scan:
    return Scan(
        id=scan_id,
        project_id=_PROJECT_ID,
        status=ScanStatus.PENDING,
        triggered_by=_OWNER_ID,
        started_at=None,
        finished_at=None,
        failure_reason=None,
    )


def _connected_repo(provider: str = "github") -> ConnectedRepo:
    return ConnectedRepo(
        id="repo-1", project_id=_PROJECT_ID, provider=provider, url=_REPO_URL, default_branch="main"
    )


def _github_connection() -> GitHubConnection:
    return GitHubConnection(
        user_id=_OWNER_ID,
        access_token=_ACCESS_TOKEN,
        github_username="acme-owner",
        connected_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


async def _seed(scan_repository, connected_repo_repository, github_connection_repository, scan):
    await scan_repository.add(scan)
    await connected_repo_repository.add(_connected_repo())
    await github_connection_repository.add(_github_connection())


async def test_successful_scan_completes_and_persists_a_scan_result(
    scan_repository,
    scan_result_repository,
    scanner,
    repo_checkout,
    connected_repo_repository,
    github_connection_repository,
    id_generator,
    clock,
):
    scan = _pending_scan()
    await _seed(scan_repository, connected_repo_repository, github_connection_repository, scan)
    use_case = _use_case(
        scan_repository,
        scan_result_repository,
        scanner,
        repo_checkout,
        connected_repo_repository,
        github_connection_repository,
        id_generator,
        clock,
    )

    await use_case.execute(_SCAN_ID)

    updated = await scan_repository.get_by_id(_SCAN_ID)
    assert updated.status is ScanStatus.COMPLETED
    assert updated.started_at == clock.now()
    assert updated.finished_at == clock.now()
    assert updated.failure_reason is None
    results = await scan_result_repository.get_by_scan_id(_SCAN_ID)
    assert len(results) == 1
    assert results[0].tool == "semgrep"
    assert repo_checkout.cleanup_calls == [repo_checkout.local_path]


async def test_checkout_failure_marks_the_scan_failed(
    scan_repository,
    scan_result_repository,
    scanner,
    repo_checkout_factory,
    connected_repo_repository,
    github_connection_repository,
    id_generator,
    clock,
):
    scan = _pending_scan()
    await _seed(scan_repository, connected_repo_repository, github_connection_repository, scan)
    repo_checkout = repo_checkout_factory(fail=True)
    use_case = _use_case(
        scan_repository,
        scan_result_repository,
        scanner,
        repo_checkout,
        connected_repo_repository,
        github_connection_repository,
        id_generator,
        clock,
    )

    with pytest.raises(RepoCheckoutFailed, match="simulated checkout failure"):
        await use_case.execute(_SCAN_ID)

    updated = await scan_repository.get_by_id(_SCAN_ID)
    assert updated.status is ScanStatus.FAILED
    assert updated.failure_reason == "simulated checkout failure"
    assert await scan_result_repository.get_by_scan_id(_SCAN_ID) == []


async def test_scanner_failure_marks_the_scan_failed(
    scan_repository,
    scan_result_repository,
    scanner_factory,
    repo_checkout,
    connected_repo_repository,
    github_connection_repository,
    id_generator,
    clock,
):
    scan = _pending_scan()
    await _seed(scan_repository, connected_repo_repository, github_connection_repository, scan)
    scanner = scanner_factory(fail=True)
    use_case = _use_case(
        scan_repository,
        scan_result_repository,
        scanner,
        repo_checkout,
        connected_repo_repository,
        github_connection_repository,
        id_generator,
        clock,
    )

    with pytest.raises(ScannerExecutionFailed, match="simulated scanner failure"):
        await use_case.execute(_SCAN_ID)

    updated = await scan_repository.get_by_id(_SCAN_ID)
    assert updated.status is ScanStatus.FAILED
    assert updated.failure_reason == "simulated scanner failure"
    # cleanup still runs even though the scan failed after a successful checkout.
    assert repo_checkout.cleanup_calls == [repo_checkout.local_path]


async def test_missing_connected_repo_marks_the_scan_failed(
    scan_repository,
    scan_result_repository,
    scanner,
    repo_checkout,
    connected_repo_repository,
    github_connection_repository,
    id_generator,
    clock,
):
    scan = _pending_scan()
    await scan_repository.add(scan)
    # No connected repo, no github connection seeded.
    use_case = _use_case(
        scan_repository,
        scan_result_repository,
        scanner,
        repo_checkout,
        connected_repo_repository,
        github_connection_repository,
        id_generator,
        clock,
    )

    with pytest.raises(ConnectedRepoNotFound, match="No connected repo"):
        await use_case.execute(_SCAN_ID)

    updated = await scan_repository.get_by_id(_SCAN_ID)
    assert updated.status is ScanStatus.FAILED
    assert repo_checkout.checkout_calls == []


async def test_missing_github_connection_marks_the_scan_failed(
    scan_repository,
    scan_result_repository,
    scanner,
    repo_checkout,
    connected_repo_repository,
    github_connection_repository,
    id_generator,
    clock,
):
    scan = _pending_scan()
    await scan_repository.add(scan)
    await connected_repo_repository.add(_connected_repo())
    # No github connection seeded for the owner.
    use_case = _use_case(
        scan_repository,
        scan_result_repository,
        scanner,
        repo_checkout,
        connected_repo_repository,
        github_connection_repository,
        id_generator,
        clock,
    )

    with pytest.raises(GitHubConnectionNotFound, match="No GitHub connection"):
        await use_case.execute(_SCAN_ID)

    updated = await scan_repository.get_by_id(_SCAN_ID)
    assert updated.status is ScanStatus.FAILED
    assert repo_checkout.checkout_calls == []


async def test_unsupported_provider_marks_the_scan_failed(
    scan_repository,
    scan_result_repository,
    scanner,
    repo_checkout,
    connected_repo_repository,
    github_connection_repository,
    id_generator,
    clock,
):
    scan = _pending_scan()
    await scan_repository.add(scan)
    await connected_repo_repository.add(_connected_repo(provider="gitlab"))
    await github_connection_repository.add(_github_connection())
    use_case = _use_case(
        scan_repository,
        scan_result_repository,
        scanner,
        repo_checkout,
        connected_repo_repository,
        github_connection_repository,
        id_generator,
        clock,
    )

    with pytest.raises(UnsupportedRepoProvider, match="not 'github'"):
        await use_case.execute(_SCAN_ID)

    updated = await scan_repository.get_by_id(_SCAN_ID)
    assert updated.status is ScanStatus.FAILED
    assert repo_checkout.checkout_calls == []


async def test_redelivered_after_completed_is_a_no_op(
    scan_repository,
    scan_result_repository,
    scanner,
    repo_checkout,
    connected_repo_repository,
    github_connection_repository,
    id_generator,
    clock,
):
    scan = _pending_scan()
    await _seed(scan_repository, connected_repo_repository, github_connection_repository, scan)
    use_case = _use_case(
        scan_repository,
        scan_result_repository,
        scanner,
        repo_checkout,
        connected_repo_repository,
        github_connection_repository,
        id_generator,
        clock,
    )
    await use_case.execute(_SCAN_ID)
    assert len(scanner.run_calls) == 1

    # Redelivery of the same (already-succeeded) job.
    await use_case.execute(_SCAN_ID)

    assert scanner.run_calls == [repo_checkout.local_path]
    assert repo_checkout.checkout_calls == [_REPO_URL]


async def test_retry_after_crash_between_upsert_and_completed_redoes_real_work(
    scan_repository,
    scan_result_repository,
    scanner,
    repo_checkout,
    connected_repo_repository,
    github_connection_repository,
    id_generator,
    clock,
):
    """The worst-case retry window: a crash after ScanResult was upserted but
    before Scan was marked COMPLETED. Pre-seeds exactly that state (RUNNING,
    started_at already set, finished_at still None, a ScanResult already
    present for (scan_id, "semgrep")) rather than a clean PENDING retry —
    which is the trivial first-attempt case already covered above.
    """
    started_at = datetime(2026, 1, 1, tzinfo=UTC)
    scan = Scan(
        id=_SCAN_ID,
        project_id=_PROJECT_ID,
        status=ScanStatus.RUNNING,
        triggered_by=_OWNER_ID,
        started_at=started_at,
        finished_at=None,
        failure_reason=None,
    )
    await _seed(scan_repository, connected_repo_repository, github_connection_repository, scan)
    await scan_result_repository.upsert(
        ScanResult(id="pre-existing-id", scan_id=_SCAN_ID, tool="semgrep", raw_output="{}")
    )
    use_case = _use_case(
        scan_repository,
        scan_result_repository,
        scanner,
        repo_checkout,
        connected_repo_repository,
        github_connection_repository,
        id_generator,
        clock,
    )

    await use_case.execute(_SCAN_ID)

    # Real work was redone, not skipped — the accepted MVP trade-off.
    assert len(repo_checkout.checkout_calls) == 1
    assert len(scanner.run_calls) == 1

    updated = await scan_repository.get_by_id(_SCAN_ID)
    assert updated.status is ScanStatus.COMPLETED
    # started_at is preserved from the original attempt, not overwritten.
    assert updated.started_at == started_at
    assert updated.finished_at == clock.now()

    # Upsert, not insert: still exactly one row for (scan_id, "semgrep").
    results = await scan_result_repository.get_by_scan_id(_SCAN_ID)
    assert len(results) == 1
