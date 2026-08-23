from datetime import UTC, datetime

import pytest

from verion.modules.identity.domain.github_connection import GitHubConnection
from verion.modules.normalization.domain.normalization_run import NormalizationRunStatus
from verion.modules.projects.domain.project import ConnectedRepo
from verion.modules.projects.domain.scanner_config import ScannerConfig
from verion.modules.scanning.application.run_scan import RunScanUseCase
from verion.modules.scanning.domain.exceptions import (
    ConnectedRepoNotFound,
    GitHubConnectionNotFound,
    NoScannersEnabled,
    RepoCheckoutFailed,
    UnknownScanner,
    UnsupportedRepoProvider,
)
from verion.modules.scanning.domain.raw_scan_result import RawScanResult
from verion.modules.scanning.domain.scan import Scan, ScanStatus
from verion.modules.scanning.domain.scan_result import ScanResult, ScanResultStatus
from verion.modules.scanning.domain.scanner_target_kind import ScannerTargetKind
from verion.shared_kernel.scanner_tools import ScannerTool

_PROJECT_ID = "project-1"
_SCAN_ID = "scan-1"
_OWNER_ID = "owner-1"
_REPO_URL = "https://github.com/acme/widgets"
_ACCESS_TOKEN = "gh-token-1"
_ZAP_TARGET = "https://staging.acme.example"


def _use_case(
    scan_repository,
    scan_result_repository,
    scanners,
    repo_checkout,
    connected_repo_repository,
    github_connection_repository,
    scanner_config_repository,
    normalization_runs,
    id_generator,
    clock,
) -> RunScanUseCase:
    return RunScanUseCase(
        scans=scan_repository,
        scan_results=scan_result_repository,
        scanners=scanners,
        repo_checkout=repo_checkout,
        connected_repos=connected_repo_repository,
        github_connections=github_connection_repository,
        scanner_configs=scanner_config_repository,
        normalization_runs=normalization_runs,
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


def _config(
    enabled_tools: tuple[ScannerTool, ...] = (ScannerTool.SEMGREP,),
    zap_target_url: str | None = None,
) -> ScannerConfig:
    return ScannerConfig(
        id="config-1",
        project_id=_PROJECT_ID,
        enabled_tools=enabled_tools,
        zap_target_url=zap_target_url,
        updated_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


async def _seed(
    scan_repository,
    connected_repo_repository,
    github_connection_repository,
    scan,
    scanner_config_repository=None,
    config=None,
):
    """Seeds the happy-path prerequisites.

    `config` defaults to Semgrep-only rather than to "unconfigured": most tests
    here are about one scanner's behaviour, and leaving it unconfigured would
    silently opt them into the Semgrep+Trivy default and require every one of
    them to register a Trivy fake. The default path has its own test below.
    """
    await scan_repository.add(scan)
    await connected_repo_repository.add(_connected_repo())
    await github_connection_repository.add(_github_connection())
    if scanner_config_repository is not None:
        await scanner_config_repository.upsert(config if config is not None else _config())


async def test_successful_scan_completes_and_persists_a_scan_result(
    scan_repository,
    scan_result_repository,
    scanner,
    scanners,
    repo_checkout,
    connected_repo_repository,
    github_connection_repository,
    scanner_config_repository,
    normalization_run_repository,
    id_generator,
    clock,
):
    scan = _pending_scan()
    await _seed(
        scan_repository,
        connected_repo_repository,
        github_connection_repository,
        scan,
        scanner_config_repository,
    )
    use_case = _use_case(
        scan_repository,
        scan_result_repository,
        scanners,
        repo_checkout,
        connected_repo_repository,
        github_connection_repository,
        scanner_config_repository,
        normalization_run_repository,
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
    assert results[0].status is ScanResultStatus.SUCCEEDED
    assert results[0].failure_reason is None
    assert repo_checkout.cleanup_calls == [repo_checkout.local_path]


async def test_every_enabled_scanner_runs_against_the_same_single_checkout(
    scan_repository,
    scan_result_repository,
    scanner_factory,
    repo_checkout,
    connected_repo_repository,
    github_connection_repository,
    scanner_config_repository,
    normalization_run_repository,
    id_generator,
    clock,
):
    """M3.7's headline claim: one trigger, N tools. The single-checkout
    assertion is the load-bearing one — it is the property M5's cross-tool
    correlation rests on (both tools saw the same tree), and the reason
    ADR-016 rejected one job per (scan, tool).
    """
    semgrep = scanner_factory(tool=ScannerTool.SEMGREP)
    trivy = scanner_factory(tool=ScannerTool.TRIVY)
    scan = _pending_scan()
    await _seed(
        scan_repository,
        connected_repo_repository,
        github_connection_repository,
        scan,
        scanner_config_repository,
        _config(enabled_tools=(ScannerTool.SEMGREP, ScannerTool.TRIVY)),
    )
    use_case = _use_case(
        scan_repository,
        scan_result_repository,
        {ScannerTool.SEMGREP: semgrep, ScannerTool.TRIVY: trivy},
        repo_checkout,
        connected_repo_repository,
        github_connection_repository,
        scanner_config_repository,
        normalization_run_repository,
        id_generator,
        clock,
    )

    await use_case.execute(_SCAN_ID)

    assert repo_checkout.checkout_calls == [_REPO_URL]
    assert semgrep.run_calls == [repo_checkout.local_path]
    assert trivy.run_calls == [repo_checkout.local_path]

    results = await scan_result_repository.get_by_scan_id(_SCAN_ID)
    assert sorted(result.tool for result in results) == ["semgrep", "trivy"]
    updated = await scan_repository.get_by_id(_SCAN_ID)
    assert updated.status is ScanStatus.COMPLETED


async def test_a_failing_scanner_does_not_discard_a_succeeding_scanners_output(
    scan_repository,
    scan_result_repository,
    scanner_factory,
    repo_checkout,
    connected_repo_repository,
    github_connection_repository,
    scanner_config_repository,
    normalization_run_repository,
    id_generator,
    clock,
):
    """PRODUCT_SPEC.md §12's "ZAP times out but Semgrep succeeds", directly."""
    semgrep = scanner_factory(
        tool=ScannerTool.SEMGREP,
        result=RawScanResult(tool=ScannerTool.SEMGREP, raw_output='{"results": []}'),
    )
    trivy = scanner_factory(tool=ScannerTool.TRIVY, fail=True)
    scan = _pending_scan()
    await _seed(
        scan_repository,
        connected_repo_repository,
        github_connection_repository,
        scan,
        scanner_config_repository,
        _config(enabled_tools=(ScannerTool.SEMGREP, ScannerTool.TRIVY)),
    )
    use_case = _use_case(
        scan_repository,
        scan_result_repository,
        {ScannerTool.SEMGREP: semgrep, ScannerTool.TRIVY: trivy},
        repo_checkout,
        connected_repo_repository,
        github_connection_repository,
        scanner_config_repository,
        normalization_run_repository,
        id_generator,
        clock,
    )

    # Deliberately no pytest.raises: a tool failing is a recorded outcome, not
    # a job failure. Raising here would hand the scan back to arq for a retry
    # that re-runs every scanner and could discard the output that succeeded.
    await use_case.execute(_SCAN_ID)

    updated = await scan_repository.get_by_id(_SCAN_ID)
    assert updated.status is ScanStatus.PARTIAL
    # The per-tool reasons carry the detail; the Scan-level field stays free
    # for "nothing ran at all" failures.
    assert updated.failure_reason is None

    results = {
        result.tool: result for result in await scan_result_repository.get_by_scan_id(_SCAN_ID)
    }
    assert results["semgrep"].raw_output == '{"results": []}'
    assert results["trivy"].status is ScanResultStatus.FAILED


async def test_after_a_partial_failure_m4_can_tell_trustworthy_results_from_failed_ones(
    scan_repository,
    scan_result_repository,
    scanner_factory,
    repo_checkout,
    connected_repo_repository,
    github_connection_repository,
    scanner_config_repository,
    normalization_run_repository,
    id_generator,
    clock,
):
    """The negative case that actually matters for M4.

    "Both rows exist" is not the property M4 needs — it needs to distinguish
    them without ambiguity. This asserts the distinction directly, through the
    exact query M4 will use.
    """
    semgrep = scanner_factory(tool=ScannerTool.SEMGREP)
    trivy = scanner_factory(tool=ScannerTool.TRIVY, fail=True)
    scan = _pending_scan()
    await _seed(
        scan_repository,
        connected_repo_repository,
        github_connection_repository,
        scan,
        scanner_config_repository,
        _config(enabled_tools=(ScannerTool.SEMGREP, ScannerTool.TRIVY)),
    )
    use_case = _use_case(
        scan_repository,
        scan_result_repository,
        {ScannerTool.SEMGREP: semgrep, ScannerTool.TRIVY: trivy},
        repo_checkout,
        connected_repo_repository,
        github_connection_repository,
        scanner_config_repository,
        normalization_run_repository,
        id_generator,
        clock,
    )

    await use_case.execute(_SCAN_ID)

    trustworthy = await scan_result_repository.get_succeeded_by_scan_id(_SCAN_ID)
    assert [result.tool for result in trustworthy] == ["semgrep"]
    # Guaranteed by ScanResult's invariant and the table's CHECK constraint —
    # this is what lets M4's mappers take `str` rather than `str | None`.
    assert all(result.raw_output is not None for result in trustworthy)

    # The failed tool is not silently absent: M4 can still tell "trivy was
    # attempted and failed" apart from "trivy was never enabled".
    everything = await scan_result_repository.get_by_scan_id(_SCAN_ID)
    failed = next(result for result in everything if result.tool == "trivy")
    assert failed.status is ScanResultStatus.FAILED
    assert failed.raw_output is None
    assert "simulated scanner failure" in failed.failure_reason


async def test_all_scanners_failing_marks_the_scan_failed_without_raising(
    scan_repository,
    scan_result_repository,
    scanner_factory,
    repo_checkout,
    connected_repo_repository,
    github_connection_repository,
    scanner_config_repository,
    normalization_run_repository,
    id_generator,
    clock,
):
    semgrep = scanner_factory(tool=ScannerTool.SEMGREP, fail=True)
    trivy = scanner_factory(tool=ScannerTool.TRIVY, fail=True)
    scan = _pending_scan()
    await _seed(
        scan_repository,
        connected_repo_repository,
        github_connection_repository,
        scan,
        scanner_config_repository,
        _config(enabled_tools=(ScannerTool.SEMGREP, ScannerTool.TRIVY)),
    )
    use_case = _use_case(
        scan_repository,
        scan_result_repository,
        {ScannerTool.SEMGREP: semgrep, ScannerTool.TRIVY: trivy},
        repo_checkout,
        connected_repo_repository,
        github_connection_repository,
        scanner_config_repository,
        normalization_run_repository,
        id_generator,
        clock,
    )

    await use_case.execute(_SCAN_ID)

    updated = await scan_repository.get_by_id(_SCAN_ID)
    assert updated.status is ScanStatus.FAILED
    # Still one row per tool: "attempted and failed" is recorded, not inferred
    # from the Scan-level status.
    assert len(await scan_result_repository.get_by_scan_id(_SCAN_ID)) == 2
    assert await scan_result_repository.get_succeeded_by_scan_id(_SCAN_ID) == []
    assert repo_checkout.cleanup_calls == [repo_checkout.local_path]


async def test_an_unanticipated_scanner_exception_is_isolated_like_a_declared_one(
    scan_repository,
    scan_result_repository,
    scanner_factory,
    repo_checkout,
    connected_repo_repository,
    github_connection_repository,
    scanner_config_repository,
    normalization_run_repository,
    id_generator,
    clock,
):
    """Why RunScanUseCase catches Exception rather than ScannerExecutionFailed.

    An adapter blowing up in a way nobody anticipated must not take down a
    sibling that succeeded. Narrowing the catch would make §12's tolerance hold
    only for the failures we thought of in advance.
    """
    semgrep = scanner_factory(tool=ScannerTool.SEMGREP)
    trivy = scanner_factory(tool=ScannerTool.TRIVY, error=RuntimeError("adapter bug"))
    scan = _pending_scan()
    await _seed(
        scan_repository,
        connected_repo_repository,
        github_connection_repository,
        scan,
        scanner_config_repository,
        _config(enabled_tools=(ScannerTool.SEMGREP, ScannerTool.TRIVY)),
    )
    use_case = _use_case(
        scan_repository,
        scan_result_repository,
        {ScannerTool.SEMGREP: semgrep, ScannerTool.TRIVY: trivy},
        repo_checkout,
        connected_repo_repository,
        github_connection_repository,
        scanner_config_repository,
        normalization_run_repository,
        id_generator,
        clock,
    )

    await use_case.execute(_SCAN_ID)

    updated = await scan_repository.get_by_id(_SCAN_ID)
    assert updated.status is ScanStatus.PARTIAL
    assert [
        result.tool for result in await scan_result_repository.get_succeeded_by_scan_id(_SCAN_ID)
    ] == ["semgrep"]
    everything = {
        result.tool: result for result in await scan_result_repository.get_by_scan_id(_SCAN_ID)
    }
    assert "RuntimeError: adapter bug" in everything["trivy"].failure_reason


async def test_a_url_kind_scanner_receives_the_configured_target_not_the_checkout_path(
    scan_repository,
    scan_result_repository,
    scanner_factory,
    repo_checkout,
    connected_repo_repository,
    github_connection_repository,
    scanner_config_repository,
    normalization_run_repository,
    id_generator,
    clock,
):
    """ADR-016 decision 4: dispatch routes by target_kind, not by tool name."""
    semgrep = scanner_factory(tool=ScannerTool.SEMGREP)
    zap = scanner_factory(tool=ScannerTool.ZAP, target_kind=ScannerTargetKind.URL)
    scan = _pending_scan()
    await _seed(
        scan_repository,
        connected_repo_repository,
        github_connection_repository,
        scan,
        scanner_config_repository,
        _config(enabled_tools=(ScannerTool.SEMGREP, ScannerTool.ZAP), zap_target_url=_ZAP_TARGET),
    )
    use_case = _use_case(
        scan_repository,
        scan_result_repository,
        {ScannerTool.SEMGREP: semgrep, ScannerTool.ZAP: zap},
        repo_checkout,
        connected_repo_repository,
        github_connection_repository,
        scanner_config_repository,
        normalization_run_repository,
        id_generator,
        clock,
    )

    await use_case.execute(_SCAN_ID)

    assert semgrep.run_calls == [repo_checkout.local_path]
    assert zap.run_calls == [_ZAP_TARGET]
    updated = await scan_repository.get_by_id(_SCAN_ID)
    assert updated.status is ScanStatus.COMPLETED


async def test_no_checkout_happens_when_no_enabled_scanner_needs_a_repo(
    scan_repository,
    scan_result_repository,
    scanner_factory,
    repo_checkout,
    connected_repo_repository,
    github_connection_repository,
    scanner_config_repository,
    normalization_run_repository,
    id_generator,
    clock,
):
    """A ZAP-only project never clones — the concrete payoff of target_kind."""
    zap = scanner_factory(tool=ScannerTool.ZAP, target_kind=ScannerTargetKind.URL)
    scan = _pending_scan()
    await _seed(
        scan_repository,
        connected_repo_repository,
        github_connection_repository,
        scan,
        scanner_config_repository,
        _config(enabled_tools=(ScannerTool.ZAP,), zap_target_url=_ZAP_TARGET),
    )
    use_case = _use_case(
        scan_repository,
        scan_result_repository,
        {ScannerTool.ZAP: zap},
        repo_checkout,
        connected_repo_repository,
        github_connection_repository,
        scanner_config_repository,
        normalization_run_repository,
        id_generator,
        clock,
    )

    await use_case.execute(_SCAN_ID)

    assert repo_checkout.checkout_calls == []
    assert repo_checkout.cleanup_calls == []
    assert zap.run_calls == [_ZAP_TARGET]


async def test_a_url_scanner_without_a_target_fails_only_that_tool(
    scan_repository,
    scan_result_repository,
    scanner_factory,
    repo_checkout,
    connected_repo_repository,
    github_connection_repository,
    scanner_config_repository,
    normalization_run_repository,
    id_generator,
    clock,
):
    """The write path rejects this combination, so reaching it means config was
    written around it. It is still that tool's failure, not the scan's."""
    semgrep = scanner_factory(tool=ScannerTool.SEMGREP)
    zap = scanner_factory(tool=ScannerTool.ZAP, target_kind=ScannerTargetKind.URL)
    scan = _pending_scan()
    await _seed(
        scan_repository,
        connected_repo_repository,
        github_connection_repository,
        scan,
        scanner_config_repository,
        _config(enabled_tools=(ScannerTool.SEMGREP, ScannerTool.ZAP), zap_target_url=None),
    )
    use_case = _use_case(
        scan_repository,
        scan_result_repository,
        {ScannerTool.SEMGREP: semgrep, ScannerTool.ZAP: zap},
        repo_checkout,
        connected_repo_repository,
        github_connection_repository,
        scanner_config_repository,
        normalization_run_repository,
        id_generator,
        clock,
    )

    await use_case.execute(_SCAN_ID)

    assert zap.run_calls == []
    updated = await scan_repository.get_by_id(_SCAN_ID)
    assert updated.status is ScanStatus.PARTIAL
    everything = {
        result.tool: result for result in await scan_result_repository.get_by_scan_id(_SCAN_ID)
    }
    assert "No target configured" in everything["zap"].failure_reason
    assert everything["semgrep"].status is ScanResultStatus.SUCCEEDED


async def test_an_unconfigured_project_runs_the_default_scanners(
    scan_repository,
    scan_result_repository,
    scanner_factory,
    repo_checkout,
    connected_repo_repository,
    github_connection_repository,
    scanner_config_repository,
    normalization_run_repository,
    id_generator,
    clock,
):
    """No config row means "never configured", not "nothing enabled" — and the
    default is deliberately the two scanners that take no user-supplied
    target."""
    semgrep = scanner_factory(tool=ScannerTool.SEMGREP)
    trivy = scanner_factory(tool=ScannerTool.TRIVY)
    zap = scanner_factory(tool=ScannerTool.ZAP, target_kind=ScannerTargetKind.URL)
    scan = _pending_scan()
    # No config seeded at all.
    await _seed(scan_repository, connected_repo_repository, github_connection_repository, scan)
    use_case = _use_case(
        scan_repository,
        scan_result_repository,
        {ScannerTool.SEMGREP: semgrep, ScannerTool.TRIVY: trivy, ScannerTool.ZAP: zap},
        repo_checkout,
        connected_repo_repository,
        github_connection_repository,
        scanner_config_repository,
        normalization_run_repository,
        id_generator,
        clock,
    )

    await use_case.execute(_SCAN_ID)

    results = await scan_result_repository.get_by_scan_id(_SCAN_ID)
    assert sorted(result.tool for result in results) == ["semgrep", "trivy"]
    # ZAP is registered and available, and still does not run: it cannot be
    # defaulted on because only a user can supply its target.
    assert zap.run_calls == []


async def test_explicitly_enabling_nothing_fails_the_scan_and_is_not_the_default(
    scan_repository,
    scan_result_repository,
    scanners,
    repo_checkout,
    connected_repo_repository,
    github_connection_repository,
    scanner_config_repository,
    normalization_run_repository,
    id_generator,
    clock,
):
    """An empty enabled_tools is "configured to run nothing", which must not
    collapse into the unconfigured default — the distinction a truthiness check
    would silently lose."""
    scan = _pending_scan()
    await _seed(
        scan_repository,
        connected_repo_repository,
        github_connection_repository,
        scan,
        scanner_config_repository,
        _config(enabled_tools=()),
    )
    use_case = _use_case(
        scan_repository,
        scan_result_repository,
        scanners,
        repo_checkout,
        connected_repo_repository,
        github_connection_repository,
        scanner_config_repository,
        normalization_run_repository,
        id_generator,
        clock,
    )

    with pytest.raises(NoScannersEnabled, match="No scanners enabled"):
        await use_case.execute(_SCAN_ID)

    updated = await scan_repository.get_by_id(_SCAN_ID)
    assert updated.status is ScanStatus.FAILED
    assert repo_checkout.checkout_calls == []
    assert await scan_result_repository.get_by_scan_id(_SCAN_ID) == []


async def test_a_configured_tool_with_no_registered_adapter_fails_the_whole_scan(
    scan_repository,
    scan_result_repository,
    scanners,
    repo_checkout,
    connected_repo_repository,
    github_connection_repository,
    scanner_config_repository,
    normalization_run_repository,
    id_generator,
    clock,
):
    """A deployment/config error, not a tool outcome — so it is loud, and no
    partial results are written that would imply the tool was even attempted."""
    scan = _pending_scan()
    await _seed(
        scan_repository,
        connected_repo_repository,
        github_connection_repository,
        scan,
        scanner_config_repository,
        # Trivy enabled, but only Semgrep is registered in `scanners`.
        _config(enabled_tools=(ScannerTool.SEMGREP, ScannerTool.TRIVY)),
    )
    use_case = _use_case(
        scan_repository,
        scan_result_repository,
        scanners,
        repo_checkout,
        connected_repo_repository,
        github_connection_repository,
        scanner_config_repository,
        normalization_run_repository,
        id_generator,
        clock,
    )

    with pytest.raises(UnknownScanner, match="trivy"):
        await use_case.execute(_SCAN_ID)

    updated = await scan_repository.get_by_id(_SCAN_ID)
    assert updated.status is ScanStatus.FAILED
    assert repo_checkout.checkout_calls == []
    assert await scan_result_repository.get_by_scan_id(_SCAN_ID) == []


async def test_checkout_failure_marks_the_scan_failed(
    scan_repository,
    scan_result_repository,
    scanners,
    repo_checkout_factory,
    connected_repo_repository,
    github_connection_repository,
    scanner_config_repository,
    normalization_run_repository,
    id_generator,
    clock,
):
    scan = _pending_scan()
    await _seed(
        scan_repository,
        connected_repo_repository,
        github_connection_repository,
        scan,
        scanner_config_repository,
    )
    repo_checkout = repo_checkout_factory(fail=True)
    use_case = _use_case(
        scan_repository,
        scan_result_repository,
        scanners,
        repo_checkout,
        connected_repo_repository,
        github_connection_repository,
        scanner_config_repository,
        normalization_run_repository,
        id_generator,
        clock,
    )

    with pytest.raises(RepoCheckoutFailed, match="simulated checkout failure"):
        await use_case.execute(_SCAN_ID)

    updated = await scan_repository.get_by_id(_SCAN_ID)
    assert updated.status is ScanStatus.FAILED
    # Nothing ran, so the Scan-level failure_reason is the right home for this
    # — exactly the meaning it had before M3.7.
    assert updated.failure_reason == "simulated checkout failure"
    assert await scan_result_repository.get_by_scan_id(_SCAN_ID) == []


async def test_missing_connected_repo_marks_the_scan_failed(
    scan_repository,
    scan_result_repository,
    scanners,
    repo_checkout,
    connected_repo_repository,
    github_connection_repository,
    scanner_config_repository,
    normalization_run_repository,
    id_generator,
    clock,
):
    scan = _pending_scan()
    await scan_repository.add(scan)
    await scanner_config_repository.upsert(_config())
    # No connected repo, no github connection seeded.
    use_case = _use_case(
        scan_repository,
        scan_result_repository,
        scanners,
        repo_checkout,
        connected_repo_repository,
        github_connection_repository,
        scanner_config_repository,
        normalization_run_repository,
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
    scanners,
    repo_checkout,
    connected_repo_repository,
    github_connection_repository,
    scanner_config_repository,
    normalization_run_repository,
    id_generator,
    clock,
):
    scan = _pending_scan()
    await scan_repository.add(scan)
    await connected_repo_repository.add(_connected_repo())
    await scanner_config_repository.upsert(_config())
    # No github connection seeded for the owner.
    use_case = _use_case(
        scan_repository,
        scan_result_repository,
        scanners,
        repo_checkout,
        connected_repo_repository,
        github_connection_repository,
        scanner_config_repository,
        normalization_run_repository,
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
    scanners,
    repo_checkout,
    connected_repo_repository,
    github_connection_repository,
    scanner_config_repository,
    normalization_run_repository,
    id_generator,
    clock,
):
    scan = _pending_scan()
    await scan_repository.add(scan)
    await connected_repo_repository.add(_connected_repo(provider="gitlab"))
    await github_connection_repository.add(_github_connection())
    await scanner_config_repository.upsert(_config())
    use_case = _use_case(
        scan_repository,
        scan_result_repository,
        scanners,
        repo_checkout,
        connected_repo_repository,
        github_connection_repository,
        scanner_config_repository,
        normalization_run_repository,
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
    scanners,
    repo_checkout,
    connected_repo_repository,
    github_connection_repository,
    scanner_config_repository,
    normalization_run_repository,
    id_generator,
    clock,
):
    scan = _pending_scan()
    await _seed(
        scan_repository,
        connected_repo_repository,
        github_connection_repository,
        scan,
        scanner_config_repository,
    )
    use_case = _use_case(
        scan_repository,
        scan_result_repository,
        scanners,
        repo_checkout,
        connected_repo_repository,
        github_connection_repository,
        scanner_config_repository,
        normalization_run_repository,
        id_generator,
        clock,
    )
    await use_case.execute(_SCAN_ID)
    assert len(scanner.run_calls) == 1

    # Redelivery of the same (already-succeeded) job.
    await use_case.execute(_SCAN_ID)

    assert scanner.run_calls == [repo_checkout.local_path]
    assert repo_checkout.checkout_calls == [_REPO_URL]


async def test_retry_after_a_partial_scan_reruns_every_enabled_scanner(
    scan_repository,
    scan_result_repository,
    scanner_factory,
    repo_checkout,
    connected_repo_repository,
    github_connection_repository,
    scanner_config_repository,
    normalization_run_repository,
    id_generator,
    clock,
):
    """PARTIAL does not short-circuit, and the retry re-runs the tool that
    already succeeded too.

    That looks wasteful and is deliberate: re-running only the failure would
    pair a fresh checkout's result with a stale one from an older commit, which
    is the snapshot incoherence ADR-016 rejected fan-out to avoid. Locking this
    in with a test because it is the obvious place to "optimize" incorrectly.
    """
    semgrep = scanner_factory(tool=ScannerTool.SEMGREP)
    trivy = scanner_factory(tool=ScannerTool.TRIVY)
    scan = Scan(
        id=_SCAN_ID,
        project_id=_PROJECT_ID,
        status=ScanStatus.PARTIAL,
        triggered_by=_OWNER_ID,
        started_at=datetime(2026, 1, 1, tzinfo=UTC),
        finished_at=datetime(2026, 1, 1, tzinfo=UTC),
        failure_reason=None,
    )
    await _seed(
        scan_repository,
        connected_repo_repository,
        github_connection_repository,
        scan,
        scanner_config_repository,
        _config(enabled_tools=(ScannerTool.SEMGREP, ScannerTool.TRIVY)),
    )
    await scan_result_repository.upsert(
        ScanResult.succeeded(
            id="pre-existing-id", scan_id=_SCAN_ID, tool="semgrep", raw_output="{}"
        )
    )
    use_case = _use_case(
        scan_repository,
        scan_result_repository,
        {ScannerTool.SEMGREP: semgrep, ScannerTool.TRIVY: trivy},
        repo_checkout,
        connected_repo_repository,
        github_connection_repository,
        scanner_config_repository,
        normalization_run_repository,
        id_generator,
        clock,
    )

    await use_case.execute(_SCAN_ID)

    assert len(semgrep.run_calls) == 1
    assert len(trivy.run_calls) == 1
    updated = await scan_repository.get_by_id(_SCAN_ID)
    assert updated.status is ScanStatus.COMPLETED


async def test_retry_after_crash_between_upsert_and_completed_redoes_real_work(
    scan_repository,
    scan_result_repository,
    scanner,
    scanners,
    repo_checkout,
    connected_repo_repository,
    github_connection_repository,
    scanner_config_repository,
    normalization_run_repository,
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
    await _seed(
        scan_repository,
        connected_repo_repository,
        github_connection_repository,
        scan,
        scanner_config_repository,
    )
    await scan_result_repository.upsert(
        ScanResult.succeeded(
            id="pre-existing-id", scan_id=_SCAN_ID, tool="semgrep", raw_output="{}"
        )
    )
    use_case = _use_case(
        scan_repository,
        scan_result_repository,
        scanners,
        repo_checkout,
        connected_repo_repository,
        github_connection_repository,
        scanner_config_repository,
        normalization_run_repository,
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


# ADR-0017 — the scan → normalize handoff. The invariant these pin down is
# "a NormalizationRun exists iff ScanResult rows were persisted", chosen so
# there is exactly one code path and no hole in what a future sweep relies on.


async def test_a_completed_scan_records_that_normalization_is_owed(
    scan_repository,
    scan_result_repository,
    scanners,
    repo_checkout,
    connected_repo_repository,
    github_connection_repository,
    scanner_config_repository,
    normalization_run_repository,
    id_generator,
    clock,
):
    scan = _pending_scan()
    await _seed(
        scan_repository,
        connected_repo_repository,
        github_connection_repository,
        scan,
        scanner_config_repository,
    )
    use_case = _use_case(
        scan_repository,
        scan_result_repository,
        scanners,
        repo_checkout,
        connected_repo_repository,
        github_connection_repository,
        scanner_config_repository,
        normalization_run_repository,
        id_generator,
        clock,
    )

    await use_case.execute(_SCAN_ID)

    run = await normalization_run_repository.get_by_scan_id(_SCAN_ID)
    assert run is not None
    assert run.status is NormalizationRunStatus.PENDING
    assert run.requested_at == clock.now()
    # Scan.status stays scanner-scoped: COMPLETED means every enabled scanner
    # finished, not that the pipeline did. Nothing downstream reads it.
    updated = await scan_repository.get_by_id(_SCAN_ID)
    assert updated.status is ScanStatus.COMPLETED


async def test_a_partial_scan_records_that_normalization_is_owed(
    scan_repository,
    scan_result_repository,
    scanner_factory,
    repo_checkout,
    connected_repo_repository,
    github_connection_repository,
    scanner_config_repository,
    normalization_run_repository,
    id_generator,
    clock,
):
    """Skipping a PARTIAL scan would discard a succeeding scanner's output one
    layer up — the corruption PRODUCT_SPEC.md §12 forbids, arriving one layer
    above where ADR-016 decision 2 prevented it."""
    semgrep = scanner_factory(tool=ScannerTool.SEMGREP)
    trivy = scanner_factory(tool=ScannerTool.TRIVY, fail=True)
    scan = _pending_scan()
    await _seed(
        scan_repository,
        connected_repo_repository,
        github_connection_repository,
        scan,
        scanner_config_repository,
        _config(enabled_tools=(ScannerTool.SEMGREP, ScannerTool.TRIVY)),
    )
    use_case = _use_case(
        scan_repository,
        scan_result_repository,
        {ScannerTool.SEMGREP: semgrep, ScannerTool.TRIVY: trivy},
        repo_checkout,
        connected_repo_repository,
        github_connection_repository,
        scanner_config_repository,
        normalization_run_repository,
        id_generator,
        clock,
    )

    await use_case.execute(_SCAN_ID)

    updated = await scan_repository.get_by_id(_SCAN_ID)
    assert updated.status is ScanStatus.PARTIAL
    run = await normalization_run_repository.get_by_scan_id(_SCAN_ID)
    assert run is not None
    assert run.status is NormalizationRunStatus.PENDING


async def test_a_scan_where_every_tool_failed_still_records_normalization_as_owed(
    scan_repository,
    scan_result_repository,
    scanner_factory,
    repo_checkout,
    connected_repo_repository,
    github_connection_repository,
    scanner_config_repository,
    normalization_run_repository,
    id_generator,
    clock,
):
    """The degenerate case, resolved to keep the invariant uniform.

    Normalizing an all-failed scan produces zero findings, which is harmless.
    Skipping it would create a second code path and a scan with no progress row
    — indistinguishable, to a sweep, from one whose row was lost.
    """
    semgrep = scanner_factory(tool=ScannerTool.SEMGREP, fail=True)
    trivy = scanner_factory(tool=ScannerTool.TRIVY, fail=True)
    scan = _pending_scan()
    await _seed(
        scan_repository,
        connected_repo_repository,
        github_connection_repository,
        scan,
        scanner_config_repository,
        _config(enabled_tools=(ScannerTool.SEMGREP, ScannerTool.TRIVY)),
    )
    use_case = _use_case(
        scan_repository,
        scan_result_repository,
        {ScannerTool.SEMGREP: semgrep, ScannerTool.TRIVY: trivy},
        repo_checkout,
        connected_repo_repository,
        github_connection_repository,
        scanner_config_repository,
        normalization_run_repository,
        id_generator,
        clock,
    )

    await use_case.execute(_SCAN_ID)

    updated = await scan_repository.get_by_id(_SCAN_ID)
    assert updated.status is ScanStatus.FAILED
    # ScanResult rows exist, so the row exists — the "iff" holds in this
    # direction even though there will be nothing to normalize.
    assert len(await scan_result_repository.get_by_scan_id(_SCAN_ID)) == 2
    assert await normalization_run_repository.get_by_scan_id(_SCAN_ID) is not None


async def test_a_failure_before_any_tool_runs_records_no_normalization_run(
    scan_repository,
    scan_result_repository,
    scanners,
    repo_checkout_factory,
    connected_repo_repository,
    github_connection_repository,
    scanner_config_repository,
    normalization_run_repository,
    id_generator,
    clock,
):
    """The other direction of the same "iff": no ScanResult rows were
    persisted, so nothing is owed and no row is written. The Scan-level
    failure_reason carries this one, exactly as it did before M4."""
    scan = _pending_scan()
    await _seed(
        scan_repository,
        connected_repo_repository,
        github_connection_repository,
        scan,
        scanner_config_repository,
    )
    use_case = _use_case(
        scan_repository,
        scan_result_repository,
        scanners,
        repo_checkout_factory(fail=True),
        connected_repo_repository,
        github_connection_repository,
        scanner_config_repository,
        normalization_run_repository,
        id_generator,
        clock,
    )

    with pytest.raises(RepoCheckoutFailed):
        await use_case.execute(_SCAN_ID)

    assert await scan_result_repository.get_by_scan_id(_SCAN_ID) == []
    assert await normalization_run_repository.get_by_scan_id(_SCAN_ID) is None
    assert normalization_run_repository.request_calls == []


async def test_a_retry_re_requests_normalization_without_overwriting_the_row(
    scan_repository,
    scan_result_repository,
    scanner,
    scanners,
    repo_checkout,
    connected_repo_repository,
    github_connection_repository,
    scanner_config_repository,
    normalization_run_repository,
    id_generator,
    clock,
):
    """The idempotent insert, from the caller's side.

    A retry of a PARTIAL scan re-requests a run that already exists. That must
    be a no-op — not an IntegrityError, and not an overwrite: DO UPDATE would
    reset a running or completed row back to pending and re-normalize a scan
    that was already normalized (ADR-0017 decision 2).
    """
    scan = Scan(
        id=_SCAN_ID,
        project_id=_PROJECT_ID,
        status=ScanStatus.PARTIAL,
        triggered_by=_OWNER_ID,
        started_at=datetime(2026, 1, 1, tzinfo=UTC),
        finished_at=None,
        failure_reason=None,
    )
    await _seed(
        scan_repository,
        connected_repo_repository,
        github_connection_repository,
        scan,
        scanner_config_repository,
    )
    # The row the first attempt already wrote, which the retry must leave alone.
    await normalization_run_repository.request(
        id="pre-existing-run", scan_id=_SCAN_ID, requested_at=datetime(2026, 1, 1, tzinfo=UTC)
    )
    use_case = _use_case(
        scan_repository,
        scan_result_repository,
        scanners,
        repo_checkout,
        connected_repo_repository,
        github_connection_repository,
        scanner_config_repository,
        normalization_run_repository,
        id_generator,
        clock,
    )

    await use_case.execute(_SCAN_ID)

    assert len(scanner.run_calls) == 1
    # The request *was* made again: the conflict is resolved at the write, not
    # by the caller reading first, which would be racy across two workers.
    assert normalization_run_repository.request_calls == [_SCAN_ID, _SCAN_ID]
    run = await normalization_run_repository.get_by_scan_id(_SCAN_ID)
    assert run.id == "pre-existing-run"
    assert run.status is NormalizationRunStatus.PENDING


class _ScanRepositoryFailingOnTheTerminalUpdate:
    """Delegates to the in-memory repository but fails the *second* update —
    the terminal one that writes the derived status.

    That is precisely the window ADR-0017 decision 2's ordering constraint
    exists for, and the only way to observe the ordering from outside.
    """

    def __init__(self, inner) -> None:
        self._inner = inner
        self.update_calls = 0

    async def add(self, scan):
        await self._inner.add(scan)

    async def get_by_id(self, scan_id):
        return await self._inner.get_by_id(scan_id)

    async def update(self, scan):
        self.update_calls += 1
        if self.update_calls >= 2:
            raise RuntimeError("simulated database failure")
        await self._inner.update(scan)


async def test_the_handoff_row_is_written_before_the_scan_status_update(
    scan_repository,
    scan_result_repository,
    scanners,
    repo_checkout,
    connected_repo_repository,
    github_connection_repository,
    scanner_config_repository,
    normalization_run_repository,
    id_generator,
    clock,
):
    """The ordering constraint, asserted rather than left to a comment.

    Reversed, a failure writing the handoff row would still commit COMPLETED
    (worker.py commits in `finally`) and the retry would return immediately at
    the `== COMPLETED` guard — normalization lost silently and permanently.
    Pinned with a test because swapping these two lines looks harmless and is
    not; the mutation was run, and reordering fails this test and only this one.

    Scope, so the assertion is not read as more than it is: this covers the
    *non-database* failure, where the session stays usable and the RUNNING flush
    commits. A real database error would abort the transaction instead, so the
    worker's commit would raise and the scan would roll back to PENDING — which
    is why the property ADR-0017 decision 2 states is "never left COMPLETED"
    rather than "left RUNNING". Both land on a status that does not
    short-circuit; only this one is reachable with in-memory fakes.
    """
    scan = _pending_scan()
    await _seed(
        scan_repository,
        connected_repo_repository,
        github_connection_repository,
        scan,
        scanner_config_repository,
    )
    failing_scans = _ScanRepositoryFailingOnTheTerminalUpdate(scan_repository)
    use_case = _use_case(
        failing_scans,
        scan_result_repository,
        scanners,
        repo_checkout,
        connected_repo_repository,
        github_connection_repository,
        scanner_config_repository,
        normalization_run_repository,
        id_generator,
        clock,
    )

    # Not one of the six pre-tool exceptions, so it is neither caught nor
    # converted — it propagates with the scan still RUNNING. That third exit
    # path is what makes this ordering the safe one.
    with pytest.raises(RuntimeError, match="simulated database failure"):
        await use_case.execute(_SCAN_ID)

    assert await normalization_run_repository.get_by_scan_id(_SCAN_ID) is not None
    updated = await scan_repository.get_by_id(_SCAN_ID)
    assert updated.status is ScanStatus.RUNNING
