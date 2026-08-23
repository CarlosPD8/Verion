"""The pipeline end to end, against real Postgres (M4.4).

Scan → `ScanResult` rows → handoff row → claim → `Finding` rows + sightings. This
is the first test in the project where a trigger produces a persisted finding.

**Not container-bound, deliberately, and the choice is budgeted.** The scanners
are in-process fakes fed M4.1's committed fixtures as their `raw_output`, so the
`Tests (pytest …)` step pays a fixture parse and some queries. Reusing
`test_multi_scanner_dispatch.py`'s three real adapters would have added a fourth
ZAP-class test, and `CLAUDE.md` records roughly three of those to the 120s CI
split — a third of the remaining headroom, spent on coverage that test already
owns. What this file is about is the handoff and the identity model, and neither
needs a real subprocess. Same reasoning and same shape as
`test_normalization_handoff.py`.
"""

from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import text

from verion.modules.identity.adapters.outbound.db.repository import (
    PostgresGitHubConnectionRepository,
)
from verion.modules.identity.domain.github_connection import GitHubConnection
from verion.modules.normalization.adapters.outbound.db.repository import (
    PostgresFindingRepository,
    PostgresNormalizationRunRepository,
)
from verion.modules.normalization.application.normalize_scan import NormalizeScanUseCase
from verion.modules.normalization.domain.normalization_run import (
    NormalizationRun,
    NormalizationRunStatus,
)
from verion.modules.projects.adapters.outbound.db.repository import (
    PostgresConnectedRepoRepository,
    PostgresProjectRepository,
    PostgresScannerConfigRepository,
)
from verion.modules.projects.domain.project import ConnectedRepo, Project
from verion.modules.projects.domain.scanner_config import ScannerConfig
from verion.modules.scanning.adapters.outbound.db.repository import (
    PostgresScanRepository,
    PostgresScanResultRepository,
)
from verion.modules.scanning.application.run_scan import RunScanUseCase
from verion.modules.scanning.domain.exceptions import ScannerExecutionFailed
from verion.modules.scanning.domain.raw_scan_result import RawScanResult
from verion.modules.scanning.domain.scan import Scan, ScanStatus
from verion.modules.scanning.domain.scanner_target_kind import ScannerTargetKind
from verion.platform.clock import SystemClock
from verion.platform.id_generator import UuidIdGenerator
from verion.shared_kernel.scanner_tools import ScannerTool


class _FixtureScanner:
    """Returns a committed real-tool capture. No subprocess, real output shape."""

    def __init__(self, tool: ScannerTool, raw_output: str | None = None) -> None:
        self.tool = tool
        self.target_kind = ScannerTargetKind.REPO_PATH
        self._raw_output = raw_output

    async def run(self, target: str) -> RawScanResult:
        if self._raw_output is None:
            raise ScannerExecutionFailed("simulated scanner failure")
        return RawScanResult(tool=self.tool, raw_output=self._raw_output)


class _FakeRepoCheckout:
    async def checkout(self, repo_url: str, access_token: str | None) -> str:
        return "/tmp/verion-pipeline-fixture"

    async def cleanup(self, local_path: str) -> None:
        return None


async def _seed(db_session, run_id: str, tools: tuple[ScannerTool, ...]) -> Scan:
    project = Project(
        id=f"project-pipe-{run_id}",
        owner_id=f"owner-pipe-{run_id}",
        name="Widgets",
        created_at=datetime.now(UTC),
    )
    await PostgresProjectRepository(db_session).add(project)
    await PostgresConnectedRepoRepository(db_session).add(
        ConnectedRepo(
            id=f"repo-pipe-{run_id}",
            project_id=project.id,
            provider="github",
            url="https://github.com/octocat/Hello-World",
            default_branch="master",
        )
    )
    await PostgresGitHubConnectionRepository(db_session).add(
        GitHubConnection(
            user_id=project.owner_id,
            access_token="",
            github_username="octocat",
            connected_at=datetime.now(UTC),
        )
    )
    await PostgresScannerConfigRepository(db_session).upsert(
        ScannerConfig(
            id=f"config-pipe-{run_id}",
            project_id=project.id,
            enabled_tools=tools,
            zap_target_url=None,
            updated_at=datetime.now(UTC),
        )
    )
    scan = Scan(
        id=f"scan-pipe-{run_id}",
        project_id=project.id,
        status=ScanStatus.PENDING,
        triggered_by=project.owner_id,
        started_at=None,
        finished_at=None,
        failure_reason=None,
    )
    await PostgresScanRepository(db_session).add(scan)
    return scan


async def _run_scan(db_session, scan: Scan, scanners) -> None:
    await RunScanUseCase(
        scans=PostgresScanRepository(db_session),
        scan_results=PostgresScanResultRepository(db_session),
        scanners=scanners,
        repo_checkout=_FakeRepoCheckout(),
        connected_repos=PostgresConnectedRepoRepository(db_session),
        github_connections=PostgresGitHubConnectionRepository(db_session),
        scanner_configs=PostgresScannerConfigRepository(db_session),
        normalization_runs=PostgresNormalizationRunRepository(db_session),
        id_generator=UuidIdGenerator(),
        clock=SystemClock(),
    ).execute(scan.id)
    await db_session.commit()


async def _normalize(db_session, scan_id: str) -> None:
    runs = PostgresNormalizationRunRepository(db_session)
    run = await runs.claim(scan_id=scan_id, now=SystemClock().now())
    assert run is not None, "the handoff row must exist and be claimable"
    await db_session.commit()
    await NormalizeScanUseCase(
        scan_results=PostgresScanResultRepository(db_session),
        findings=PostgresFindingRepository(db_session),
        normalization_runs=runs,
        id_generator=UuidIdGenerator(),
        clock=SystemClock(),
    ).execute(run)
    await db_session.commit()


async def test_a_partial_scan_normalizes_the_succeeded_tools_only(db_session, scanner_fixture):
    """M4.4's headline acceptance criterion.

    Asserted through `get_succeeded_by_scan_id` rather than by row counts alone,
    because the count would also pass if the failed tool had contributed rows and
    something else had dropped an equal number.
    """
    run_id = uuid4().hex[:12]
    scan = await _seed(db_session, run_id, (ScannerTool.SEMGREP, ScannerTool.TRIVY))
    await _run_scan(
        db_session,
        scan,
        {
            ScannerTool.SEMGREP: _FixtureScanner(
                ScannerTool.SEMGREP, scanner_fixture("semgrep_scan.json")
            ),
            # No output: this tool fails, which is what makes the scan PARTIAL.
            ScannerTool.TRIVY: _FixtureScanner(ScannerTool.TRIVY),
        },
    )
    stored_scan = await PostgresScanRepository(db_session).get_by_id(scan.id)
    assert stored_scan.status is ScanStatus.PARTIAL

    await _normalize(db_session, scan.id)

    trustworthy = await PostgresScanResultRepository(db_session).get_succeeded_by_scan_id(scan.id)
    assert [result.tool for result in trustworthy] == ["semgrep"]

    findings = await PostgresFindingRepository(db_session).get_by_project_id(scan.project_id)
    assert findings
    # The failed tool contributed nothing — asserted against the same query the
    # use case reads, not against a count.
    assert {str(finding.source) for finding in findings} == {result.tool for result in trustworthy}
    run = await PostgresNormalizationRunRepository(db_session).get_by_scan_id(scan.id)
    assert run.status is NormalizationRunStatus.COMPLETED
    assert run.started_at is not None
    assert run.finished_at is not None


async def test_the_semgrep_findings_carry_a_stable_identity_after_the_g9_g10_fix(
    db_session, scanner_fixture
):
    """G9 and G10, at the layer they were about all along.

    `file_path` and `rule_id` are both `dedup_hash` inputs. Before M4.4 the first
    carried a per-scan `mkdtemp` prefix and the second the `--config` path relative
    to the worker's CWD, so every Semgrep finding re-keyed on every scan while
    Trivy and ZAP deduped correctly. What the ADAPTER now produces is pinned by
    `test_semgrep_adapter.py`; this asserts the shape reaches the stored row.
    """
    run_id = uuid4().hex[:12]
    scan = await _seed(db_session, run_id, (ScannerTool.SEMGREP,))
    await _run_scan(
        db_session,
        scan,
        {
            ScannerTool.SEMGREP: _FixtureScanner(
                ScannerTool.SEMGREP, scanner_fixture("semgrep_scan.json")
            )
        },
    )
    await _normalize(db_session, scan.id)

    findings = await PostgresFindingRepository(db_session).get_by_project_id(scan.project_id)
    finding = next(f for f in findings if str(f.source) == "semgrep")
    assert finding.rule_id == "dangerous-eval"
    assert finding.location.file_path == "vulnerable.py"
    assert finding.dedup_hash.startswith("v1:")


async def test_a_retried_normalization_changes_nothing(db_session, scanner_fixture):
    """`ARCHITECTURE.md` §9's idempotency requirement, and ADR-0020 decision 5's
    `match_count` contract, on the path that actually exercises them.

    The retry is guaranteed rather than hypothetical (ADR-016 decision 1), so this
    is the assertion that fails if anyone ever makes the sighting upsert SUM: the
    count would double on the second pass, silently.

    The scenario is a worker killed after its claim committed — the row is left
    `RUNNING`, the sweep re-enqueues it, and the full deterministic pass runs
    again over `ScanResult` rows that have not changed. Note it is NOT a completed
    run being re-run: `COMPLETED` is terminal and `claim` refuses it, which an
    earlier draft of this test discovered by having the state machine reject it.
    """
    run_id = uuid4().hex[:12]
    scan = await _seed(db_session, run_id, (ScannerTool.SEMGREP,))
    await _run_scan(
        db_session,
        scan,
        {
            ScannerTool.SEMGREP: _FixtureScanner(
                ScannerTool.SEMGREP, scanner_fixture("semgrep_scan.json")
            )
        },
    )
    await _normalize(db_session, scan.id)

    findings = PostgresFindingRepository(db_session)
    before = await findings.get_by_project_id(scan.project_id)
    sightings_before = await findings.get_sightings_by_finding_id(before[0].id)

    await _retry_after_a_killed_worker(db_session, scan)

    after = await findings.get_by_project_id(scan.project_id)
    assert [finding.id for finding in after] == [finding.id for finding in before]
    sightings_after = await findings.get_sightings_by_finding_id(before[0].id)
    assert len(sightings_after) == len(sightings_before)
    assert sightings_after[0].match_count == sightings_before[0].match_count


async def _retry_after_a_killed_worker(db_session, scan: Scan) -> None:
    """Leave the row exactly as a worker killed after its claim would, then let
    the normal claim-and-run path pick it up.

    The `RUNNING` row is CONSTRUCTED rather than transitioned into, because there
    is no legal transition from `COMPLETED` — that is the point of it being
    terminal. Constructing it is not going around the state machine: the object
    still passes `__post_init__` and the row still passes
    `ck_normalization_runs_timestamp_shape`, so what is being set up is a state
    the system can really be in, not one the guards forbid.
    """
    runs = PostgresNormalizationRunRepository(db_session)
    stored = await runs.get_by_scan_id(scan.id)
    await runs.update(
        NormalizationRun(
            id=stored.id,
            scan_id=stored.scan_id,
            project_id=stored.project_id,
            status=NormalizationRunStatus.RUNNING,
            requested_at=stored.requested_at,
            started_at=stored.started_at,
            finished_at=None,
            failure_reason=None,
        )
    )
    await db_session.commit()

    # And now the ordinary path: claim (RUNNING is claimable, which is what lets
    # the sweep recover a stalled row) and re-run the full deterministic pass.
    reclaimed = await runs.claim(scan_id=scan.id, now=SystemClock().now())
    assert reclaimed is not None
    await db_session.commit()
    await NormalizeScanUseCase(
        scan_results=PostgresScanResultRepository(db_session),
        findings=PostgresFindingRepository(db_session),
        normalization_runs=runs,
        id_generator=UuidIdGenerator(),
        clock=SystemClock(),
    ).execute(reclaimed)
    await db_session.commit()


async def test_a_second_scan_sights_the_same_findings_rather_than_duplicating_them(
    db_session, scanner_fixture
):
    """FR-5's actual requirement — dedup ACROSS repeated scans — and ADR-0020
    decision 5's first contract, on the only path where it is non-vacuous.

    The second scan's mapper generates fresh ids; the upsert resolves them to the
    stored row and hands back the row the database now holds. A sighting written
    against `representative.id` rather than the returned `stored.id` would point
    at a finding that does not exist, and the foreign key is what would say so.
    """
    run_id = uuid4().hex[:12]
    raw = scanner_fixture("semgrep_scan.json")
    scan = await _seed(db_session, run_id, (ScannerTool.SEMGREP,))
    await _run_scan(
        db_session, scan, {ScannerTool.SEMGREP: _FixtureScanner(ScannerTool.SEMGREP, raw)}
    )
    await _normalize(db_session, scan.id)
    findings = PostgresFindingRepository(db_session)
    first = await findings.get_by_project_id(scan.project_id)

    second_scan = Scan(
        id=f"scan-pipe-{run_id}-2",
        project_id=scan.project_id,
        status=ScanStatus.PENDING,
        triggered_by=scan.triggered_by,
        started_at=None,
        finished_at=None,
        failure_reason=None,
    )
    await PostgresScanRepository(db_session).add(second_scan)
    await _run_scan(
        db_session, second_scan, {ScannerTool.SEMGREP: _FixtureScanner(ScannerTool.SEMGREP, raw)}
    )
    await _normalize(db_session, second_scan.id)

    after = await findings.get_by_project_id(scan.project_id)
    # No duplicate rows: the identity resolved to the same findings.
    assert [finding.id for finding in after] == [finding.id for finding in first]
    # And the second scan recorded a sighting against the RESOLVED id.
    sightings = await findings.get_sightings_by_finding_id(first[0].id)
    assert {sighting.scan_id for sighting in sightings} == {scan.id, second_scan.id}


async def test_a_scan_where_every_tool_failed_completes_with_no_findings(db_session):
    """ADR-0017 decision 3's degenerate case, on the real path.

    `ScanResult` rows exist, so the handoff row exists, so the stage runs — one
    code path, no hole in the invariant the sweep is built on. The run is
    `completed`, not `failed`: normalization did not fail, it had nothing
    trustworthy to do.
    """
    run_id = uuid4().hex[:12]
    scan = await _seed(db_session, run_id, (ScannerTool.SEMGREP, ScannerTool.TRIVY))
    await _run_scan(
        db_session,
        scan,
        {
            ScannerTool.SEMGREP: _FixtureScanner(ScannerTool.SEMGREP),
            ScannerTool.TRIVY: _FixtureScanner(ScannerTool.TRIVY),
        },
    )
    assert (await PostgresScanRepository(db_session).get_by_id(scan.id)).status is ScanStatus.FAILED

    await _normalize(db_session, scan.id)

    assert await PostgresFindingRepository(db_session).get_by_project_id(scan.project_id) == []
    run = await PostgresNormalizationRunRepository(db_session).get_by_scan_id(scan.id)
    assert run.status is NormalizationRunStatus.COMPLETED
    assert run.failure_reason is None
    rows = await db_session.execute(
        text("SELECT count(*) FROM finding_sightings WHERE scan_id = :scan_id"),
        {"scan_id": scan.id},
    )
    assert rows.scalar_one() == 0
