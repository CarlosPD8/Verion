import asyncio
import dataclasses
from collections.abc import Mapping

# ConnectedRepoRepositoryPort/GitHubConnectionRepositoryPort/
# ScannerConfigRepositoryPort belong to projects/identity — importing their
# *ports* (not .domain/.adapters) is import-linter-legal (cross-module-scanning
# only forbids .domain/.adapters) and mirrors platform/di.py's
# get_current_github_access_token, just without Depends(). A repo URL, its auth
# token and a project's scanner configuration genuinely live in those two other
# modules; Scan itself only ever carries project_id/triggered_by.
#
# NormalizationRunRepositoryPort is the same legality but a different shape:
# the three above are *reads*, this one is a *write* into another module's
# table, which is why its method takes primitives rather than a
# NormalizationRun — constructing that entity here would be a direct
# .domain import and the contract would reject it. It is also why this use
# case's unit of work now spans two modules, recorded in ARCHITECTURE.md §9
# and decided in ADR-0017 decision 1.
from verion.modules.identity.ports.github_connection_repository import (
    GitHubConnectionRepositoryPort,
)
from verion.modules.normalization.ports.normalization_run_repository import (
    NormalizationRunRepositoryPort,
)
from verion.modules.projects.ports.connected_repo_repository import ConnectedRepoRepositoryPort
from verion.modules.projects.ports.scanner_config_repository import ScannerConfigRepositoryPort
from verion.modules.scanning.domain.exceptions import (
    ConnectedRepoNotFound,
    GitHubConnectionNotFound,
    NoScannersEnabled,
    RepoCheckoutFailed,
    UnknownScanner,
    UnsupportedRepoProvider,
)
from verion.modules.scanning.domain.scan import ScanStatus
from verion.modules.scanning.domain.scan_result import ScanResult
from verion.modules.scanning.domain.scanner_dispatch import (
    derive_scan_status,
    resolve_enabled_tools,
)
from verion.modules.scanning.domain.scanner_target_kind import ScannerTargetKind
from verion.modules.scanning.ports.repo_checkout import RepoCheckoutPort
from verion.modules.scanning.ports.scan_repository import ScanRepositoryPort
from verion.modules.scanning.ports.scan_result_repository import ScanResultRepositoryPort
from verion.modules.scanning.ports.scanner import ScannerPort
from verion.shared_kernel.ports import ClockPort, IdGeneratorPort
from verion.shared_kernel.scanner_tools import ScannerTool

# A tool's stderr lands in a persisted failure_reason, and a pathological run
# can emit megabytes of it. Bounded so one bad scan can't bloat the row (and,
# once a future endpoint surfaces this, the response).
_MAX_FAILURE_REASON_CHARS = 2000


class RunScanUseCase:
    """Runs every scanner enabled for the project, concurrently, in one job.

    **Dispatch shape (ADR-016 decision 1).** One arq job per Scan rather than
    one per (scan, tool), for snapshot coherence above all: fan-out means each
    job does its own checkout, so a push landing mid-scan gives Semgrep and
    Trivy different commits — and M5 correlates a Semgrep file:line against a
    Trivy dependency finding on the premise that both saw the same tree. One
    job checks out once, so that premise holds by construction. It also keeps
    this use case the sole owner of Scan status, as M3.3 designed it.

    **Idempotency, concretely:** unchanged from M3.3 except that PARTIAL joins
    RUNNING in not short-circuiting. Only COMPLETED does. A retry re-runs
    *every* enabled scanner, not just the failed ones — re-running only the
    failures would pair a fresh-checkout ZAP result with a stale Semgrep result
    from an older commit, which is the same incoherence rejected above arriving
    by a different door. Real work repeated, buying correctness in that window
    rather than work-avoidance; the (scan_id, tool) upsert keeps the final
    persisted state correct either way.

    **What raises and what doesn't.** A failure *before any tool runs* (no
    connected repo, no GitHub connection, unsupported provider, failed
    checkout, no scanners enabled, an unknown scanner) marks the Scan FAILED
    and re-raises, so arq's retry/backoff still applies — a checkout that
    failed on a network blip is worth retrying. A failure *of a tool* does not
    raise: it is a recorded outcome on that tool's ScanResult, and the scan has
    reached a terminal, truthful state. Letting arq retry there would re-run
    every scanner and could discard output that already succeeded, which is
    precisely the corruption PRODUCT_SPEC.md §12 forbids. This is a deliberate
    change from M3.3's single-scanner behaviour, where any scanner failure
    re-raised.

    **What it hands off (ADR-0017 decision 2).** Persisting the ScanResult rows
    ends this stage, not the pipeline. In the same transaction this use case
    records that normalization is owed for the scan, so the handoff survives a
    lost enqueue and cannot be half-written. Note the status this sets is still
    scanner-scoped: COMPLETED means every enabled scanner finished, never that
    the pipeline finished. Nothing downstream may read it — M4 reads
    get_succeeded_by_scan_id.
    """

    def __init__(
        self,
        scans: ScanRepositoryPort,
        scan_results: ScanResultRepositoryPort,
        scanners: Mapping[ScannerTool, ScannerPort],
        repo_checkout: RepoCheckoutPort,
        connected_repos: ConnectedRepoRepositoryPort,
        github_connections: GitHubConnectionRepositoryPort,
        scanner_configs: ScannerConfigRepositoryPort,
        normalization_runs: NormalizationRunRepositoryPort,
        id_generator: IdGeneratorPort,
        clock: ClockPort,
    ) -> None:
        self._scans = scans
        self._scan_results = scan_results
        self._scanners = scanners
        self._repo_checkout = repo_checkout
        self._connected_repos = connected_repos
        self._github_connections = github_connections
        self._scanner_configs = scanner_configs
        self._normalization_runs = normalization_runs
        self._id_generator = id_generator
        self._clock = clock

    async def execute(self, scan_id: str) -> None:
        scan = await self._scans.get_by_id(scan_id)
        if scan is None:
            raise ValueError(f"No scan with id '{scan_id}'")

        # Redelivered-after-success: the job already ran to completion once,
        # nothing left to do. Still the only status that short-circuits — see
        # the class docstring for why RUNNING and PARTIAL do not.
        if scan.status == ScanStatus.COMPLETED:
            return

        scan = dataclasses.replace(
            scan,
            status=ScanStatus.RUNNING,
            # Only set on first attempt — a retry must not overwrite the
            # original start time.
            started_at=scan.started_at or self._clock.now(),
        )
        await self._scans.update(scan)

        local_path: str | None = None
        try:
            config = await self._scanner_configs.get_by_project_id(scan.project_id)
            # `is not None`, never truthiness: an empty enabled_tools means
            # "configured to run nothing" and must not silently fall back to
            # the default, which is what an unconfigured project gets.
            enabled_tools = resolve_enabled_tools(
                config.enabled_tools if config is not None else None
            )
            zap_target_url = config.zap_target_url if config is not None else None

            if not enabled_tools:
                raise NoScannersEnabled(f"No scanners enabled for project '{scan.project_id}'")

            selected = self._select_scanners(enabled_tools)

            if any(scanner.target_kind is ScannerTargetKind.REPO_PATH for scanner in selected):
                local_path = await self._checkout_repo(scan.project_id, scan.triggered_by)

            # One checkout, N scanners, all against that same tree. gather with
            # per-scanner isolation inside _run_scanner, which never raises —
            # so one tool's failure can't cancel a sibling mid-run and discard
            # output that was about to succeed.
            results = await asyncio.gather(
                *(
                    self._run_scanner(scan.id, scanner, local_path, zap_target_url)
                    for scanner in selected
                )
            )

            for result in results:
                await self._scan_results.upsert(result)

            # **Ordering constraint, not incidental placement** (ADR-0017
            # decision 2). This must sit after the upsert loop and *before* the
            # status update below. Reversed, a failure writing this row would
            # still commit COMPLETED — worker.py commits in `finally` — and the
            # retry would return immediately at the `== COMPLETED` guard above,
            # so normalization would be lost silently and permanently.
            #
            # In this order the scan is never left COMPLETED, whichever way the
            # write fails, and that is the whole property: a DB error aborts the
            # transaction, so the `finally` commit raises PendingRollbackError
            # and even the RUNNING flush above rolls back, leaving the scan at
            # its last committed status (PENDING on a first attempt); any other
            # exception commits RUNNING. Neither short-circuits, so arq's retry
            # picks it up either way.
            #
            # Same transaction as the ScanResult rows, deliberately: one commit
            # covers both, so the row *is* the outbox and there is no
            # Postgres-commit-plus-Redis-enqueue dual write to compensate for.
            # The write is idempotent (ON CONFLICT DO NOTHING on scan_id), so a
            # retry re-requesting a run that already exists is a no-op rather
            # than an IntegrityError loop.
            await self._normalization_runs.request(
                id=self._id_generator.new_id(),
                scan_id=scan.id,
                # The dedup scope. `normalization` can reach a project through
                # none of its own inputs, and this use case already holds one —
                # so the handoff row carries it (ADR-0019 decision 7). Still
                # primitives, so nothing here learns that module's domain.
                project_id=scan.project_id,
                requested_at=self._clock.now(),
            )

            scan = dataclasses.replace(
                scan, status=derive_scan_status(results), finished_at=self._clock.now()
            )
            await self._scans.update(scan)
        except (
            ConnectedRepoNotFound,
            UnsupportedRepoProvider,
            GitHubConnectionNotFound,
            RepoCheckoutFailed,
            NoScannersEnabled,
            UnknownScanner,
        ) as exc:
            # Nothing ran, so there are no per-tool outcomes to preserve: this
            # is the Scan-level failure_reason keeping exactly the meaning M3.3
            # gave it.
            scan = dataclasses.replace(
                scan,
                status=ScanStatus.FAILED,
                finished_at=self._clock.now(),
                failure_reason=str(exc),
            )
            await self._scans.update(scan)
            # Re-raise so arq's own retry/backoff still applies — persisting
            # FAILED is for visibility, not to stop arq from retrying.
            raise
        finally:
            if local_path is not None:
                await self._repo_checkout.cleanup(local_path)

    def _select_scanners(self, enabled_tools: tuple[ScannerTool, ...]) -> list[ScannerPort]:
        selected: list[ScannerPort] = []
        for tool in enabled_tools:
            scanner = self._scanners.get(tool)
            if scanner is None:
                raise UnknownScanner(f"No scanner adapter registered for tool '{tool}'")
            selected.append(scanner)
        return selected

    async def _checkout_repo(self, project_id: str, triggered_by: str) -> str:
        connected_repo = await self._connected_repos.get_by_project_id(project_id)
        if connected_repo is None:
            raise ConnectedRepoNotFound(f"No connected repo for project '{project_id}'")

        if connected_repo.provider != "github":
            raise UnsupportedRepoProvider(
                f"Connected repo for project '{project_id}' uses provider "
                f"'{connected_repo.provider}', not 'github'"
            )

        # triggered_by is always the project owner — TriggerScanUseCase
        # requires is_owner=True before ever creating the Scan.
        github_connection = await self._github_connections.get_by_user_id(triggered_by)
        if github_connection is None:
            raise GitHubConnectionNotFound(f"No GitHub connection for user '{triggered_by}'")

        return await self._repo_checkout.checkout(
            connected_repo.url, github_connection.access_token
        )

    async def _run_scanner(
        self,
        scan_id: str,
        scanner: ScannerPort,
        local_path: str | None,
        zap_target_url: str | None,
    ) -> ScanResult:
        """Runs one scanner and returns its outcome. Never raises."""
        if scanner.target_kind is ScannerTargetKind.REPO_PATH:
            target = local_path
        else:
            target = zap_target_url

        if target is None:
            # A URL-kind scanner enabled with nothing to point at. The write
            # path rejects this combination, so it means config was written
            # around it — still that tool's failure, not the scan's, so the
            # other scanners' output survives.
            return self._failed(scan_id, scanner, f"No target configured for '{scanner.tool}'")

        try:
            raw_result = await scanner.run(target)
        except Exception as exc:
            # Deliberately broad. An adapter failing in a way nobody
            # anticipated must not take down a sibling that succeeded — that
            # tolerance is exactly what PRODUCT_SPEC.md §12 requires, and
            # narrowing this to ScannerExecutionFailed would make it hold only
            # for failures we thought of in advance.
            return self._failed(scan_id, scanner, f"{type(exc).__name__}: {exc}")

        return ScanResult.succeeded(
            id=self._id_generator.new_id(),
            scan_id=scan_id,
            # scanner.tool, not raw_result.tool: the identity dispatch selected
            # on is the identity persisted. They are the same constant, and
            # reading it from here means they cannot drift even if an adapter
            # someday builds its RawScanResult differently.
            tool=str(scanner.tool),
            raw_output=raw_result.raw_output,
        )

    def _failed(self, scan_id: str, scanner: ScannerPort, reason: str) -> ScanResult:
        return ScanResult.failed(
            id=self._id_generator.new_id(),
            scan_id=scan_id,
            tool=str(scanner.tool),
            failure_reason=reason[:_MAX_FAILURE_REASON_CHARS],
        )
