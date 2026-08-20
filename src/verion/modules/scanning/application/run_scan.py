import dataclasses

# ConnectedRepoRepositoryPort/GitHubConnectionRepositoryPort belong to
# projects/identity — importing their *ports* (not .domain/.adapters) is
# import-linter-legal (cross-module-scanning only forbids .domain/.adapters)
# and mirrors platform/di.py's get_current_github_access_token, just without
# Depends(). A repo URL and its auth token genuinely live in those two other
# modules; Scan itself only ever carries project_id/triggered_by.
from verion.modules.identity.ports.github_connection_repository import (
    GitHubConnectionRepositoryPort,
)
from verion.modules.projects.ports.connected_repo_repository import ConnectedRepoRepositoryPort
from verion.modules.scanning.domain.exceptions import (
    ConnectedRepoNotFound,
    GitHubConnectionNotFound,
    RepoCheckoutFailed,
    ScannerExecutionFailed,
    UnsupportedRepoProvider,
)
from verion.modules.scanning.domain.scan import ScanStatus
from verion.modules.scanning.domain.scan_result import ScanResult
from verion.modules.scanning.ports.repo_checkout import RepoCheckoutPort
from verion.modules.scanning.ports.scan_repository import ScanRepositoryPort
from verion.modules.scanning.ports.scan_result_repository import ScanResultRepositoryPort
from verion.modules.scanning.ports.scanner import ScannerPort
from verion.shared_kernel.ports import ClockPort, IdGeneratorPort


class RunScanUseCase:
    """Idempotency, concretely: if a retry lands while Scan.status is still
    RUNNING (the process was killed after ScanResult was upserted but before
    Scan was marked COMPLETED — no exception was raised, so FAILED was never
    set either), this re-does the checkout and re-runs the scanner in full.
    That's real work repeated, not a cheap resume — only COMPLETED short-
    circuits. The (scan_id, tool) unique-constraint upsert guarantees the
    *final persisted state* is still correct (one row, not a duplicate), but
    this design buys correctness in that window, not work-avoidance. Accepted
    MVP trade-off, not a hidden gap.
    """

    def __init__(
        self,
        scans: ScanRepositoryPort,
        scan_results: ScanResultRepositoryPort,
        scanner: ScannerPort,
        repo_checkout: RepoCheckoutPort,
        connected_repos: ConnectedRepoRepositoryPort,
        github_connections: GitHubConnectionRepositoryPort,
        id_generator: IdGeneratorPort,
        clock: ClockPort,
    ) -> None:
        self._scans = scans
        self._scan_results = scan_results
        self._scanner = scanner
        self._repo_checkout = repo_checkout
        self._connected_repos = connected_repos
        self._github_connections = github_connections
        self._id_generator = id_generator
        self._clock = clock

    async def execute(self, scan_id: str) -> None:
        scan = await self._scans.get_by_id(scan_id)
        if scan is None:
            raise ValueError(f"No scan with id '{scan_id}'")

        # Redelivered-after-success: the job already ran to completion once,
        # nothing left to do. This is the only status that short-circuits —
        # see the class docstring for why RUNNING does not.
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
            connected_repo = await self._connected_repos.get_by_project_id(scan.project_id)
            if connected_repo is None:
                raise ConnectedRepoNotFound(f"No connected repo for project '{scan.project_id}'")

            if connected_repo.provider != "github":
                raise UnsupportedRepoProvider(
                    f"Connected repo for project '{scan.project_id}' uses provider "
                    f"'{connected_repo.provider}', not 'github'"
                )

            # triggered_by is always the project owner — TriggerScanUseCase
            # requires is_owner=True before ever creating the Scan.
            github_connection = await self._github_connections.get_by_user_id(scan.triggered_by)
            if github_connection is None:
                raise GitHubConnectionNotFound(
                    f"No GitHub connection for user '{scan.triggered_by}'"
                )

            local_path = await self._repo_checkout.checkout(
                connected_repo.url, github_connection.access_token
            )
            raw_result = await self._scanner.run(local_path)

            await self._scan_results.upsert(
                ScanResult(
                    id=self._id_generator.new_id(),
                    scan_id=scan.id,
                    tool=raw_result.tool,
                    raw_output=raw_result.raw_output,
                )
            )

            scan = dataclasses.replace(
                scan, status=ScanStatus.COMPLETED, finished_at=self._clock.now()
            )
            await self._scans.update(scan)
        except (
            ConnectedRepoNotFound,
            UnsupportedRepoProvider,
            GitHubConnectionNotFound,
            RepoCheckoutFailed,
            ScannerExecutionFailed,
        ) as exc:
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
