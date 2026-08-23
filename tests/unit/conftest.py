from datetime import UTC, datetime

import pytest

from verion.modules.identity.domain.github_connection import GitHubConnection
from verion.modules.identity.domain.user import User
from verion.modules.normalization.domain.normalization_run import NormalizationRun
from verion.modules.projects.domain.exceptions import GitHubApiError
from verion.modules.projects.domain.project import ConnectedRepo, Project, ProjectMembership
from verion.modules.projects.domain.scanner_config import ScannerConfig
from verion.modules.projects.domain.security_context import SecurityContext
from verion.modules.projects.ports.vcs_provider import RepoMetadata
from verion.modules.scanning.domain.exceptions import RepoCheckoutFailed, ScannerExecutionFailed
from verion.modules.scanning.domain.raw_scan_result import RawScanResult
from verion.modules.scanning.domain.scan import Scan
from verion.modules.scanning.domain.scan_result import ScanResult, ScanResultStatus
from verion.modules.scanning.domain.scanner_target_kind import ScannerTargetKind
from verion.shared_kernel.scanner_tools import ScannerTool


class InMemoryUserRepository:
    def __init__(self) -> None:
        self._users: dict[str, User] = {}

    async def add(self, user: User) -> None:
        self._users[user.id] = user

    async def get_by_email(self, email: str) -> User | None:
        return next((u for u in self._users.values() if str(u.email) == email), None)

    async def get_by_id(self, user_id: str) -> User | None:
        return self._users.get(user_id)


class InMemoryGitHubConnectionRepository:
    def __init__(self) -> None:
        self._connections: dict[str, GitHubConnection] = {}

    async def add(self, connection: GitHubConnection) -> None:
        self._connections[connection.user_id] = connection

    async def get_by_user_id(self, user_id: str) -> GitHubConnection | None:
        return self._connections.get(user_id)


class FakePasswordHasher:
    """Non-cryptographic stand-in — proves the use-case flow, not real security."""

    _PREFIX = "hashed:"

    def hash(self, plaintext_password: str) -> str:
        return f"{self._PREFIX}{plaintext_password}"

    def verify(self, plaintext_password: str, hashed_password: str) -> bool:
        return hashed_password == self.hash(plaintext_password)


class FakeClock:
    def __init__(self, fixed_now: datetime) -> None:
        self._fixed_now = fixed_now

    def now(self) -> datetime:
        return self._fixed_now


class FakeIdGenerator:
    def __init__(self) -> None:
        self._counter = 0

    def new_id(self) -> str:
        self._counter += 1
        return f"fake-id-{self._counter}"


class InMemoryProjectRepository:
    def __init__(self) -> None:
        self._projects: dict[str, Project] = {}

    async def add(self, project: Project) -> None:
        self._projects[project.id] = project

    async def get_by_id(self, project_id: str) -> Project | None:
        return self._projects.get(project_id)


class InMemoryProjectMembershipRepository:
    def __init__(self) -> None:
        self._memberships: dict[tuple[str, str], ProjectMembership] = {}

    async def add(self, membership: ProjectMembership) -> None:
        self._memberships[(membership.project_id, membership.user_id)] = membership

    async def get_by_project_and_user(
        self, project_id: str, user_id: str
    ) -> ProjectMembership | None:
        return self._memberships.get((project_id, user_id))


class InMemoryConnectedRepoRepository:
    def __init__(self) -> None:
        self._connected_repos: dict[str, ConnectedRepo] = {}

    async def add(self, connected_repo: ConnectedRepo) -> None:
        self._connected_repos[connected_repo.id] = connected_repo

    async def get_by_id(self, connected_repo_id: str) -> ConnectedRepo | None:
        return self._connected_repos.get(connected_repo_id)

    async def get_by_project_id(self, project_id: str) -> ConnectedRepo | None:
        return next(
            (repo for repo in self._connected_repos.values() if repo.project_id == project_id),
            None,
        )

    async def get_by_url(self, url: str) -> ConnectedRepo | None:
        return next((repo for repo in self._connected_repos.values() if repo.url == url), None)


class InMemorySecurityContextRepository:
    def __init__(self) -> None:
        self._contexts: dict[str, SecurityContext] = {}

    async def add(self, context: SecurityContext) -> None:
        self._contexts[context.project_id] = context

    async def get_by_project_id(self, project_id: str) -> SecurityContext | None:
        return self._contexts.get(project_id)

    async def update(self, context: SecurityContext) -> None:
        self._contexts[context.project_id] = context


class FakeVcsProvider:
    """Returns fixed metadata/files — proves the use-case flow, no real GitHub call."""

    def __init__(
        self,
        default_branch: str = "main",
        description: str = "",
        files: dict[str, str] | None = None,
        fail: bool = False,
    ) -> None:
        self._default_branch = default_branch
        self._description = description
        self._files = files or {}
        self._fail = fail
        self.registered_webhooks: list[tuple[str, str]] = []

    async def fetch_repo_metadata(self, access_token: str, owner: str, repo: str) -> RepoMetadata:
        if self._fail:
            raise GitHubApiError("simulated GitHub API failure")
        return RepoMetadata(default_branch=self._default_branch, description=self._description)

    async def list_repo_files(self, access_token: str, owner: str, repo: str) -> list[str]:
        if self._fail:
            raise GitHubApiError("simulated GitHub API failure")
        return list(self._files.keys())

    async def get_file_content(
        self, access_token: str, owner: str, repo: str, path: str
    ) -> str | None:
        if self._fail:
            raise GitHubApiError("simulated GitHub API failure")
        return self._files.get(path)

    async def register_webhook(self, access_token: str, owner: str, repo: str) -> None:
        if self._fail:
            raise GitHubApiError("simulated GitHub API failure")
        self.registered_webhooks.append((owner, repo))


@pytest.fixture
def user_repository() -> InMemoryUserRepository:
    return InMemoryUserRepository()


@pytest.fixture
def github_connection_repository() -> InMemoryGitHubConnectionRepository:
    return InMemoryGitHubConnectionRepository()


@pytest.fixture
def password_hasher() -> FakePasswordHasher:
    return FakePasswordHasher()


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock(fixed_now=datetime(2026, 1, 1, tzinfo=UTC))


@pytest.fixture
def id_generator() -> FakeIdGenerator:
    return FakeIdGenerator()


@pytest.fixture
def project_repository() -> InMemoryProjectRepository:
    return InMemoryProjectRepository()


@pytest.fixture
def membership_repository() -> InMemoryProjectMembershipRepository:
    return InMemoryProjectMembershipRepository()


@pytest.fixture
def connected_repo_repository() -> InMemoryConnectedRepoRepository:
    return InMemoryConnectedRepoRepository()


@pytest.fixture
def vcs_provider() -> FakeVcsProvider:
    return FakeVcsProvider()


@pytest.fixture
def vcs_provider_factory() -> type[FakeVcsProvider]:
    """Lets a test construct a FakeVcsProvider with custom files/fail args,
    without importing across test modules (tests/ isn't a package)."""
    return FakeVcsProvider


@pytest.fixture
def security_context_repository() -> InMemorySecurityContextRepository:
    return InMemorySecurityContextRepository()


class InMemoryScanRepository:
    def __init__(self) -> None:
        self._scans: dict[str, Scan] = {}

    async def add(self, scan: Scan) -> None:
        self._scans[scan.id] = scan

    async def get_by_id(self, scan_id: str) -> Scan | None:
        return self._scans.get(scan_id)

    async def update(self, scan: Scan) -> None:
        self._scans[scan.id] = scan


class FakeJobQueue:
    """Records enqueued scan IDs — proves the use-case flow, no real Redis."""

    def __init__(self) -> None:
        self.enqueued_scan_ids: list[str] = []

    async def enqueue_scan(self, scan_id: str) -> None:
        self.enqueued_scan_ids.append(scan_id)


@pytest.fixture
def scan_repository() -> InMemoryScanRepository:
    return InMemoryScanRepository()


@pytest.fixture
def job_queue() -> FakeJobQueue:
    return FakeJobQueue()


class InMemoryScanResultRepository:
    def __init__(self) -> None:
        # Keyed by (scan_id, tool) — mirrors the Postgres adapter's
        # (scan_id, tool) unique constraint, so upsert-not-insert behavior
        # is provable in unit tests too.
        self._results: dict[tuple[str, str], ScanResult] = {}

    async def upsert(self, scan_result: ScanResult) -> None:
        self._results[(scan_result.scan_id, scan_result.tool)] = scan_result

    async def get_by_scan_id(self, scan_id: str) -> list[ScanResult]:
        return [result for result in self._results.values() if result.scan_id == scan_id]

    async def get_succeeded_by_scan_id(self, scan_id: str) -> list[ScanResult]:
        return [
            result
            for result in self._results.values()
            if result.scan_id == scan_id and result.status is ScanResultStatus.SUCCEEDED
        ]


class InMemoryNormalizationRunRepository:
    def __init__(self) -> None:
        # Keyed by scan_id — mirrors the Postgres adapter's UNIQUE(scan_id), so
        # "a retry re-requesting an existing run is a no-op" is provable in unit
        # tests too, not only against real Postgres.
        self._runs: dict[str, NormalizationRun] = {}
        # Records every call, including the no-op ones, so a test can assert the
        # request was *made* on a retry and still did not overwrite the row.
        self.request_calls: list[str] = []

    async def request(self, *, id: str, scan_id: str, requested_at: datetime) -> None:
        self.request_calls.append(scan_id)
        # DO NOTHING, never DO UPDATE: overwriting would reset a running or
        # completed row back to pending (ADR-0017 decision 2).
        if scan_id in self._runs:
            return
        self._runs[scan_id] = NormalizationRun.requested(
            id=id, scan_id=scan_id, requested_at=requested_at
        )

    async def get_by_scan_id(self, scan_id: str) -> NormalizationRun | None:
        return self._runs.get(scan_id)


class InMemoryScannerConfigRepository:
    def __init__(self) -> None:
        self._configs: dict[str, ScannerConfig] = {}

    async def get_by_project_id(self, project_id: str) -> ScannerConfig | None:
        return self._configs.get(project_id)

    async def upsert(self, config: ScannerConfig) -> None:
        self._configs[config.project_id] = config


class FakeScanner:
    """Records each call to `run` — proves whether a retry redoes real work,
    no real subprocess.

    `tool`/`target_kind` are instance attributes rather than class constants
    (as the real adapters use) so one test can stand up several distinct fake
    scanners; ScannerPort is a Protocol, and an instance attribute satisfies it
    the same way.
    """

    def __init__(
        self,
        result: RawScanResult | None = None,
        fail: bool = False,
        tool: ScannerTool = ScannerTool.SEMGREP,
        target_kind: ScannerTargetKind = ScannerTargetKind.REPO_PATH,
        error: Exception | None = None,
    ) -> None:
        self.tool = tool
        self.target_kind = target_kind
        self._result = result or RawScanResult(tool=tool, raw_output="{}")
        self._fail = fail
        # Lets a test raise something *other* than ScannerExecutionFailed, to
        # prove per-scanner isolation holds for unanticipated failures too —
        # which is the whole reason RunScanUseCase catches broadly.
        self._error = error
        self.run_calls: list[str] = []

    async def run(self, target: str) -> RawScanResult:
        self.run_calls.append(target)
        if self._error is not None:
            raise self._error
        if self._fail:
            raise ScannerExecutionFailed("simulated scanner failure")
        return self._result


class FakeRepoCheckout:
    """Records each call to `checkout`/`cleanup` — proves whether a retry
    redoes real work, no real git subprocess."""

    def __init__(self, local_path: str = "/tmp/fake-checkout", fail: bool = False) -> None:
        self.local_path = local_path
        self._fail = fail
        self.checkout_calls: list[str] = []
        self.cleanup_calls: list[str] = []

    async def checkout(self, repo_url: str, access_token: str | None) -> str:
        self.checkout_calls.append(repo_url)
        if self._fail:
            raise RepoCheckoutFailed("simulated checkout failure")
        return self.local_path

    async def cleanup(self, local_path: str) -> None:
        self.cleanup_calls.append(local_path)


@pytest.fixture
def scan_result_repository() -> InMemoryScanResultRepository:
    return InMemoryScanResultRepository()


@pytest.fixture
def scanner_config_repository() -> InMemoryScannerConfigRepository:
    return InMemoryScannerConfigRepository()


@pytest.fixture
def normalization_run_repository() -> InMemoryNormalizationRunRepository:
    return InMemoryNormalizationRunRepository()


@pytest.fixture
def scanner() -> FakeScanner:
    return FakeScanner()


@pytest.fixture
def scanners(scanner: FakeScanner) -> dict[ScannerTool, FakeScanner]:
    """The single-scanner registry most RunScanUseCase tests want. A test
    exercising dispatch across several tools builds its own."""
    return {scanner.tool: scanner}


@pytest.fixture
def scanner_factory() -> type[FakeScanner]:
    """Lets a test construct a FakeScanner with custom result/fail/tool args."""
    return FakeScanner


@pytest.fixture
def repo_checkout() -> FakeRepoCheckout:
    return FakeRepoCheckout()


@pytest.fixture
def repo_checkout_factory() -> type[FakeRepoCheckout]:
    """Lets a test construct a FakeRepoCheckout with custom fail args."""
    return FakeRepoCheckout


class FakeDnsResolver:
    """Returns a fixed set of IPs for any hostname — proves ZapAdapter's SSRF
    gate reacts to the RESOLVED IP, not the hostname string, without a real
    DNS lookup."""

    def __init__(self, ips: list[str] | None = None) -> None:
        self._ips = ips if ips is not None else ["93.184.216.34"]
        self.resolve_calls: list[str] = []

    async def resolve(self, hostname: str) -> list[str]:
        self.resolve_calls.append(hostname)
        return self._ips


@pytest.fixture
def dns_resolver() -> FakeDnsResolver:
    return FakeDnsResolver()


@pytest.fixture
def dns_resolver_factory() -> type[FakeDnsResolver]:
    """Lets a test construct a FakeDnsResolver with custom resolved ips."""
    return FakeDnsResolver


class InMemoryWebhookDeliveryRepository:
    def __init__(self) -> None:
        self._seen: set[str] = set()
        # Records every call, including redeliveries — lets a test assert
        # the dedup check itself ran, not just its outcome.
        self.record_calls: list[str] = []

    async def record_if_new(self, delivery_id: str) -> bool:
        self.record_calls.append(delivery_id)
        if delivery_id in self._seen:
            return False
        self._seen.add(delivery_id)
        return True


@pytest.fixture
def webhook_delivery_repository() -> InMemoryWebhookDeliveryRepository:
    return InMemoryWebhookDeliveryRepository()
