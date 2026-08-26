from datetime import UTC, datetime

import pytest

from verion.modules.identity.domain.github_connection import GitHubConnection
from verion.modules.identity.domain.user import User
from verion.modules.normalization.domain.finding import (
    Finding,
    FindingSighting,
    SightedFinding,
    merge_observation,
)
from verion.modules.normalization.domain.normalization_run import (
    NormalizationRun,
    NormalizationRunStatus,
)
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
from verion.shared_kernel.severity import Severity


class InMemoryProjectAccess:
    """`ProjectAccessPort` — a set of (project_id, user_id) pairs that may read.

    A set rather than a membership store, deliberately: the port returns a verdict
    and cannot say WHY access was denied, so a fake that modelled memberships
    would be modelling more than the port exposes and would invite a test to
    assert on a distinction no consumer can observe.
    """

    def __init__(self, permitted: set[tuple[str, str]] | None = None) -> None:
        self._permitted = permitted or set()
        self.calls: list[tuple[str, str]] = []

    def permit(self, project_id: str, user_id: str) -> None:
        self._permitted.add((project_id, user_id))

    async def may_read_project(self, *, project_id: str, user_id: str) -> bool:
        self.calls.append((project_id, user_id))
        return (project_id, user_id) in self._permitted


class ExplodingFindingRepository:
    """Every read raises. Proves a use case authorized BEFORE it touched storage.

    The gate-placement assertion, in the shape ADR-0013 established for the SSRF
    validators: a check that happens to run first is not the same as a check that
    must. If an authorization check is moved below a read by a later refactor,
    nothing else in the suite would fail — the denial still happens, just after
    the database was consulted with an unauthorized caller's project id.
    """

    async def list_for_project(self, **_: object) -> list[SightedFinding]:
        raise AssertionError("the repository was read before authorization")

    async def count_for_project(self, **_: object) -> int:
        raise AssertionError("the repository was read before authorization")

    async def get_by_id(self, **_: object) -> Finding | None:
        raise AssertionError("the repository was read before authorization")

    # Added at M5.8, when CorrelateFindingsUseCase became the first consumer to reach for
    # this read. Without it the gate test still fails when the check is moved below the
    # query — but on AttributeError, which reports a missing method rather than the defect
    # the fake exists to name.
    async def get_by_project_id(self, *_: object, **__: object) -> list[Finding]:
        raise AssertionError("the repository was read before authorization")


class ExplodingNormalizationRunRepository:
    """Every envelope read raises. `ExplodingFindingRepository`'s twin, for M5.2.

    `ListProjectRisksUseCase` reads two ports, and only the first sits behind the access
    check by construction. This one is what makes the second's placement provable too.
    """

    async def get_latest_by_project_id(self, *_: object, **__: object) -> None:
        raise AssertionError("the run repository was read before authorization")

    async def count_unfinished_by_project_id(self, *_: object, **__: object) -> int:
        raise AssertionError("the run repository was read before authorization")


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
        # (scan_id, project_id) rather than scan_id alone, so a caller that
        # dropped the dedup scope — which no CHECK constraint or type could
        # catch, both being str — fails a unit test rather than reaching M4.4.
        self.request_calls: list[tuple[str, str]] = []

    async def request(
        self, *, id: str, scan_id: str, project_id: str, requested_at: datetime
    ) -> None:
        self.request_calls.append((scan_id, project_id))
        # DO NOTHING, never DO UPDATE: overwriting would reset a running or
        # completed row back to pending (ADR-0017 decision 2).
        if scan_id in self._runs:
            return
        self._runs[scan_id] = NormalizationRun.requested(
            id=id, scan_id=scan_id, project_id=project_id, requested_at=requested_at
        )

    async def get_by_scan_id(self, scan_id: str) -> NormalizationRun | None:
        return self._runs.get(scan_id)

    async def claim(self, *, scan_id: str, now: datetime) -> NormalizationRun | None:
        run = self._runs.get(scan_id)
        if run is None or run.status is NormalizationRunStatus.COMPLETED:
            return None
        claimed = run.start(now)
        self._runs[scan_id] = claimed
        return claimed

    async def update(self, run: NormalizationRun) -> None:
        self._runs[run.scan_id] = run

    async def get_stale(self, *, older_than: datetime, limit: int) -> list[NormalizationRun]:
        # Mirrors the Postgres adapter's predicate, including RUNNING, so the
        # sweep use case's behaviour is provable without a database. The
        # INVARIANT that it never reads Scan.status is not provable here — this
        # fake has no scans to read — which is exactly why that assertion lives
        # in the integration test instead.
        stale = [
            run
            for run in self._runs.values()
            if run.status in (NormalizationRunStatus.PENDING, NormalizationRunStatus.RUNNING)
            and run.requested_at < older_than
        ]
        return sorted(stale, key=lambda run: run.requested_at)[:limit]

    async def get_latest_by_project_id(self, project_id: str) -> NormalizationRun | None:
        # requested_at DESC then id DESC, mirroring the adapter's total order —
        # two scans of one project can be requested within the same clock tick.
        for_project = [run for run in self._runs.values() if run.project_id == project_id]
        if not for_project:
            return None
        return max(for_project, key=lambda run: (run.requested_at, run.id))

    async def count_unfinished_by_project_id(self, project_id: str) -> int:
        return sum(
            1
            for run in self._runs.values()
            if run.project_id == project_id and run.status is not NormalizationRunStatus.COMPLETED
        )

    def seed(self, run: NormalizationRun) -> None:
        """Place a run in an arbitrary state, for tests about what happens next."""
        self._runs[run.scan_id] = run


class InMemoryFindingRepository:
    """Models the one behaviour the real upsert has that a naive fake does not:
    **it returns the STORED finding, not the one it was handed.**

    Identity is the `dedup_hash` and `id` is a surrogate, so on every scan after
    the first the observation arrives with a freshly generated id that LOSES to
    the stored one (ADR-0019 decision 1, ADR-0020 decision 5). A fake that
    returned its argument would make `record_sighting(finding_id=stored.id)` and
    `record_sighting(finding_id=observation.id)` indistinguishable, and the test
    that pins that contract would be vacuous.
    """

    def __init__(self) -> None:
        self._findings: dict[tuple[str, str], Finding] = {}
        self._sightings: dict[tuple[str, str], FindingSighting] = {}
        # Every call, in order, including the ones that resolved to an existing
        # row — so a test can assert on call COUNT, which is what ADR-0020
        # decision 5's "once per (finding, scan), with the complete count"
        # contract is actually about.
        self.upsert_calls: list[Finding] = []
        self.sighting_calls: list[FindingSighting] = []

    async def upsert(self, finding: Finding) -> Finding:
        self.upsert_calls.append(finding)
        key = (finding.project_id, finding.dedup_hash)
        existing = self._findings.get(key)
        stored = merge_observation(existing, finding) if existing is not None else finding
        self._findings[key] = stored
        return stored

    async def record_sighting(self, sighting: FindingSighting) -> None:
        self.sighting_calls.append(sighting)
        # Overwrite, never sum — match_count is a per-scan TOTAL, and summing
        # would double-count on the guaranteed retry path (ADR-0020 decision 5).
        self._sightings[(sighting.finding_id, sighting.scan_id)] = sighting

    async def get_by_project_id(self, project_id: str) -> list[Finding]:
        return sorted(
            (f for f in self._findings.values() if f.project_id == project_id),
            key=lambda f: f.dedup_hash,
        )

    def _matching(
        self, project_id: str, min_severity: Severity | None, source: ScannerTool | None
    ) -> list[Finding]:
        # Filters by RANK, mirroring the adapter's IN-over-members. Written as a
        # rank comparison rather than a copy of the adapter's member list so the
        # two agree by both deriving from Severity.rank rather than from each
        # other — including the consequence that UNKNOWN (rank 0) drops out of
        # every min_severity except itself.
        return [
            finding
            for finding in self._findings.values()
            if finding.project_id == project_id
            and (min_severity is None or finding.severity.rank >= min_severity.rank)
            and (source is None or finding.source is source)
        ]

    async def list_for_project(
        self,
        *,
        project_id: str,
        min_severity: Severity | None,
        source: ScannerTool | None,
        limit: int,
        offset: int,
    ) -> list[SightedFinding]:
        ordered = sorted(
            self._matching(project_id, min_severity, source),
            key=lambda f: (-f.severity.rank, f.dedup_hash),
        )
        page = ordered[offset : offset + limit]
        sighted: list[SightedFinding] = []
        for finding in page:
            observations = sorted(
                (s for s in self._sightings.values() if s.finding_id == finding.id),
                key=lambda s: (s.observed_at, s.scan_id),
            )
            if not observations:
                # The real adapter raises here too: NormalizeScanUseCase writes a
                # sighting in the same transaction as the upsert, so a finding
                # without one means something wrote around the repository.
                raise ValueError(f"Finding '{finding.id}' has no sightings")
            sighted.append(
                SightedFinding(
                    finding=finding,
                    first_seen_at=observations[0].observed_at,
                    last_seen_at=observations[-1].observed_at,
                    last_seen_scan_id=observations[-1].scan_id,
                    sighting_count=len(observations),
                    latest_match_count=observations[-1].match_count,
                )
            )
        return sighted

    async def count_for_project(
        self, *, project_id: str, min_severity: Severity | None, source: ScannerTool | None
    ) -> int:
        return len(self._matching(project_id, min_severity, source))

    async def get_by_id(self, *, project_id: str, finding_id: str) -> Finding | None:
        for finding in self._findings.values():
            if finding.id == finding_id and finding.project_id == project_id:
                return finding
        return None

    async def get_sightings_by_finding_id(self, finding_id: str) -> list[FindingSighting]:
        return sorted(
            (s for s in self._sightings.values() if s.finding_id == finding_id),
            key=lambda s: s.scan_id,
        )


class RecordingNormalizationQueue:
    def __init__(self, fail: bool = False) -> None:
        self.enqueued: list[str] = []
        self._fail = fail

    async def enqueue_normalization(self, scan_id: str) -> None:
        if self._fail:
            raise ConnectionError("simulated Redis outage")
        self.enqueued.append(scan_id)


@pytest.fixture
def finding_repository() -> InMemoryFindingRepository:
    return InMemoryFindingRepository()


@pytest.fixture
def project_access() -> InMemoryProjectAccess:
    return InMemoryProjectAccess()


@pytest.fixture
def exploding_finding_repository() -> ExplodingFindingRepository:
    return ExplodingFindingRepository()


@pytest.fixture
def exploding_normalization_run_repository() -> ExplodingNormalizationRunRepository:
    return ExplodingNormalizationRunRepository()


@pytest.fixture
def normalization_queue() -> RecordingNormalizationQueue:
    return RecordingNormalizationQueue()


@pytest.fixture
def clock_factory() -> type[FakeClock]:
    """Lets a test pin a `now` other than the shared `clock` fixture's.

    Same shape as `dns_resolver_factory`. The sweep's tests need a clock they can
    position relative to a run's `requested_at`, which a fixed fixture cannot do.
    """
    return FakeClock


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
