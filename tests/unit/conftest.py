from datetime import UTC, datetime

import pytest

from verion.modules.identity.domain.user import User
from verion.modules.projects.domain.exceptions import GitHubApiError
from verion.modules.projects.domain.project import ConnectedRepo, Project, ProjectMembership
from verion.modules.projects.domain.security_context import SecurityContext
from verion.modules.projects.ports.vcs_provider import RepoMetadata


class InMemoryUserRepository:
    def __init__(self) -> None:
        self._users: dict[str, User] = {}

    async def add(self, user: User) -> None:
        self._users[user.id] = user

    async def get_by_email(self, email: str) -> User | None:
        return next((u for u in self._users.values() if str(u.email) == email), None)

    async def get_by_id(self, user_id: str) -> User | None:
        return self._users.get(user_id)


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


class InMemorySecurityContextRepository:
    def __init__(self) -> None:
        self._contexts: dict[str, SecurityContext] = {}

    async def add(self, context: SecurityContext) -> None:
        self._contexts[context.project_id] = context

    async def get_by_project_id(self, project_id: str) -> SecurityContext | None:
        return self._contexts.get(project_id)


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


@pytest.fixture
def user_repository() -> InMemoryUserRepository:
    return InMemoryUserRepository()


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
