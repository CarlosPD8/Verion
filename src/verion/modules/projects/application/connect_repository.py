from verion.modules.projects.domain.authorization import require_owner
from verion.modules.projects.domain.exceptions import ProjectNotFound
from verion.modules.projects.domain.project import ConnectedRepo, validate_connected_repo_url
from verion.modules.projects.ports.connected_repo_repository import ConnectedRepoRepositoryPort
from verion.modules.projects.ports.project_membership_repository import (
    ProjectMembershipRepositoryPort,
)
from verion.modules.projects.ports.project_repository import ProjectRepositoryPort
from verion.shared_kernel.ports import IdGeneratorPort


class ConnectRepositoryUseCase:
    def __init__(
        self,
        projects: ProjectRepositoryPort,
        memberships: ProjectMembershipRepositoryPort,
        connected_repos: ConnectedRepoRepositoryPort,
        id_generator: IdGeneratorPort,
    ) -> None:
        self._projects = projects
        self._memberships = memberships
        self._connected_repos = connected_repos
        self._id_generator = id_generator

    async def execute(
        self, project_id: str, user_id: str, provider: str, url: str, default_branch: str
    ) -> ConnectedRepo:
        project = await self._projects.get_by_id(project_id)
        if project is None:
            raise ProjectNotFound(f"No project with id '{project_id}'")

        membership = await self._memberships.get_by_project_and_user(project_id, user_id)
        require_owner(membership)
        # Only this write path can carry userinfo. ConnectRepositoryViaGitHubUseCase builds
        # `https://github.com/{owner}/{repo}` itself, whose netloc is always github.com.
        validate_connected_repo_url(url)

        existing = await self._connected_repos.get_by_project_id(project_id)
        connected_repo = ConnectedRepo(
            # Reuses the existing row's id when there is one: this is one repository per
            # project being re-pointed, not a new record each time it changes —
            # UpdateScannerConfigUseCase's wording, one relation over. Without the reuse
            # the upsert keeps the stored id and this would return a different one.
            id=existing.id if existing is not None else self._id_generator.new_id(),
            project_id=project_id,
            provider=provider,
            url=url,
            default_branch=default_branch,
        )
        await self._connected_repos.upsert(connected_repo)

        return connected_repo
