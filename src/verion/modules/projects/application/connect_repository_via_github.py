from verion.modules.projects.domain.authorization import require_owner
from verion.modules.projects.domain.exceptions import ProjectNotFound
from verion.modules.projects.domain.project import ConnectedRepo
from verion.modules.projects.ports.connected_repo_repository import ConnectedRepoRepositoryPort
from verion.modules.projects.ports.project_membership_repository import (
    ProjectMembershipRepositoryPort,
)
from verion.modules.projects.ports.project_repository import ProjectRepositoryPort
from verion.modules.projects.ports.vcs_provider import VcsProviderPort
from verion.shared_kernel.ports import IdGeneratorPort


class ConnectRepositoryViaGitHubUseCase:
    def __init__(
        self,
        projects: ProjectRepositoryPort,
        memberships: ProjectMembershipRepositoryPort,
        connected_repos: ConnectedRepoRepositoryPort,
        vcs_provider: VcsProviderPort,
        id_generator: IdGeneratorPort,
    ) -> None:
        self._projects = projects
        self._memberships = memberships
        self._connected_repos = connected_repos
        self._vcs_provider = vcs_provider
        self._id_generator = id_generator

    async def execute(
        self, project_id: str, user_id: str, access_token: str, owner: str, repo: str
    ) -> ConnectedRepo:
        project = await self._projects.get_by_id(project_id)
        if project is None:
            raise ProjectNotFound(f"No project with id '{project_id}'")

        membership = await self._memberships.get_by_project_and_user(project_id, user_id)
        require_owner(membership)

        metadata = await self._vcs_provider.fetch_repo_metadata(access_token, owner, repo)

        connected_repo = ConnectedRepo(
            id=self._id_generator.new_id(),
            project_id=project_id,
            provider="github",
            url=f"https://github.com/{owner}/{repo}",
            default_branch=metadata.default_branch,
        )
        await self._connected_repos.add(connected_repo)

        # M3.6: registers this app's push webhook using the same scope=repo
        # token already granted at OAuth-connect time (M1.5a) — no new
        # user-facing authorization step. Composed as the last step of this
        # use case rather than a separate endpoint, per ROADMAP.md's M3.6
        # "GitHub Actions integration / webhook receiver" line.
        await self._vcs_provider.register_webhook(access_token, owner, repo)

        return connected_repo
