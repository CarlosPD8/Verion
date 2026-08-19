from verion.modules.projects.domain.authorization import require_owner
from verion.modules.projects.domain.exceptions import ProjectNotFound
from verion.modules.projects.domain.project import ConnectedRepo
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

        connected_repo = ConnectedRepo(
            id=self._id_generator.new_id(),
            project_id=project_id,
            provider=provider,
            url=url,
            default_branch=default_branch,
        )
        await self._connected_repos.add(connected_repo)

        return connected_repo
