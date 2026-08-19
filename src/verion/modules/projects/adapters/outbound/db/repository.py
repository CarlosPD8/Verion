from sqlalchemy.ext.asyncio import AsyncSession

from verion.modules.projects.adapters.outbound.db.models import (
    ConnectedRepoModel,
    ProjectMembershipModel,
    ProjectModel,
)
from verion.modules.projects.domain.project import ConnectedRepo, Project, ProjectMembership, Role


def _project_to_domain(model: ProjectModel) -> Project:
    return Project(
        id=model.id, owner_id=model.owner_id, name=model.name, created_at=model.created_at
    )


def _project_from_domain(project: Project) -> ProjectModel:
    return ProjectModel(
        id=project.id,
        owner_id=project.owner_id,
        name=project.name,
        created_at=project.created_at,
    )


def _connected_repo_to_domain(model: ConnectedRepoModel) -> ConnectedRepo:
    return ConnectedRepo(
        id=model.id,
        project_id=model.project_id,
        provider=model.provider,
        url=model.url,
        default_branch=model.default_branch,
    )


def _connected_repo_from_domain(connected_repo: ConnectedRepo) -> ConnectedRepoModel:
    return ConnectedRepoModel(
        id=connected_repo.id,
        project_id=connected_repo.project_id,
        provider=connected_repo.provider,
        url=connected_repo.url,
        default_branch=connected_repo.default_branch,
    )


def _membership_to_domain(model: ProjectMembershipModel) -> ProjectMembership:
    return ProjectMembership(
        project_id=model.project_id, user_id=model.user_id, role=Role(model.role)
    )


def _membership_from_domain(membership: ProjectMembership) -> ProjectMembershipModel:
    return ProjectMembershipModel(
        project_id=membership.project_id,
        user_id=membership.user_id,
        role=str(membership.role),
    )


class PostgresProjectRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, project: Project) -> None:
        self._session.add(_project_from_domain(project))
        await self._session.flush()

    async def get_by_id(self, project_id: str) -> Project | None:
        model = await self._session.get(ProjectModel, project_id)
        return _project_to_domain(model) if model is not None else None


class PostgresConnectedRepoRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, connected_repo: ConnectedRepo) -> None:
        self._session.add(_connected_repo_from_domain(connected_repo))
        await self._session.flush()

    async def get_by_id(self, connected_repo_id: str) -> ConnectedRepo | None:
        model = await self._session.get(ConnectedRepoModel, connected_repo_id)
        return _connected_repo_to_domain(model) if model is not None else None


class PostgresProjectMembershipRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, membership: ProjectMembership) -> None:
        self._session.add(_membership_from_domain(membership))
        await self._session.flush()

    async def get_by_project_and_user(
        self, project_id: str, user_id: str
    ) -> ProjectMembership | None:
        model = await self._session.get(ProjectMembershipModel, (project_id, user_id))
        return _membership_to_domain(model) if model is not None else None
