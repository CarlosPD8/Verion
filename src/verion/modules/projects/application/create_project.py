from verion.modules.projects.domain.project import Project, ProjectMembership, Role
from verion.modules.projects.ports.project_membership_repository import (
    ProjectMembershipRepositoryPort,
)
from verion.modules.projects.ports.project_repository import ProjectRepositoryPort
from verion.shared_kernel.ports import ClockPort, IdGeneratorPort


class CreateProjectUseCase:
    def __init__(
        self,
        projects: ProjectRepositoryPort,
        memberships: ProjectMembershipRepositoryPort,
        clock: ClockPort,
        id_generator: IdGeneratorPort,
    ) -> None:
        self._projects = projects
        self._memberships = memberships
        self._clock = clock
        self._id_generator = id_generator

    async def execute(self, owner_id: str, name: str) -> Project:
        project = Project(
            id=self._id_generator.new_id(),
            owner_id=owner_id,
            name=name,
            created_at=self._clock.now(),
        )
        await self._projects.add(project)

        await self._memberships.add(
            ProjectMembership(project_id=project.id, user_id=owner_id, role=Role.OWNER)
        )

        return project
