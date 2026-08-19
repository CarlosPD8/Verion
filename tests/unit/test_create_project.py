from verion.modules.projects.application.create_project import CreateProjectUseCase
from verion.modules.projects.domain.project import Role


async def test_creates_a_project(project_repository, membership_repository, clock, id_generator):
    use_case = CreateProjectUseCase(
        projects=project_repository,
        memberships=membership_repository,
        clock=clock,
        id_generator=id_generator,
    )

    project = await use_case.execute(owner_id="user-1", name="Verion")

    assert project.owner_id == "user-1"
    assert project.name == "Verion"
    assert project.created_at == clock.now()
    assert await project_repository.get_by_id(project.id) == project


async def test_auto_creates_an_owner_membership_for_the_creator(
    project_repository, membership_repository, clock, id_generator
):
    use_case = CreateProjectUseCase(
        projects=project_repository,
        memberships=membership_repository,
        clock=clock,
        id_generator=id_generator,
    )

    project = await use_case.execute(owner_id="user-1", name="Verion")

    membership = await membership_repository.get_by_project_and_user(project.id, "user-1")
    assert membership is not None
    assert membership.role is Role.OWNER
