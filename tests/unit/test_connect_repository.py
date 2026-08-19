import pytest

from verion.modules.projects.application.connect_repository import ConnectRepositoryUseCase
from verion.modules.projects.domain.exceptions import InsufficientPermissions, ProjectNotFound
from verion.modules.projects.domain.project import Project, ProjectMembership, Role


async def _seed_project(project_repository, clock, project_id="project-1", owner_id="owner-1"):
    project = Project(id=project_id, owner_id=owner_id, name="Verion", created_at=clock.now())
    await project_repository.add(project)
    return project


def _use_case(project_repository, membership_repository, connected_repo_repository, id_generator):
    return ConnectRepositoryUseCase(
        projects=project_repository,
        memberships=membership_repository,
        connected_repos=connected_repo_repository,
        id_generator=id_generator,
    )


async def test_connects_a_repository_as_owner(
    project_repository, membership_repository, connected_repo_repository, clock, id_generator
):
    project = await _seed_project(project_repository, clock)
    await membership_repository.add(
        ProjectMembership(project_id=project.id, user_id="owner-1", role=Role.OWNER)
    )
    use_case = _use_case(
        project_repository, membership_repository, connected_repo_repository, id_generator
    )

    connected_repo = await use_case.execute(
        project_id=project.id,
        user_id="owner-1",
        provider="github",
        url="https://github.com/example/repo",
        default_branch="main",
    )

    assert connected_repo.project_id == project.id
    assert await connected_repo_repository.get_by_id(connected_repo.id) == connected_repo


async def test_rejects_a_non_member(
    project_repository, membership_repository, connected_repo_repository, clock, id_generator
):
    project = await _seed_project(project_repository, clock)
    use_case = _use_case(
        project_repository, membership_repository, connected_repo_repository, id_generator
    )

    with pytest.raises(InsufficientPermissions):
        await use_case.execute(
            project_id=project.id,
            user_id="stranger",
            provider="github",
            url="https://github.com/example/repo",
            default_branch="main",
        )


async def test_rejects_a_member_who_is_not_an_owner(
    project_repository, membership_repository, connected_repo_repository, clock, id_generator
):
    project = await _seed_project(project_repository, clock)
    await membership_repository.add(
        ProjectMembership(project_id=project.id, user_id="member-1", role=Role.MEMBER)
    )
    use_case = _use_case(
        project_repository, membership_repository, connected_repo_repository, id_generator
    )

    with pytest.raises(InsufficientPermissions):
        await use_case.execute(
            project_id=project.id,
            user_id="member-1",
            provider="github",
            url="https://github.com/example/repo",
            default_branch="main",
        )


async def test_raises_project_not_found_for_an_unknown_project(
    project_repository, membership_repository, connected_repo_repository, id_generator
):
    use_case = _use_case(
        project_repository, membership_repository, connected_repo_repository, id_generator
    )

    with pytest.raises(ProjectNotFound):
        await use_case.execute(
            project_id="does-not-exist",
            user_id="owner-1",
            provider="github",
            url="https://github.com/example/repo",
            default_branch="main",
        )
