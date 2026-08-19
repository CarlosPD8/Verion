import pytest

from verion.modules.projects.application.connect_repository_via_github import (
    ConnectRepositoryViaGitHubUseCase,
)
from verion.modules.projects.domain.exceptions import InsufficientPermissions, ProjectNotFound
from verion.modules.projects.domain.project import Project, ProjectMembership, Role


async def _seed_project(project_repository, clock, project_id="project-1", owner_id="owner-1"):
    project = Project(id=project_id, owner_id=owner_id, name="Verion", created_at=clock.now())
    await project_repository.add(project)
    return project


def _use_case(
    project_repository, membership_repository, connected_repo_repository, vcs_provider, id_generator
):
    return ConnectRepositoryViaGitHubUseCase(
        projects=project_repository,
        memberships=membership_repository,
        connected_repos=connected_repo_repository,
        vcs_provider=vcs_provider,
        id_generator=id_generator,
    )


async def test_connects_a_repository_via_github_as_owner(
    project_repository,
    membership_repository,
    connected_repo_repository,
    vcs_provider,
    clock,
    id_generator,
):
    project = await _seed_project(project_repository, clock)
    await membership_repository.add(
        ProjectMembership(project_id=project.id, user_id="owner-1", role=Role.OWNER)
    )
    use_case = _use_case(
        project_repository,
        membership_repository,
        connected_repo_repository,
        vcs_provider,
        id_generator,
    )

    connected_repo = await use_case.execute(
        project_id=project.id,
        user_id="owner-1",
        access_token="gho_faketoken",
        owner="example",
        repo="repo",
    )

    assert connected_repo.provider == "github"
    assert connected_repo.url == "https://github.com/example/repo"
    assert connected_repo.default_branch == "main"
    assert await connected_repo_repository.get_by_id(connected_repo.id) == connected_repo


async def test_rejects_a_non_member(
    project_repository,
    membership_repository,
    connected_repo_repository,
    vcs_provider,
    clock,
    id_generator,
):
    project = await _seed_project(project_repository, clock)
    use_case = _use_case(
        project_repository,
        membership_repository,
        connected_repo_repository,
        vcs_provider,
        id_generator,
    )

    with pytest.raises(InsufficientPermissions):
        await use_case.execute(
            project_id=project.id,
            user_id="stranger",
            access_token="gho_faketoken",
            owner="example",
            repo="repo",
        )


async def test_rejects_a_member_who_is_not_an_owner(
    project_repository,
    membership_repository,
    connected_repo_repository,
    vcs_provider,
    clock,
    id_generator,
):
    project = await _seed_project(project_repository, clock)
    await membership_repository.add(
        ProjectMembership(project_id=project.id, user_id="member-1", role=Role.MEMBER)
    )
    use_case = _use_case(
        project_repository,
        membership_repository,
        connected_repo_repository,
        vcs_provider,
        id_generator,
    )

    with pytest.raises(InsufficientPermissions):
        await use_case.execute(
            project_id=project.id,
            user_id="member-1",
            access_token="gho_faketoken",
            owner="example",
            repo="repo",
        )


async def test_raises_project_not_found_for_an_unknown_project(
    project_repository, membership_repository, connected_repo_repository, vcs_provider, id_generator
):
    use_case = _use_case(
        project_repository,
        membership_repository,
        connected_repo_repository,
        vcs_provider,
        id_generator,
    )

    with pytest.raises(ProjectNotFound):
        await use_case.execute(
            project_id="does-not-exist",
            user_id="owner-1",
            access_token="gho_faketoken",
            owner="example",
            repo="repo",
        )
