from datetime import UTC, datetime

import pytest

from verion.modules.projects.application.build_security_context import (
    BuildSecurityContextUseCase,
)
from verion.modules.projects.application.build_security_context_from_github import (
    BuildSecurityContextFromGitHubUseCase,
)
from verion.modules.projects.domain.context_detection import detect_stack
from verion.modules.projects.domain.exceptions import (
    ConnectedRepoNotFound,
    GitHubApiError,
    InsufficientPermissions,
    UnsupportedRepoProvider,
)
from verion.modules.projects.domain.project import ConnectedRepo, Project, ProjectMembership, Role


async def _seed_project(project_repository, clock, project_id="project-1", owner_id="owner-1"):
    project = Project(id=project_id, owner_id=owner_id, name="Verion", created_at=clock.now())
    await project_repository.add(project)
    return project


async def _seed_connected_repo(
    connected_repo_repository,
    project_id="project-1",
    provider="github",
    url="https://github.com/example/repo",
    default_branch="main",
):
    connected_repo = ConnectedRepo(
        id="repo-1",
        project_id=project_id,
        provider=provider,
        url=url,
        default_branch=default_branch,
    )
    await connected_repo_repository.add(connected_repo)
    return connected_repo


def _use_case(
    project_repository,
    membership_repository,
    security_context_repository,
    connected_repo_repository,
    clock,
    id_generator,
    vcs_provider,
):
    build_security_context = BuildSecurityContextUseCase(
        projects=project_repository,
        memberships=membership_repository,
        security_contexts=security_context_repository,
        detector=detect_stack,
        id_generator=id_generator,
        clock=clock,
    )
    return BuildSecurityContextFromGitHubUseCase(
        projects=project_repository,
        memberships=membership_repository,
        connected_repos=connected_repo_repository,
        vcs_provider=vcs_provider,
        build_security_context=build_security_context,
    )


async def test_builds_and_persists_a_security_context_from_github(
    project_repository,
    membership_repository,
    security_context_repository,
    connected_repo_repository,
    clock,
    id_generator,
    vcs_provider_factory,
):
    project = await _seed_project(project_repository, clock)
    await membership_repository.add(
        ProjectMembership(project_id=project.id, user_id="owner-1", role=Role.OWNER)
    )
    await _seed_connected_repo(connected_repo_repository, project_id=project.id)
    vcs_provider = vcs_provider_factory(
        files={
            "pyproject.toml": 'dependencies = ["fastapi"]',
            "Dockerfile": "FROM python:3.12",
            "src/main.py": "print('irrelevant')",
        }
    )
    use_case = _use_case(
        project_repository,
        membership_repository,
        security_context_repository,
        connected_repo_repository,
        clock,
        id_generator,
        vcs_provider,
    )

    context = await use_case.execute(
        project_id=project.id, user_id="owner-1", access_token="gho_faketoken"
    )

    assert context.project_id == project.id
    assert context.language == "python"
    assert context.framework == "fastapi"
    assert context.deployment_target == "docker"
    assert context.created_at == datetime(2026, 1, 1, tzinfo=UTC)
    assert await security_context_repository.get_by_project_id(project.id) == context


async def test_rejects_a_non_member_without_calling_the_vcs_provider(
    project_repository,
    membership_repository,
    security_context_repository,
    connected_repo_repository,
    clock,
    id_generator,
    vcs_provider_factory,
):
    project = await _seed_project(project_repository, clock)
    await _seed_connected_repo(connected_repo_repository, project_id=project.id)
    vcs_provider = vcs_provider_factory(fail=True)
    use_case = _use_case(
        project_repository,
        membership_repository,
        security_context_repository,
        connected_repo_repository,
        clock,
        id_generator,
        vcs_provider,
    )

    with pytest.raises(InsufficientPermissions):
        await use_case.execute(
            project_id=project.id, user_id="stranger", access_token="gho_faketoken"
        )


async def test_rejects_a_member_who_is_not_an_owner(
    project_repository,
    membership_repository,
    security_context_repository,
    connected_repo_repository,
    clock,
    id_generator,
    vcs_provider,
):
    project = await _seed_project(project_repository, clock)
    await membership_repository.add(
        ProjectMembership(project_id=project.id, user_id="member-1", role=Role.MEMBER)
    )
    await _seed_connected_repo(connected_repo_repository, project_id=project.id)
    use_case = _use_case(
        project_repository,
        membership_repository,
        security_context_repository,
        connected_repo_repository,
        clock,
        id_generator,
        vcs_provider,
    )

    with pytest.raises(InsufficientPermissions):
        await use_case.execute(
            project_id=project.id, user_id="member-1", access_token="gho_faketoken"
        )


async def test_raises_connected_repo_not_found_when_no_repo_is_connected(
    project_repository,
    membership_repository,
    security_context_repository,
    connected_repo_repository,
    clock,
    id_generator,
    vcs_provider,
):
    project = await _seed_project(project_repository, clock)
    await membership_repository.add(
        ProjectMembership(project_id=project.id, user_id="owner-1", role=Role.OWNER)
    )
    use_case = _use_case(
        project_repository,
        membership_repository,
        security_context_repository,
        connected_repo_repository,
        clock,
        id_generator,
        vcs_provider,
    )

    with pytest.raises(ConnectedRepoNotFound):
        await use_case.execute(
            project_id=project.id, user_id="owner-1", access_token="gho_faketoken"
        )


async def test_raises_unsupported_repo_provider_for_a_non_github_repo(
    project_repository,
    membership_repository,
    security_context_repository,
    connected_repo_repository,
    clock,
    id_generator,
    vcs_provider,
):
    project = await _seed_project(project_repository, clock)
    await membership_repository.add(
        ProjectMembership(project_id=project.id, user_id="owner-1", role=Role.OWNER)
    )
    await _seed_connected_repo(
        connected_repo_repository,
        project_id=project.id,
        provider="gitlab",
        url="https://gitlab.com/example/repo",
    )
    use_case = _use_case(
        project_repository,
        membership_repository,
        security_context_repository,
        connected_repo_repository,
        clock,
        id_generator,
        vcs_provider,
    )

    with pytest.raises(UnsupportedRepoProvider):
        await use_case.execute(
            project_id=project.id, user_id="owner-1", access_token="gho_faketoken"
        )


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/example",
        "https://not-github.com/example/repo",
        "https://github.com/example/repo/extra",
    ],
)
async def test_raises_unsupported_repo_provider_for_a_malformed_github_url(
    project_repository,
    membership_repository,
    security_context_repository,
    connected_repo_repository,
    clock,
    id_generator,
    vcs_provider,
    url,
):
    project = await _seed_project(project_repository, clock)
    await membership_repository.add(
        ProjectMembership(project_id=project.id, user_id="owner-1", role=Role.OWNER)
    )
    await _seed_connected_repo(connected_repo_repository, project_id=project.id, url=url)
    use_case = _use_case(
        project_repository,
        membership_repository,
        security_context_repository,
        connected_repo_repository,
        clock,
        id_generator,
        vcs_provider,
    )

    with pytest.raises(UnsupportedRepoProvider):
        await use_case.execute(
            project_id=project.id, user_id="owner-1", access_token="gho_faketoken"
        )


async def test_tolerates_a_trailing_slash_on_an_otherwise_valid_github_url(
    project_repository,
    membership_repository,
    security_context_repository,
    connected_repo_repository,
    clock,
    id_generator,
    vcs_provider_factory,
):
    project = await _seed_project(project_repository, clock)
    await membership_repository.add(
        ProjectMembership(project_id=project.id, user_id="owner-1", role=Role.OWNER)
    )
    await _seed_connected_repo(
        connected_repo_repository, project_id=project.id, url="https://github.com/example/repo/"
    )
    vcs_provider = vcs_provider_factory(files={"pyproject.toml": "[project]"})
    use_case = _use_case(
        project_repository,
        membership_repository,
        security_context_repository,
        connected_repo_repository,
        clock,
        id_generator,
        vcs_provider,
    )

    context = await use_case.execute(
        project_id=project.id, user_id="owner-1", access_token="gho_faketoken"
    )

    assert context.project_id == project.id


async def test_github_api_error_propagates_unchanged(
    project_repository,
    membership_repository,
    security_context_repository,
    connected_repo_repository,
    clock,
    id_generator,
    vcs_provider_factory,
):
    project = await _seed_project(project_repository, clock)
    await membership_repository.add(
        ProjectMembership(project_id=project.id, user_id="owner-1", role=Role.OWNER)
    )
    await _seed_connected_repo(connected_repo_repository, project_id=project.id)
    vcs_provider = vcs_provider_factory(fail=True)
    use_case = _use_case(
        project_repository,
        membership_repository,
        security_context_repository,
        connected_repo_repository,
        clock,
        id_generator,
        vcs_provider,
    )

    with pytest.raises(GitHubApiError):
        await use_case.execute(
            project_id=project.id, user_id="owner-1", access_token="gho_faketoken"
        )
