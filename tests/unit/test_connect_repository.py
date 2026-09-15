import pytest

from verion.modules.projects.application.connect_repository import ConnectRepositoryUseCase
from verion.modules.projects.domain.exceptions import (
    InsufficientPermissions,
    InvalidConnectedRepoUrl,
    ProjectNotFound,
)
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


@pytest.mark.parametrize(
    "url",
    [
        "https://octocat:ghp_s3cret@github.com/example/repo",
        # Username only: `password` is None here, so a check on the password alone passes it.
        "https://ghp_s3cret@github.com/example/repo",
        # Otherwise invalid too: the refusal must not depend on the rest being well-formed.
        "ftp://octocat:ghp_s3cret@gitlab.example/repo",
        # No `//` authority, so `urlparse` reports no username: the forms a check on
        # `username` and `password` alone passes.
        "https:octocat:ghp_s3cret@github.com/example/repo",
        "https:/octocat:ghp_s3cret@github.com/example/repo",
        "octocat:ghp_s3cret@github.com/example/repo",
        # A backslash ends the text check's authority before the `@`, while `urlparse` still
        # reports a username: the case only the `urlparse` branch refuses.
        "https://ghp_s3cret\\@github.com/example/repo",
    ],
)
async def test_a_credential_in_the_repository_url_is_rejected_and_never_echoed(
    url, project_repository, membership_repository, connected_repo_repository, clock, id_generator
):
    """Rule 12, at the write path of `ConnectedRepo.url`.

    Before `validate_connected_repo_url` this value was stored with no userinfo check, and
    came back in the connect response and in the detect route's error detail. Beyond the
    refusal, two things are asserted: the message does not carry the credential, and no row
    was stored, since a refusal that still stored the row would not be one.
    """
    project = await _seed_project(project_repository, clock)
    await membership_repository.add(
        ProjectMembership(project_id=project.id, user_id="owner-1", role=Role.OWNER)
    )
    use_case = _use_case(
        project_repository, membership_repository, connected_repo_repository, id_generator
    )

    with pytest.raises(InvalidConnectedRepoUrl) as exc_info:
        await use_case.execute(
            project_id=project.id,
            user_id="owner-1",
            provider="github",
            url=url,
            default_branch="main",
        )

    assert "ghp_s3cret" not in str(exc_info.value)
    assert await connected_repo_repository.get_by_project_id(project.id) is None


async def test_an_at_sign_after_the_host_is_not_userinfo(
    project_repository, membership_repository, connected_repo_repository, clock, id_generator
):
    """The userinfo check reads only the text before the path, so an `@` after the host
    does not make a repository unconnectable."""
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
        url="https://github.com/example/repo?ref=release@2026",
        default_branch="main",
    )

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
