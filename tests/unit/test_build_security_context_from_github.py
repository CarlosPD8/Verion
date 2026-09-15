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
    SourceArchiveMalformed,
    SourceArchiveTooLarge,
    UnsupportedRepoProvider,
)
from verion.modules.projects.domain.project import ConnectedRepo, Project, ProjectMembership, Role
from verion.modules.projects.domain.route_extraction import RouteMap, RouteSpan, UnreadTree
from verion.modules.projects.ports.vcs_provider import SourceArchive


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
    route_map_repository,
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
        route_maps=route_map_repository,
        id_generator=id_generator,
        clock=clock,
    )


async def test_builds_and_persists_a_security_context_from_github(
    project_repository,
    membership_repository,
    security_context_repository,
    connected_repo_repository,
    clock,
    id_generator,
    vcs_provider_factory,
    route_map_repository,
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
        route_map_repository,
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
    route_map_repository,
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
        route_map_repository,
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
    route_map_repository,
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
        route_map_repository,
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
    route_map_repository,
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
        route_map_repository,
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
    route_map_repository,
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
        route_map_repository,
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
    route_map_repository,
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
        route_map_repository,
    )

    with pytest.raises(UnsupportedRepoProvider):
        await use_case.execute(
            project_id=project.id, user_id="owner-1", access_token="gho_faketoken"
        )


async def test_a_credential_in_a_stored_repository_url_is_not_echoed_in_the_error(
    project_repository,
    membership_repository,
    security_context_repository,
    connected_repo_repository,
    clock,
    id_generator,
    vcs_provider,
    route_map_repository,
):
    """Rule 12, for a row written before `validate_connected_repo_url` refused userinfo.

    Its netloc is `octocat:ghp_s3cret@github.com`, not `github.com`, so this path raises, and
    the detect route returns the message as its 400 detail. It quoted the URL until
    2026-09-15.
    """
    project = await _seed_project(project_repository, clock)
    await membership_repository.add(
        ProjectMembership(project_id=project.id, user_id="owner-1", role=Role.OWNER)
    )
    await _seed_connected_repo(
        connected_repo_repository,
        project_id=project.id,
        url="https://octocat:ghp_s3cret@github.com/example/repo",
    )
    use_case = _use_case(
        project_repository,
        membership_repository,
        security_context_repository,
        connected_repo_repository,
        clock,
        id_generator,
        vcs_provider,
        route_map_repository,
    )

    with pytest.raises(UnsupportedRepoProvider) as exc_info:
        await use_case.execute(
            project_id=project.id, user_id="owner-1", access_token="gho_faketoken"
        )

    assert "ghp_s3cret" not in str(exc_info.value)


async def test_tolerates_a_trailing_slash_on_an_otherwise_valid_github_url(
    project_repository,
    membership_repository,
    security_context_repository,
    connected_repo_repository,
    clock,
    id_generator,
    vcs_provider_factory,
    route_map_repository,
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
        route_map_repository,
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
    route_map_repository,
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
        route_map_repository,
    )

    with pytest.raises(GitHubApiError):
        await use_case.execute(
            project_id=project.id, user_id="owner-1", access_token="gho_faketoken"
        )


# ---------------------------------------------------------------------------
# M5.6 commit 4 — the route map, derived and stored at context build
# ---------------------------------------------------------------------------

_SHA = "c68caa7aba8db8ae64da6dd2b4e1b8a05ecd1850"
_FLASK_MANIFEST = {"requirements.txt": "Flask==2.3.1\n"}
_APP = '@app.route("/calculate")\ndef calculate():\n    return eval(request.args["expr"])\n'


async def _owned_project(
    project_repository, membership_repository, connected_repo_repository, clock
):
    project = await _seed_project(project_repository, clock)
    await membership_repository.add(
        ProjectMembership(project_id=project.id, user_id="owner-1", role=Role.OWNER)
    )
    await _seed_connected_repo(connected_repo_repository, project_id=project.id)
    return project


async def test_a_flask_tree_stores_its_route_map_with_the_archive_s_commit(
    project_repository,
    membership_repository,
    security_context_repository,
    connected_repo_repository,
    clock,
    id_generator,
    vcs_provider_factory,
    route_map_repository,
):
    project = await _owned_project(
        project_repository, membership_repository, connected_repo_repository, clock
    )
    vcs_provider = vcs_provider_factory(
        files=_FLASK_MANIFEST,
        archive=SourceArchive(commit_sha=_SHA, files={"app.py": _APP}, undecodable_files=()),
    )
    use_case = _use_case(
        project_repository,
        membership_repository,
        security_context_repository,
        connected_repo_repository,
        clock,
        id_generator,
        vcs_provider,
        route_map_repository,
    )

    await use_case.execute(project_id=project.id, user_id="owner-1", access_token="gho_faketoken")

    record = await route_map_repository.get_by_project_id(project.id)
    assert record is not None
    assert record.framework == "flask"
    assert record.source_archive_commit_sha == _SHA
    assert record.derived_at == clock.now()
    assert record.route_map == RouteMap(
        routes=(RouteSpan(path="/calculate", file_path="app.py", start_line=1, end_line=3),),
        unparsed_files=(),
        unresolved_routes=(),
        unread_tree=None,
    )
    assert vcs_provider.archive_requests == [("example", "repo")]


async def test_a_non_flask_tree_is_never_fetched_and_stores_an_empty_map_with_no_commit(
    project_repository,
    membership_repository,
    security_context_repository,
    connected_repo_repository,
    clock,
    id_generator,
    vcs_provider_factory,
    route_map_repository,
):
    """No archive is configured, so the fake RAISES if one is requested: no fetch, not an
    ignored one. A non-Flask build costs exactly what it did before this commit."""
    project = await _owned_project(
        project_repository, membership_repository, connected_repo_repository, clock
    )
    vcs_provider = vcs_provider_factory(files={"pyproject.toml": 'dependencies = ["fastapi"]'})
    use_case = _use_case(
        project_repository,
        membership_repository,
        security_context_repository,
        connected_repo_repository,
        clock,
        id_generator,
        vcs_provider,
        route_map_repository,
    )

    await use_case.execute(project_id=project.id, user_id="owner-1", access_token="gho_faketoken")

    record = await route_map_repository.get_by_project_id(project.id)
    assert record is not None
    assert record.framework == "fastapi"
    assert record.source_archive_commit_sha is None
    assert record.route_map == RouteMap(
        routes=(), unparsed_files=(), unresolved_routes=(), unread_tree=None
    )
    assert vcs_provider.archive_requests == []


@pytest.mark.parametrize(
    ("error", "reason"),
    [
        (GitHubApiError("simulated"), UnreadTree.FETCH_FAILED),
        (SourceArchiveTooLarge("simulated"), UnreadTree.TOO_LARGE),
        (SourceArchiveMalformed("simulated"), UnreadTree.MALFORMED),
    ],
    ids=["fetch-failed", "too-large", "malformed"],
)
async def test_an_archive_failure_is_stored_as_its_reason_and_the_context_is_still_built(
    project_repository,
    membership_repository,
    security_context_repository,
    connected_repo_repository,
    clock,
    id_generator,
    vcs_provider_factory,
    route_map_repository,
    error,
    reason,
):
    """Distinguishable from "no routes", which is the whole point: a swallowed failure that
    stored an empty read map would silently lose correlation for the project."""
    project = await _owned_project(
        project_repository, membership_repository, connected_repo_repository, clock
    )
    vcs_provider = vcs_provider_factory(files=_FLASK_MANIFEST, archive_error=error)
    use_case = _use_case(
        project_repository,
        membership_repository,
        security_context_repository,
        connected_repo_repository,
        clock,
        id_generator,
        vcs_provider,
        route_map_repository,
    )

    context = await use_case.execute(
        project_id=project.id, user_id="owner-1", access_token="gho_faketoken"
    )

    assert context.framework == "flask"
    assert await security_context_repository.get_by_project_id(project.id) == context
    record = await route_map_repository.get_by_project_id(project.id)
    assert record is not None
    assert record.route_map == RouteMap.not_read(reason)
    assert record.source_archive_commit_sha is None


async def test_undecodable_and_unparseable_members_are_both_reported_as_unparsed(
    project_repository,
    membership_repository,
    security_context_repository,
    connected_repo_repository,
    clock,
    id_generator,
    vcs_provider_factory,
    route_map_repository,
):
    project = await _owned_project(
        project_repository, membership_repository, connected_repo_repository, clock
    )
    vcs_provider = vcs_provider_factory(
        files=_FLASK_MANIFEST,
        archive=SourceArchive(
            commit_sha=_SHA,
            files={"app.py": _APP, "broken.py": "def (:\n"},
            undecodable_files=("latin1.py",),
        ),
    )
    use_case = _use_case(
        project_repository,
        membership_repository,
        security_context_repository,
        connected_repo_repository,
        clock,
        id_generator,
        vcs_provider,
        route_map_repository,
    )

    await use_case.execute(project_id=project.id, user_id="owner-1", access_token="gho_faketoken")

    record = await route_map_repository.get_by_project_id(project.id)
    assert record is not None
    assert record.route_map.unparsed_files == ("broken.py", "latin1.py")
    assert [route.path for route in record.route_map.routes] == ["/calculate"]
