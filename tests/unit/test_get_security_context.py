from datetime import UTC, datetime

import pytest

from verion.modules.projects.application.get_security_context import GetSecurityContextUseCase
from verion.modules.projects.domain.exceptions import (
    InsufficientPermissions,
    ProjectNotFound,
    SecurityContextNotFound,
)
from verion.modules.projects.domain.project import Project, ProjectMembership, Role
from verion.modules.projects.domain.security_context import SecurityContext


async def _seed_project(project_repository, clock, project_id="project-1", owner_id="owner-1"):
    project = Project(id=project_id, owner_id=owner_id, name="Verion", created_at=clock.now())
    await project_repository.add(project)
    return project


def _use_case(project_repository, membership_repository, security_context_repository):
    return GetSecurityContextUseCase(
        projects=project_repository,
        memberships=membership_repository,
        security_contexts=security_context_repository,
    )


async def test_owner_can_read_the_context(
    project_repository, membership_repository, security_context_repository, clock
):
    project = await _seed_project(project_repository, clock)
    await membership_repository.add(
        ProjectMembership(project_id=project.id, user_id="owner-1", role=Role.OWNER)
    )
    existing = SecurityContext(
        id="context-1",
        project_id=project.id,
        language="python",
        framework="fastapi",
        database=None,
        deployment_target="docker",
        ci_provider=None,
        exposure_tags=["public_facing"],
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    await security_context_repository.add(existing)
    use_case = _use_case(project_repository, membership_repository, security_context_repository)

    context = await use_case.execute(project_id=project.id, user_id="owner-1")

    assert context == existing


async def test_plain_member_can_read_the_context(
    project_repository, membership_repository, security_context_repository, clock
):
    project = await _seed_project(project_repository, clock)
    await membership_repository.add(
        ProjectMembership(project_id=project.id, user_id="member-1", role=Role.MEMBER)
    )
    existing = SecurityContext(
        id="context-1",
        project_id=project.id,
        language="python",
        framework=None,
        database=None,
        deployment_target=None,
        ci_provider=None,
        exposure_tags=[],
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    await security_context_repository.add(existing)
    use_case = _use_case(project_repository, membership_repository, security_context_repository)

    context = await use_case.execute(project_id=project.id, user_id="member-1")

    assert context == existing


async def test_rejects_a_non_member(
    project_repository, membership_repository, security_context_repository, clock
):
    project = await _seed_project(project_repository, clock)
    use_case = _use_case(project_repository, membership_repository, security_context_repository)

    with pytest.raises(InsufficientPermissions):
        await use_case.execute(project_id=project.id, user_id="stranger")


async def test_raises_project_not_found_for_an_unknown_project(
    project_repository, membership_repository, security_context_repository
):
    use_case = _use_case(project_repository, membership_repository, security_context_repository)

    with pytest.raises(ProjectNotFound):
        await use_case.execute(project_id="does-not-exist", user_id="owner-1")


async def test_raises_security_context_not_found_when_none_has_been_built_yet(
    project_repository, membership_repository, security_context_repository, clock
):
    project = await _seed_project(project_repository, clock)
    await membership_repository.add(
        ProjectMembership(project_id=project.id, user_id="owner-1", role=Role.OWNER)
    )
    use_case = _use_case(project_repository, membership_repository, security_context_repository)

    with pytest.raises(SecurityContextNotFound):
        await use_case.execute(project_id=project.id, user_id="owner-1")
