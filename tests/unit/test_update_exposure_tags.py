from datetime import UTC, datetime

import pytest

from verion.modules.projects.application.update_exposure_tags import UpdateExposureTagsUseCase
from verion.modules.projects.domain.exceptions import InsufficientPermissions, ProjectNotFound
from verion.modules.projects.domain.project import Project, ProjectMembership, Role
from verion.modules.projects.domain.security_context import SecurityContext


async def _seed_project(project_repository, clock, project_id="project-1", owner_id="owner-1"):
    project = Project(id=project_id, owner_id=owner_id, name="Verion", created_at=clock.now())
    await project_repository.add(project)
    return project


def _use_case(
    project_repository, membership_repository, security_context_repository, clock, id_generator
):
    return UpdateExposureTagsUseCase(
        projects=project_repository,
        memberships=membership_repository,
        security_contexts=security_context_repository,
        id_generator=id_generator,
        clock=clock,
    )


async def test_updates_exposure_tags_on_an_existing_context(
    project_repository, membership_repository, security_context_repository, clock, id_generator
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
        exposure_tags=[],
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    await security_context_repository.add(existing)
    use_case = _use_case(
        project_repository, membership_repository, security_context_repository, clock, id_generator
    )

    context = await use_case.execute(
        project_id=project.id, user_id="owner-1", exposure_tags=["public_facing", "handles_pii"]
    )

    assert context.id == "context-1"
    assert context.language == "python"
    assert context.exposure_tags == ["public_facing", "handles_pii"]
    assert await security_context_repository.get_by_project_id(project.id) == context


async def test_creates_a_tags_only_context_when_none_exists(
    project_repository, membership_repository, security_context_repository, clock, id_generator
):
    project = await _seed_project(project_repository, clock)
    await membership_repository.add(
        ProjectMembership(project_id=project.id, user_id="owner-1", role=Role.OWNER)
    )
    use_case = _use_case(
        project_repository, membership_repository, security_context_repository, clock, id_generator
    )

    context = await use_case.execute(
        project_id=project.id, user_id="owner-1", exposure_tags=["public_facing"]
    )

    assert context.project_id == project.id
    assert context.language is None
    assert context.framework is None
    assert context.database is None
    assert context.deployment_target is None
    assert context.ci_provider is None
    assert context.exposure_tags == ["public_facing"]
    assert await security_context_repository.get_by_project_id(project.id) == context


async def test_rejects_a_non_owner(
    project_repository, membership_repository, security_context_repository, clock, id_generator
):
    project = await _seed_project(project_repository, clock)
    await membership_repository.add(
        ProjectMembership(project_id=project.id, user_id="member-1", role=Role.MEMBER)
    )
    use_case = _use_case(
        project_repository, membership_repository, security_context_repository, clock, id_generator
    )

    with pytest.raises(InsufficientPermissions):
        await use_case.execute(
            project_id=project.id, user_id="member-1", exposure_tags=["public_facing"]
        )


async def test_raises_project_not_found_for_an_unknown_project(
    project_repository, membership_repository, security_context_repository, clock, id_generator
):
    use_case = _use_case(
        project_repository, membership_repository, security_context_repository, clock, id_generator
    )

    with pytest.raises(ProjectNotFound):
        await use_case.execute(
            project_id="does-not-exist", user_id="owner-1", exposure_tags=["public_facing"]
        )
