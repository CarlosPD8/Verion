import dataclasses
from datetime import UTC, datetime

from verion.modules.projects.adapters.outbound.db.repository import (
    PostgresConnectedRepoRepository,
    PostgresProjectMembershipRepository,
    PostgresProjectRepository,
    PostgresSecurityContextRepository,
)
from verion.modules.projects.domain.project import ConnectedRepo, Project, ProjectMembership, Role
from verion.modules.projects.domain.security_context import SecurityContext


def _project(project_id: str = "project-1") -> Project:
    return Project(
        id=project_id,
        owner_id="owner-1",
        name="Verion",
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


async def test_round_trips_a_project_through_postgres(db_session):
    repository = PostgresProjectRepository(db_session)
    project = _project()

    await repository.add(project)

    assert await repository.get_by_id(project.id) == project


async def test_get_project_by_id_returns_none_when_missing(db_session):
    repository = PostgresProjectRepository(db_session)

    assert await repository.get_by_id("does-not-exist") is None


async def test_round_trips_a_connected_repo_through_postgres(db_session):
    await PostgresProjectRepository(db_session).add(_project())
    repository = PostgresConnectedRepoRepository(db_session)
    connected_repo = ConnectedRepo(
        id="repo-1",
        project_id="project-1",
        provider="github",
        url="https://github.com/example/repo",
        default_branch="main",
    )

    await repository.add(connected_repo)

    assert await repository.get_by_id(connected_repo.id) == connected_repo


async def test_get_connected_repo_by_id_returns_none_when_missing(db_session):
    repository = PostgresConnectedRepoRepository(db_session)

    assert await repository.get_by_id("does-not-exist") is None


async def test_round_trips_a_membership_through_postgres_composite_key(db_session):
    await PostgresProjectRepository(db_session).add(_project())
    repository = PostgresProjectMembershipRepository(db_session)
    membership = ProjectMembership(project_id="project-1", user_id="owner-1", role=Role.OWNER)

    await repository.add(membership)

    assert (await repository.get_by_project_and_user("project-1", "owner-1")) == membership


async def test_get_membership_returns_none_when_missing(db_session):
    repository = PostgresProjectMembershipRepository(db_session)

    assert await repository.get_by_project_and_user("project-1", "nobody") is None


async def test_round_trips_a_security_context_through_postgres(db_session):
    await PostgresProjectRepository(db_session).add(_project())
    repository = PostgresSecurityContextRepository(db_session)
    context = SecurityContext(
        id="context-1",
        project_id="project-1",
        language="python",
        framework="fastapi",
        database=None,
        deployment_target="docker",
        ci_provider=None,
        exposure_tags=["public_facing", "handles_pii"],
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )

    await repository.add(context)

    assert await repository.get_by_project_id("project-1") == context


async def test_get_security_context_by_project_id_returns_none_when_missing(db_session):
    repository = PostgresSecurityContextRepository(db_session)

    assert await repository.get_by_project_id("does-not-exist") is None


async def test_update_persists_changed_exposure_tags(db_session):
    await PostgresProjectRepository(db_session).add(_project())
    repository = PostgresSecurityContextRepository(db_session)
    context = SecurityContext(
        id="context-1",
        project_id="project-1",
        language=None,
        framework=None,
        database=None,
        deployment_target=None,
        ci_provider=None,
        exposure_tags=[],
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    await repository.add(context)

    updated = dataclasses.replace(context, exposure_tags=["public_facing"])
    await repository.update(updated)

    assert await repository.get_by_project_id("project-1") == updated
