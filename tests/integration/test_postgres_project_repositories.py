import dataclasses
from datetime import UTC, datetime

import pytest
from sqlalchemy.exc import IntegrityError

from verion.modules.projects.adapters.outbound.db.models import (
    ConnectedRepoModel,
    SecurityContextModel,
)
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

    await repository.upsert(connected_repo)

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


async def test_a_second_connected_repo_for_one_project_is_refused_by_the_database(db_session):
    """`uq_connected_repos_project_id`, asserted against Postgres — M8.7, ADR-0039.

    `upsert` cannot produce this — that is the point of it — so the insert goes through
    the ORM directly, `test_a_second_row_for_one_project_is_refused_by_the_database`'s
    shape one table over. Without the constraint a project could hold two repositories
    and `get_by_project_id` raised `MultipleResultsFound` from `run_scan`'s checkout
    path rather than from the route that caused it (**G51**).

    **The constraint name is asserted, not just the exception type.** `IntegrityError`
    alone would be satisfied by the foreign key, and the mutation this test exists to
    kill removes *this* constraint specifically. `test_schema_matches_models` checks
    that the name exists and never that it does anything.
    """
    await PostgresProjectRepository(db_session).add(_project())
    await PostgresConnectedRepoRepository(db_session).upsert(
        ConnectedRepo(
            id="repo-1",
            project_id="project-1",
            provider="github",
            url="https://github.com/example/repo",
            default_branch="main",
        )
    )

    db_session.add(
        ConnectedRepoModel(
            id="repo-2",
            project_id="project-1",
            provider="github",
            url="https://github.com/example/second",
            default_branch="main",
        )
    )

    with pytest.raises(IntegrityError) as raised:
        await db_session.flush()
    assert "uq_connected_repos_project_id" in str(raised.value)


async def test_a_second_security_context_for_one_project_is_refused_by_the_database(db_session):
    """`uq_security_contexts_project_id`, the same assertion one table over.

    Written out rather than parametrised with the test above: the two constraints are
    separate decisions on separate tables, and a parametrised version would report one
    failure where the mutation removes both.

    Without it a second detect added a second row, after which every context read for
    that project raised — freezing the route map at the first detect and making a stored
    `FETCH_FAILED` permanent, because every recovery runs through a second detect
    (**G55**).
    """
    await PostgresProjectRepository(db_session).add(_project())
    await PostgresSecurityContextRepository(db_session).add(
        SecurityContext(
            id="context-1",
            project_id="project-1",
            language="python",
            framework="flask",
            database=None,
            deployment_target=None,
            ci_provider=None,
            exposure_tags=[],
            created_at=datetime(2026, 1, 1, tzinfo=UTC),
        )
    )

    db_session.add(
        SecurityContextModel(
            id="context-2",
            project_id="project-1",
            language="rust",
            framework=None,
            database=None,
            deployment_target=None,
            ci_provider=None,
            exposure_tags=[],
            created_at=datetime(2026, 1, 1, tzinfo=UTC),
        )
    )

    with pytest.raises(IntegrityError) as raised:
        await db_session.flush()
    assert "uq_security_contexts_project_id" in str(raised.value)


async def test_a_re_detect_preserves_the_exposure_tags_and_refreshes_the_detected_fields(
    db_session,
):
    """ADR-0039 decision 3, against real SQL — the claim no fake can carry.

    Decision 3 is what prevents the worst defect M8.7 could introduce: erasing the
    owner's confirmed exposure tags on every re-detect, in the step M8.4's first bullet
    exists to perform. `BuildSecurityContextUseCase` builds its context with
    `exposure_tags=[]`, so the tags survive only because `upsert_detected`'s `set_`
    omits the column — for exactly the reason it omits `id`.

    **This has to be an integration test.** The mutation it kills is adding
    `exposure_tags` to that `set_`, which is a change in the `ON CONFLICT` clause; a
    fake agreeing with the adapter is not evidence about the adapter.

    Four assertions, because the omission has four consequences and a test asserting
    only the tags would pass against an upsert that had stopped refreshing anything.
    """
    await PostgresProjectRepository(db_session).add(_project())
    repository = PostgresSecurityContextRepository(db_session)
    detected = SecurityContext(
        id="context-1",
        project_id="project-1",
        language="python",
        framework="flask",
        database=None,
        deployment_target="docker",
        ci_provider=None,
        exposure_tags=[],
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    await repository.upsert_detected(detected)
    # The owner confirms the context — the PATCH half, and the only writer of the tags.
    await repository.update(dataclasses.replace(detected, exposure_tags=["public_facing"]))

    # A later detect, against a tree that has moved: new framework, new id minted by a
    # caller that did not read first, and the empty tag list every detect carries.
    await repository.upsert_detected(
        dataclasses.replace(
            detected,
            id="context-2",
            language="rust",
            framework="axum",
            exposure_tags=[],
            created_at=datetime(2026, 6, 1, tzinfo=UTC),
        )
    )

    stored = await repository.get_by_project_id("project-1")
    assert stored is not None
    assert stored.exposure_tags == ["public_facing"]  # survived the re-detect
    assert stored.framework == "axum"  # detected fields did move
    assert stored.id == "context-1"  # the row keeps its id
    assert stored.created_at == datetime(2026, 1, 1, tzinfo=UTC)  # and its first-detect time
