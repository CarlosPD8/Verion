"""`PostgresServingDeclarationRepository` against real Postgres.

The unit suite (`tests/unit/test_serving_declaration.py`) proves the rule; this proves
that what the rule reads survives a round trip and that the one-row-per-project shape is
enforced by the database rather than by the repository's good behaviour.
"""

from datetime import UTC, datetime

import pytest
from sqlalchemy.exc import IntegrityError

from verion.modules.projects.adapters.outbound.db.models import ServingDeclarationModel
from verion.modules.projects.adapters.outbound.db.repository import (
    PostgresProjectRepository,
    PostgresServingDeclarationRepository,
)
from verion.modules.projects.domain.project import Project
from verion.modules.projects.domain.serving_declaration import ServingDeclaration

_AT = datetime(2026, 1, 1, tzinfo=UTC)


def _project(project_id: str = "project-1") -> Project:
    return Project(id=project_id, owner_id="owner-1", name="Verion", created_at=_AT)


def _declaration(
    *,
    declaration_id: str = "declaration-1",
    project_id: str = "project-1",
    declared_target_url: str = "https://staging.example.com",
    declared_by: str = "user-1",
    declared_at: datetime = _AT,
) -> ServingDeclaration:
    return ServingDeclaration(
        id=declaration_id,
        project_id=project_id,
        declared_target_url=declared_target_url,
        declared_repo_url="https://github.com/example/repo",
        declared_default_branch="main",
        declared_at=declared_at,
        declared_by=declared_by,
    )


async def test_round_trips_a_declaration_through_postgres(db_session):
    await PostgresProjectRepository(db_session).add(_project())
    repository = PostgresServingDeclarationRepository(db_session)
    declaration = _declaration()

    await repository.upsert(declaration)

    assert await repository.get_by_project_id("project-1") == declaration


async def test_a_project_that_never_declared_reads_as_none(db_session):
    await PostgresProjectRepository(db_session).add(_project())

    assert (
        await PostgresServingDeclarationRepository(db_session).get_by_project_id("project-1")
        is None
    )


async def test_a_stored_target_url_survives_the_round_trip_byte_for_byte(db_session):
    """The property ADR-0028 decision 2's verbatim comparison rests on.

    A round trip that trimmed, lowercased or otherwise touched the string would make the
    rule compare a normalized stored value against an unnormalized live one — the same
    disagreement the decision refuses a normalizer to avoid, arriving through the adapter
    instead. The trailing space and the mixed case are the two shapes a well-meaning
    adapter would most plausibly clean up.
    """
    await PostgresProjectRepository(db_session).add(_project())
    repository = PostgresServingDeclarationRepository(db_session)
    awkward = "  HTTPS://Staging.Example.COM/App/  "

    await repository.upsert(_declaration(declared_target_url=awkward))

    stored = await repository.get_by_project_id("project-1")
    assert stored is not None
    assert stored.declared_target_url == awkward


async def test_re_declaring_replaces_the_row_but_keeps_its_id(db_session):
    """Upsert on the project_id constraint: the five declared columns move together and
    the surrogate id does not.

    A re-declaration is a new assertion by a person at a time, so carrying the first
    declaration's `declared_by` or `declared_at` forward would attribute the current claim
    to somebody who did not make it. **The id is the deliberate exception**, and it is
    asserted rather than left incidental: `id` is absent from the statement's `set_`, so
    the row keeps the identity it was inserted with even though the caller supplies a
    fresh one. Without this assertion the choice would be invisible, and a later edit
    adding `id` to `set_` would pass every other test in this file.
    """
    await PostgresProjectRepository(db_session).add(_project())
    repository = PostgresServingDeclarationRepository(db_session)
    later = datetime(2026, 2, 1, tzinfo=UTC)

    await repository.upsert(_declaration())
    await repository.upsert(
        _declaration(
            declaration_id="declaration-2",
            declared_target_url="https://prod.example.com",
            declared_by="user-2",
            declared_at=later,
        )
    )

    stored = await repository.get_by_project_id("project-1")
    assert stored is not None
    assert stored.declared_target_url == "https://prod.example.com"
    assert stored.declared_by == "user-2"
    assert stored.declared_at == later
    assert stored.id == "declaration-1"


async def test_a_second_row_for_one_project_is_refused_by_the_database(db_session):
    """The constraint, asserted against Postgres rather than against the repository.

    `upsert` cannot produce this — that is the point of it — so the insert goes through
    the ORM directly. Without `uq_serving_declarations_project_id` a project could hold
    two declarations and "which one is in force?" would have no answer.
    """
    await PostgresProjectRepository(db_session).add(_project())
    await PostgresServingDeclarationRepository(db_session).upsert(_declaration())

    db_session.add(
        ServingDeclarationModel(
            id="declaration-2",
            project_id="project-1",
            declared_target_url="https://other.example.com",
            declared_repo_url="https://github.com/example/other",
            declared_default_branch="develop",
            declared_at=_AT,
            declared_by="user-2",
        )
    )

    with pytest.raises(IntegrityError):
        await db_session.flush()


async def test_declarations_are_scoped_to_their_own_project(db_session):
    """Two projects, two declarations, no bleed. The tenant boundary this table needs for
    the same reason `project_id` is scope rather than signal in the match key."""
    projects = PostgresProjectRepository(db_session)
    await projects.add(_project())
    await projects.add(_project("project-2"))
    repository = PostgresServingDeclarationRepository(db_session)

    await repository.upsert(_declaration())
    await repository.upsert(
        _declaration(
            declaration_id="declaration-2",
            project_id="project-2",
            declared_target_url="https://two.example.com",
        )
    )

    first = await repository.get_by_project_id("project-1")
    second = await repository.get_by_project_id("project-2")
    assert first is not None
    assert second is not None
    assert first.declared_target_url == "https://staging.example.com"
    assert second.declared_target_url == "https://two.example.com"
