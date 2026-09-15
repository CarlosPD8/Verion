"""`PostgresRouteMapRepository` and `PostgresRouteMapReader` against real Postgres (M5.6 commit 4).

What the unit suite cannot show: that a map survives the JSONB round trip with its order and
both residue tuples intact, and that the table's CHECKs refuse what `RouteMapRecord` refuses —
asserted here with the domain BYPASSED, since a constraint only earns its place if it holds
against a writer that is not the repository.
"""

from datetime import UTC, datetime

import pytest
from sqlalchemy.exc import IntegrityError

from verion.modules.projects.adapters.outbound.db.models import RouteMapModel
from verion.modules.projects.adapters.outbound.db.repository import (
    PostgresProjectRepository,
    PostgresRouteMapReader,
    PostgresRouteMapRepository,
)
from verion.modules.projects.domain.project import Project
from verion.modules.projects.domain.route_extraction import (
    RouteMap,
    RouteSpan,
    UnreadTree,
    UnresolvedRoute,
)
from verion.modules.projects.domain.route_map_record import RouteMapRecord

_AT = datetime(2026, 1, 1, tzinfo=UTC)
_SHA = "c68caa7aba8db8ae64da6dd2b4e1b8a05ecd1850"

# Two routes out of lexical order on path but in `extract_routes`' order, two unparsed files,
# one unresolved route: every field of a map populated, so a round trip that dropped, merged
# or reordered any of them fails.
_FULL_MAP = RouteMap(
    routes=(
        RouteSpan(path="/z", file_path="app.py", start_line=9, end_line=11),
        RouteSpan(path="/calculate", file_path="app.py", start_line=14, end_line=31),
    ),
    unparsed_files=("legacy.py", "templates/x.py"),
    unresolved_routes=(
        UnresolvedRoute(file_path="api.py", function_name="dynamic", decorator_line=7),
    ),
    unread_tree=None,
)


def _record(
    *,
    record_id: str = "map-1",
    framework: str | None = "flask",
    route_map: RouteMap = _FULL_MAP,
    sha: str | None = _SHA,
    derived_at: datetime = _AT,
) -> RouteMapRecord:
    return RouteMapRecord(
        id=record_id,
        project_id="project-1",
        framework=framework,
        source_archive_commit_sha=sha,
        derived_at=derived_at,
        route_map=route_map,
    )


def _raw_row(**overrides: object) -> RouteMapModel:
    columns: dict[str, object] = {
        "id": "raw-1",
        "project_id": "project-1",
        "framework": "flask",
        "source_archive_commit_sha": None,
        "unread_tree": None,
        "routes": [],
        "unresolved_routes": [],
        "unparsed_files": [],
        "derived_at": _AT,
        **overrides,
    }
    return RouteMapModel(**columns)


async def test_a_full_map_round_trips_with_order_and_both_residue_tuples(db_session):
    await PostgresProjectRepository(db_session).add(Project("project-1", "owner-1", "V", _AT))
    repository = PostgresRouteMapRepository(db_session)

    await repository.upsert(_record())

    assert await repository.get_by_project_id("project-1") == _record()


async def test_an_unread_tree_round_trips_as_its_reason(db_session):
    await PostgresProjectRepository(db_session).add(Project("project-1", "owner-1", "V", _AT))
    repository = PostgresRouteMapRepository(db_session)
    unread = _record(route_map=RouteMap.not_read(UnreadTree.TOO_LARGE), sha=None)

    await repository.upsert(unread)

    assert await repository.get_by_project_id("project-1") == unread


async def test_re_upserting_replaces_every_column_but_keeps_the_id(db_session):
    """A snapshot is replaced whole, and every column in `set_` is made to move at least once.

    Step 1 → 2: a read Flask map with a SHA becomes a failure with none (routes, residue,
    `unread_tree`, SHA and `derived_at` move). Step 2 → 3: the framework changes to one the
    extractor does not read (`framework` and `unread_tree` move back). An earlier version kept
    `framework` constant, so dropping it from `set_` passed — the guardian found that.
    """
    await PostgresProjectRepository(db_session).add(Project("project-1", "owner-1", "V", _AT))
    repository = PostgresRouteMapRepository(db_session)
    later = datetime(2026, 2, 1, tzinfo=UTC)
    latest = datetime(2026, 3, 1, tzinfo=UTC)
    not_flask = RouteMap(routes=(), unparsed_files=(), unresolved_routes=(), unread_tree=None)

    await repository.upsert(_record())
    await repository.upsert(
        _record(
            record_id="map-2",
            route_map=RouteMap.not_read(UnreadTree.FETCH_FAILED),
            sha=None,
            derived_at=later,
        )
    )
    after_failure = await repository.get_by_project_id("project-1")
    await repository.upsert(
        _record(
            record_id="map-3", framework="django", route_map=not_flask, sha=None, derived_at=latest
        )
    )
    after_reframing = await repository.get_by_project_id("project-1")

    assert after_failure == _record(
        record_id="map-1",
        route_map=RouteMap.not_read(UnreadTree.FETCH_FAILED),
        sha=None,
        derived_at=later,
    )
    assert after_reframing == _record(
        record_id="map-1", framework="django", route_map=not_flask, sha=None, derived_at=latest
    )


async def test_the_reader_answers_not_built_for_a_project_with_no_map(db_session):
    await PostgresProjectRepository(db_session).add(Project("project-1", "owner-1", "V", _AT))

    route_map = await PostgresRouteMapReader(db_session).route_map_for(project_id="project-1")

    assert route_map == RouteMap.not_read(UnreadTree.NOT_BUILT)


async def test_the_reader_returns_the_stored_map(db_session):
    await PostgresProjectRepository(db_session).add(Project("project-1", "owner-1", "V", _AT))
    await PostgresRouteMapRepository(db_session).upsert(_record())

    route_map = await PostgresRouteMapReader(db_session).route_map_for(project_id="project-1")

    assert route_map == _FULL_MAP


# --- The CHECKs, with the domain bypassed ------------------------------------


async def test_the_database_refuses_a_stored_not_built(db_session):
    """NOT_BUILT's third policing site. `RouteMapRecord` refuses it and the reader only
    synthesizes it; this is the one that holds against a writer that skipped both."""
    await PostgresProjectRepository(db_session).add(Project("project-1", "owner-1", "V", _AT))
    db_session.add(_raw_row(unread_tree=str(UnreadTree.NOT_BUILT)))

    with pytest.raises(IntegrityError):
        await db_session.flush()


async def test_the_database_refuses_an_unread_tree_with_a_commit(db_session):
    await PostgresProjectRepository(db_session).add(Project("project-1", "owner-1", "V", _AT))
    db_session.add(
        _raw_row(unread_tree=str(UnreadTree.FETCH_FAILED), source_archive_commit_sha=_SHA)
    )

    with pytest.raises(IntegrityError):
        await db_session.flush()


@pytest.mark.parametrize(
    "reason", [member for member in UnreadTree if member is not UnreadTree.NOT_BUILT]
)
async def test_every_storable_unread_tree_member_satisfies_the_check(db_session, reason):
    """The guard against the CHECK's hand-typed list drifting narrower than the enum.

    `test_schema_matches_models.py` compares constraint NAMES, so it would not notice a
    member added to `UnreadTree` and missing from the migration. This inserts each one.
    """
    await PostgresProjectRepository(db_session).add(Project("project-1", "owner-1", "V", _AT))
    db_session.add(_raw_row(unread_tree=str(reason)))

    await db_session.flush()


async def test_a_second_row_for_one_project_is_refused_by_the_database(db_session):
    await PostgresProjectRepository(db_session).add(Project("project-1", "owner-1", "V", _AT))
    await PostgresRouteMapRepository(db_session).upsert(_record())
    db_session.add(_raw_row(id="raw-2"))

    with pytest.raises(IntegrityError):
        await db_session.flush()
