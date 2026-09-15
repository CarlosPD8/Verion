"""`RouteMapRecord`'s two invariants (M5.6 commit 4).

Both are enforced again by `route_maps`' CHECK constraints, and
`tests/integration/test_postgres_route_map_repository.py` asserts that half against Postgres
with the domain bypassed. This file is the domain half.
"""

from datetime import UTC, datetime

import pytest

from verion.modules.projects.domain.route_extraction import RouteMap, RouteSpan, UnreadTree
from verion.modules.projects.domain.route_map_record import RouteMapRecord

_SHA = "c68caa7aba8db8ae64da6dd2b4e1b8a05ecd1850"
_AT = datetime(2026, 1, 1, tzinfo=UTC)
_READ = RouteMap(
    routes=(RouteSpan(path="/calculate", file_path="app.py", start_line=14, end_line=31),),
    unparsed_files=(),
    unresolved_routes=(),
    unread_tree=None,
)


def _record(route_map: RouteMap, sha: str | None) -> RouteMapRecord:
    return RouteMapRecord(
        id="map-1",
        project_id="project-1",
        framework="flask",
        source_archive_commit_sha=sha,
        derived_at=_AT,
        route_map=route_map,
    )


def test_a_stored_record_cannot_claim_it_was_never_built():
    """`NOT_BUILT` means "no record exists", which a record cannot say about itself."""
    with pytest.raises(ValueError):
        _record(RouteMap.not_read(UnreadTree.NOT_BUILT), None)


@pytest.mark.parametrize(
    "reason", [UnreadTree.FETCH_FAILED, UnreadTree.TOO_LARGE, UnreadTree.MALFORMED]
)
def test_a_tree_that_was_not_read_cannot_carry_a_commit(reason):
    with pytest.raises(ValueError):
        _record(RouteMap.not_read(reason), _SHA)


@pytest.mark.parametrize(
    "reason", [UnreadTree.FETCH_FAILED, UnreadTree.TOO_LARGE, UnreadTree.MALFORMED]
)
def test_each_storable_failure_is_accepted_without_a_commit(reason):
    assert _record(RouteMap.not_read(reason), None).route_map.unread_tree is reason


def test_a_read_tree_carries_its_commit():
    assert _record(_READ, _SHA).source_archive_commit_sha == _SHA
