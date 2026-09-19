"""The three `/projects/{id}/risk-dismissals` routes end to end, against real Postgres. ADR-0036.

What this file is for:

- **The real validation path, through real wiring** (**G65**). Dismissal reaches
  `ScoredExplainableRisks` over the real correlation and scoring, and every authorization answer
  comes from `PostgresProjectAccessReader`. Two tests override a factory, each to reach a
  failure real storage cannot stage, and each says so in its docstring.
- **The bindings.** Key-set equality for every body, the 409's included.
- **What must stay true after a write.** Read back through a SECOND session, never through the
  one that wrote, so a test observes what was committed rather than what the writer holds.
- **G37's behaviour half.** A dismissal survives every writer that touches a finding or a
  dismissal.

Findings are hand-written, following `test_security_brief_routes.py`. Helpers are module-local,
because `tests/` is not a package.
"""

from datetime import UTC, datetime

import httpx2
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from verion.modules.history.domain.exceptions import RiskEventConflict
from verion.modules.identity.adapters.outbound.security.jwt_issuer import JwtAccessTokenIssuer
from verion.modules.normalization.adapters.outbound.db.repository import PostgresFindingRepository
from verion.modules.normalization.domain.finding import Evidence, Finding, Location
from verion.modules.projects.adapters.outbound.db.repository import (
    PostgresProjectMembershipRepository,
    PostgresProjectRepository,
)
from verion.modules.projects.domain.project import Project, ProjectMembership, Role
from verion.modules.risk_engine.ports.explainable_risk import ExplainableRiskInconsistent
from verion.platform.app import app
from verion.platform.clock import SystemClock
from verion.platform.di import get_explainable_risk_port, get_undismiss_risk_use_case
from verion.platform.settings import get_settings
from verion.shared_kernel.scanner_tools import ScannerTool
from verion.shared_kernel.severity import Severity

_PROJECT = "project-1"
_ABSENT_PROJECT = "project-absent"
_OWNER = "user-owner"
_PLAIN_MEMBER = "user-plain-member"
_STRANGER = "user-stranger"
_SCAN = "scan-1"
_AT = datetime(2026, 1, 1, tzinfo=UTC)

_ITEM_KEYS = {"id", "finding_ids", "state", "reason", "actor_user_id", "occurred_at"}
_CONFLICT_KEYS = {"covering_dismissal_id"}
_PAGE_KEYS = {"items", "total", "limit", "offset"}

_NO_CURRENT_RISK = (
    "No current Risk in this project has exactly these findings. Re-read the scored Risks."
)


def _auth_headers(user_id: str) -> dict[str, str]:
    settings = get_settings()
    issuer = JwtAccessTokenIssuer(
        secret_key=settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
        expires_minutes=settings.jwt_expires_minutes,
        clock=SystemClock(),
    )
    return {"Authorization": f"Bearer {issuer.issue(subject=user_id).value}"}


@pytest_asyncio.fixture
async def client():
    transport = httpx2.ASGITransport(app=app)
    async with httpx2.AsyncClient(transport=transport, base_url="http://test") as async_client:
        yield async_client


def _trivy(finding_id: str, package: str, severity: Severity = Severity.HIGH) -> Finding:
    """`rule_id` derives from `finding_id`, so no two findings here collapse into one row."""
    return Finding(
        id=finding_id,
        project_id=_PROJECT,
        source=ScannerTool.TRIVY,
        rule_id=f"rule-{finding_id}",
        severity=severity,
        native_severity=str(severity).upper(),
        title=f"title {finding_id}",
        location=Location(file_path="requirements.txt", package=package, installed_version="1.0"),
        evidence=Evidence(
            id=f"evidence-{finding_id}",
            finding_id=finding_id,
            scan_id=_SCAN,
            raw_payload="{}",
            source_tool=ScannerTool.TRIVY,
            captured_at=_AT,
        ),
    )


async def _seed_project(db_session, *, member: str = _OWNER, role: Role = Role.OWNER) -> None:
    await PostgresProjectRepository(db_session).add(
        Project(id=_PROJECT, owner_id=_OWNER, name="Project", created_at=_AT)
    )
    await PostgresProjectMembershipRepository(db_session).add(
        ProjectMembership(project_id=_PROJECT, user_id=member, role=role)
    )
    await db_session.commit()


async def _seed_findings(db_session, *findings: Finding) -> None:
    repository = PostgresFindingRepository(db_session)
    for finding in findings:
        await repository.upsert(finding)
    await db_session.commit()


async def _dismiss(client, finding_ids, *, reason="accepted risk", user=_OWNER, project=_PROJECT):
    return await client.post(
        f"/projects/{project}/risk-dismissals",
        json={"finding_ids": finding_ids, "reason": reason},
        headers=_auth_headers(user),
    )


async def _undo(client, dismissal_id, *, body=None, user=_OWNER, project=_PROJECT):
    return await client.post(
        f"/projects/{project}/risk-dismissals/{dismissal_id}/undo",
        json=body,
        headers=_auth_headers(user),
    )


async def _list(client, *, user=_OWNER, project=_PROJECT):
    return await client.get(f"/projects/{project}/risk-dismissals", headers=_auth_headers(user))


async def _surface(client, package: str) -> dict:
    scored = (
        await client.get(f"/projects/{_PROJECT}/scored-risks", headers=_auth_headers(_OWNER))
    ).json()
    return next(item for item in scored["items"] if item["match"]["package"] == package)


async def _rows(engine, table: str) -> list[tuple]:
    """Every row of a history table, read through a session that wrote none of them."""
    async with AsyncSession(engine) as reader:
        # `table` is one of this module's two literal names, never input.
        result = await reader.execute(text(f"SELECT * FROM {table} ORDER BY id"))
        return [tuple(row) for row in result]


# ---------------------------------------------------------------------------
# Dismissing
# ---------------------------------------------------------------------------


async def test_an_unauthenticated_request_is_rejected(client, db_session):
    await _seed_project(db_session)

    assert (
        await client.post(
            f"/projects/{_PROJECT}/risk-dismissals", json={"finding_ids": ["f"], "reason": "r"}
        )
    ).status_code == 401
    assert (await client.post(f"/projects/{_PROJECT}/risk-dismissals/x/undo")).status_code == 401
    assert (await client.get(f"/projects/{_PROJECT}/risk-dismissals")).status_code == 401


async def test_a_dismissal_stores_the_surfaces_sorted_ids_and_is_committed(
    client, db_session, engine
):
    """Kills storing the request's echo: the request sends the ids reversed."""
    await _seed_project(db_session)
    await _seed_findings(
        db_session, _trivy("f-1", "urllib3"), _trivy("f-2", "urllib3"), _trivy("f-3", "flask")
    )
    surface = await _surface(client, "urllib3")

    created = await _dismiss(client, list(reversed(surface["finding_ids"])))

    assert created.status_code == 201
    body = created.json()
    assert set(body) == _ITEM_KEYS
    assert body["finding_ids"] == ["f-1", "f-2"]
    assert (body["state"], body["reason"], body["actor_user_id"]) == (
        "dismissed",
        "accepted risk",
        _OWNER,
    )
    # Committed, and read back by a session that did not write it.
    [risk] = await _rows(engine, "risks")
    assert risk == (body["id"], _PROJECT, ["f-1", "f-2"])
    [event] = await _rows(engine, "risk_events")
    assert (event[1], event[2], event[3], event[4], event[5]) == (
        body["id"],
        1,
        "dismissed",
        _OWNER,
        "accepted risk",
    )
    # Rule 14: stored timezone-aware.
    assert event[6].utcoffset() is not None


async def test_a_set_that_is_not_a_current_risk_is_refused_and_nothing_is_written(
    client, db_session, engine
):
    """Through the REAL `ScoredExplainableRisks` (G65). Kills dismiss skipping validation."""
    await _seed_project(db_session)
    await _seed_findings(db_session, _trivy("f-1", "urllib3"), _trivy("f-2", "urllib3"))

    # A subset of the current surface is not the surface.
    stale = await _dismiss(client, ["f-1"])

    assert stale.status_code == 404
    assert stale.json() == {"detail": _NO_CURRENT_RISK}
    assert await _rows(engine, "risks") == []
    assert await _rows(engine, "risk_events") == []


async def test_a_covered_surface_is_a_409_naming_the_record_and_writes_nothing(
    client, db_session, engine
):
    """Kills dropping the coverage check, and a 409 that names no record or the wrong one."""
    await _seed_project(db_session)
    await _seed_findings(db_session, _trivy("f-1", "urllib3"))
    first = (await _dismiss(client, ["f-1"])).json()

    again = await _dismiss(client, ["f-1"], reason="again")

    assert again.status_code == 409
    assert set(again.json()) == _CONFLICT_KEYS
    assert again.json() == {"covering_dismissal_id": first["id"]}
    assert len(await _rows(engine, "risks")) == 1
    assert len(await _rows(engine, "risk_events")) == 1


async def test_a_member_whose_role_is_not_owner_may_dismiss_undo_and_read(client, db_session):
    """**G75's pin for M8.1.** Member-level dismissal is the decision (ADR-0036 decision 10)."""
    await _seed_project(db_session, member=_PLAIN_MEMBER, role=Role.MEMBER)
    await _seed_findings(db_session, _trivy("f-1", "urllib3"))

    created = await _dismiss(client, ["f-1"], user=_PLAIN_MEMBER)
    undone = await _undo(client, created.json()["id"], user=_PLAIN_MEMBER)
    listed = await _list(client, user=_PLAIN_MEMBER)

    assert (created.status_code, undone.status_code, listed.status_code) == (201, 201, 200)
    assert listed.json()["items"][0]["actor_user_id"] == _PLAIN_MEMBER


async def test_a_non_member_and_an_absent_project_are_indistinguishable_on_every_route(
    client, db_session, engine
):
    """One 404 for every denial (ADR-0022 decision 2), through the real
    `PostgresProjectAccessReader`, with nothing written.

    Each detail is built from the path's project id alone, so the bodies are compared with that
    id replaced: equal up to the id the caller sent is what "indistinguishable" can mean. Kills
    any route mapping its denial to 403, and a verdict moved below a read or a write.
    """
    await _seed_project(db_session)
    await _seed_findings(db_session, _trivy("f-1", "urllib3"))
    record = (await _dismiss(client, ["f-1"])).json()

    def _shape(response, project_id: str) -> tuple[int, str]:
        return response.status_code, response.json()["detail"].replace(project_id, "{id}")

    pairs = [
        (
            await _dismiss(client, ["f-1"], user=_STRANGER),
            await _dismiss(client, ["f-1"], project=_ABSENT_PROJECT),
        ),
        (
            await _undo(client, record["id"], user=_STRANGER),
            await _undo(client, record["id"], project=_ABSENT_PROJECT),
        ),
        (await _list(client, user=_STRANGER), await _list(client, project=_ABSENT_PROJECT)),
    ]

    for forbidden, absent in pairs:
        assert forbidden.status_code == 404
        assert _shape(forbidden, _PROJECT) == _shape(absent, _ABSENT_PROJECT)
    assert len(await _rows(engine, "risks")) == 1
    assert len(await _rows(engine, "risk_events")) == 1


# ---------------------------------------------------------------------------
# The reason's bound (ADR-0036 decision 7, G91)
# ---------------------------------------------------------------------------


async def test_a_reason_of_exactly_the_bound_is_accepted(client, db_session):
    await _seed_project(db_session)
    await _seed_findings(db_session, _trivy("f-1", "urllib3"))

    assert (await _dismiss(client, ["f-1"], reason="x" * 2000)).status_code == 201


async def test_an_over_long_or_blank_reason_is_a_422_and_writes_nothing(client, db_session, engine):
    """Kills `max_length` removed from either request schema, and the blank-reason check."""
    await _seed_project(db_session)
    await _seed_findings(db_session, _trivy("f-1", "urllib3"), _trivy("f-2", "flask"))
    record = (await _dismiss(client, ["f-2"])).json()

    assert (await _dismiss(client, ["f-1"], reason="x" * 2001)).status_code == 422
    assert (await _dismiss(client, ["f-1"], reason="   ")).status_code == 422
    assert (await _dismiss(client, ["f-1"], reason="\t\n")).status_code == 422
    assert (await _undo(client, record["id"], body={"reason": "x" * 2001})).status_code == 422
    assert (await _undo(client, record["id"], body={"reason": "  "})).status_code == 422
    assert len(await _rows(engine, "risks")) == 1
    assert len(await _rows(engine, "risk_events")) == 1


async def test_empty_or_repeated_ids_are_a_422(client, db_session):
    await _seed_project(db_session)

    assert (await _dismiss(client, [])).status_code == 422
    assert (await _dismiss(client, ["f-1", "f-1"])).status_code == 422


# ---------------------------------------------------------------------------
# Undoing, and the log being append-only
# ---------------------------------------------------------------------------


async def test_undo_appends_and_leaves_the_dismissal_byte_equal(client, db_session, engine):
    """Kills undo deleting or updating the dismissal event, or deleting the record."""
    await _seed_project(db_session)
    await _seed_findings(db_session, _trivy("f-1", "urllib3"))
    record = (await _dismiss(client, ["f-1"])).json()
    [risk_before] = await _rows(engine, "risks")
    [dismissal_before] = await _rows(engine, "risk_events")

    undone = await _undo(client, record["id"], body={"reason": "fixed upstream"})

    assert undone.status_code == 201
    body = undone.json()
    assert set(body) == _ITEM_KEYS
    assert (body["id"], body["state"], body["reason"]) == (
        record["id"],
        "undismissed",
        "fixed upstream",
    )
    assert await _rows(engine, "risks") == [risk_before]
    events = sorted(await _rows(engine, "risk_events"), key=lambda row: row[2])
    assert [row[2] for row in events] == [1, 2]
    assert events[0] == dismissal_before


async def test_undo_without_a_body_is_accepted(client, db_session):
    await _seed_project(db_session)
    await _seed_findings(db_session, _trivy("f-1", "urllib3"))
    record = (await _dismiss(client, ["f-1"])).json()

    undone = await _undo(client, record["id"])

    assert undone.status_code == 201
    assert undone.json()["reason"] is None


async def test_an_undone_record_is_a_409_on_a_second_undo(client, db_session, engine):
    await _seed_project(db_session)
    await _seed_findings(db_session, _trivy("f-1", "urllib3"))
    record = (await _dismiss(client, ["f-1"])).json()
    await _undo(client, record["id"])

    again = await _undo(client, record["id"])

    assert again.status_code == 409
    assert len(await _rows(engine, "risk_events")) == 2


async def test_undo_of_an_absent_record_is_a_404(client, db_session):
    await _seed_project(db_session)

    assert (await _undo(client, "no-such-record")).status_code == 404


async def test_after_undo_the_surface_can_be_dismissed_again_as_a_new_record(client, db_session):
    await _seed_project(db_session)
    await _seed_findings(db_session, _trivy("f-1", "urllib3"))
    first = (await _dismiss(client, ["f-1"])).json()
    await _undo(client, first["id"])

    second = await _dismiss(client, ["f-1"], reason="again")

    assert second.status_code == 201
    assert second.json()["id"] != first["id"]


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------


async def test_the_list_shows_each_records_latest_event_newest_dismissal_first(client, db_session):
    await _seed_project(db_session)
    await _seed_findings(db_session, _trivy("f-1", "urllib3"), _trivy("f-2", "flask"))
    first = (await _dismiss(client, ["f-1"])).json()
    second = (await _dismiss(client, ["f-2"], reason="second")).json()
    await _undo(client, first["id"], body={"reason": "undone"})

    listed = await _list(client)

    assert listed.status_code == 200
    page = listed.json()
    assert set(page) == _PAGE_KEYS
    assert page["total"] == 2
    for item in page["items"]:
        assert set(item) == _ITEM_KEYS
    by_id = {item["id"]: item for item in page["items"]}
    assert (by_id[first["id"]]["state"], by_id[first["id"]]["reason"]) == ("undismissed", "undone")
    assert (by_id[second["id"]]["state"], by_id[second["id"]]["reason"]) == ("dismissed", "second")
    assert [item["id"] for item in page["items"]] == [second["id"], first["id"]]


async def test_the_list_bounds_its_page_parameters(client, db_session):
    await _seed_project(db_session)

    for query in ("limit=0", "limit=201", "offset=-1"):
        response = await client.get(
            f"/projects/{_PROJECT}/risk-dismissals?{query}", headers=_auth_headers(_OWNER)
        )
        assert response.status_code == 422, query


async def test_scoring_that_disagrees_with_itself_is_a_fixed_500(client, db_session, engine):
    """**Overrides `get_explainable_risk_port`**, because `MemberFindingMissing` is unreachable
    through real storage: it needs the two findings reads to disagree. This test therefore
    exercises the route's mapping, not the real adapter (the rest of this file does that)."""

    class _Inconsistent:
        async def explainable_risk(self, *, project_id, user_id, finding_ids):
            raise ExplainableRiskInconsistent("reads disagreed")

    await _seed_project(db_session)
    app.dependency_overrides[get_explainable_risk_port] = _Inconsistent
    try:
        response = await _dismiss(client, ["f-1"])
    finally:
        app.dependency_overrides.pop(get_explainable_risk_port, None)

    assert response.status_code == 500
    assert response.json() == {"detail": "This project's Risks could not be scored consistently."}
    assert await _rows(engine, "risks") == []


async def test_a_lost_undo_race_is_a_409_not_a_500(client, db_session):
    """**Overrides `get_undismiss_risk_use_case`**, because two undos racing to one ordinal cannot
    be staged through one request at a time. The race itself is pinned against Postgres by the
    contract test's `append_event` returning `False`; this pins the route's mapping of it."""

    class _Raced:
        async def execute(self, *, project_id, user_id, dismissal_id, reason):
            raise RiskEventConflict("raced")

    await _seed_project(db_session)
    app.dependency_overrides[get_undismiss_risk_use_case] = _Raced
    try:
        response = await _undo(client, "any-record")
    finally:
        app.dependency_overrides.pop(get_undismiss_risk_use_case, None)

    assert response.status_code == 409
    assert response.json() == {"detail": "This dismissal changed during the request. Re-read it."}


async def test_the_risk_listings_stay_id_less_and_lifecycle_free_after_a_dismissal(
    client, db_session
):
    """ADR-0036's fence: no id and no state on `/risks` or `/scored-risks` (M8.2's overlay)."""
    await _seed_project(db_session)
    await _seed_findings(db_session, _trivy("f-1", "urllib3"))
    await _dismiss(client, ["f-1"])

    for route in ("risks", "scored-risks"):
        item = (
            await client.get(f"/projects/{_PROJECT}/{route}", headers=_auth_headers(_OWNER))
        ).json()["items"][0]
        for forbidden in ("id", "state", "resolved", "is_open", "status", "dismissed"):
            assert forbidden not in item


# ---------------------------------------------------------------------------
# G37: a dismissal survives every writer that touches a finding or a dismissal
# ---------------------------------------------------------------------------


async def test_a_dismissal_survives_every_writer_and_a_new_member_reopens_the_risk(
    client, db_session, engine
):
    """**G37's behaviour test** (ADR-0036 decision 8), observed through a second session.

    After a dismissal, run every writer that touches a finding or a dismissal: the findings upsert
    with a new member and a raised severity, a scored read, a dismissal of the grown surface, and
    an undo of that one. Scanning, normalization and Brief writers are not run; none of them
    names `risks` or `risk_events`.
    The first record's row and event must be exactly as written. Kills any path that rewrites a
    `risks` row's snapshot or an existing event, e.g. dismissal updating an existing record to the
    new surface.

    The grown surface is dismissable at all only because the subset rule reopens a Risk a new
    member joined (decision 2). A superset rule would have answered 409 here.
    """
    await _seed_project(db_session)
    await _seed_findings(db_session, _trivy("f-1", "urllib3"), _trivy("f-2", "urllib3"))
    first = (await _dismiss(client, ["f-1", "f-2"])).json()
    [risk_before] = await _rows(engine, "risks")
    [event_before] = await _rows(engine, "risk_events")

    await _seed_findings(
        db_session,
        _trivy("f-3", "urllib3"),
        _trivy("f-1", "urllib3", severity=Severity.CRITICAL),
    )
    grown = await _surface(client, "urllib3")
    assert grown["finding_ids"] == ["f-1", "f-2", "f-3"]
    reopened = await _dismiss(client, grown["finding_ids"], reason="grown")
    assert reopened.status_code == 201
    assert (await _undo(client, reopened.json()["id"])).status_code == 201

    risks_after = await _rows(engine, "risks")
    events_after = await _rows(engine, "risk_events")
    assert risk_before in risks_after
    assert event_before in events_after
    assert [row for row in events_after if row[1] == first["id"]] == [event_before]
