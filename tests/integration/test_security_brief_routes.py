"""`POST` and `GET /projects/{id}/briefs` end to end, against real Postgres. ADR-0033.

What this file is for:

- **The real port and repository, through real wiring** (**G65**). Every test overrides
  `get_explanation_provider`, so no key is read and nothing leaves the process. Only one test
  overrides `get_explainable_risk_port`, and its docstring says so.
- **The bindings.** Key-set equality for every object in the response, and the absences
  ADR-0033 decision 2 names.
- **The decisions that would flip silently.** Exact-set selection failing closed, the
  no-signal collision, append-only generation, and **G75**'s `Role.MEMBER` pin.

Findings are hand-written, following `test_scored_risks_routes.py`. Helpers are module-local,
because `tests/` is not a package.
"""

from datetime import UTC, datetime, timedelta

import httpx2
import pytest_asyncio
from sqlalchemy import text

from verion.modules.brief.domain.exceptions import (
    BriefMemberMissing,
    ExplanationUnavailable,
)
from verion.modules.brief.domain.explanation import Explanation
from verion.modules.correlation.ports.candidate_risk import CONFIDENCE_DEFINITION
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
from verion.platform.di import (
    get_clock,
    get_explainable_risk_port,
    get_explanation_provider,
    get_generate_security_brief_use_case,
)
from verion.platform.settings import get_settings
from verion.shared_kernel.confidence import Confidence
from verion.shared_kernel.scanner_tools import ScannerTool
from verion.shared_kernel.severity import Severity

_PROJECT = "project-1"
_OTHER_PROJECT = "project-2"
_OWNER = "user-owner"
_PLAIN_MEMBER = "user-plain-member"
_STRANGER = "user-stranger"
_SCAN = "scan-1"
_AT = datetime(2026, 1, 1, tzinfo=UTC)

_ITEM_KEYS = {
    "id",
    "finding_ids",
    "why_it_matters",
    "what_happened",
    "confidence",
    "priority",
    "priority_score",
    "thresholds",
    "reasoning",
    "model",
    "prompt_version",
    "generated_at",
}
_CONFIDENCE_KEYS = {"value", "definition"}
_SIGNAL_KEYS = {"name", "value", "produced_by", "note", "definition"}
_WHAT_HAPPENED_KEYS = {"text", "model", "prompt_version"}
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


@pytest_asyncio.fixture(autouse=True)
async def fake_provider(explanation_provider_factory):
    """Every test in this file narrates with the contract-tested fake, never OpenAI."""
    provider = explanation_provider_factory()
    app.dependency_overrides[get_explanation_provider] = lambda: provider
    yield provider
    app.dependency_overrides.pop(get_explanation_provider, None)


def _finding(*, finding_id: str, source: ScannerTool, location: Location) -> Finding:
    """`rule_id` derives from `finding_id`, so no two findings here collapse into one row."""
    return Finding(
        id=finding_id,
        project_id=_PROJECT,
        source=source,
        rule_id=f"rule-{finding_id}",
        severity=Severity.HIGH,
        native_severity="HIGH",
        title=f"title {finding_id}",
        location=location,
        evidence=Evidence(
            id=f"evidence-{finding_id}",
            finding_id=finding_id,
            scan_id=_SCAN,
            raw_payload="{}",
            source_tool=source,
            captured_at=_AT,
        ),
    )


def _trivy(finding_id: str, package: str) -> Finding:
    return _finding(
        finding_id=finding_id,
        source=ScannerTool.TRIVY,
        location=Location(file_path="requirements.txt", package=package, installed_version="1.0"),
    )


def _semgrep_without_signal(finding_id: str) -> Finding:
    """No package, no url, no serving declaration: a singleton surface whose key equals every
    other no-signal key in the project."""
    return _finding(
        finding_id=finding_id,
        source=ScannerTool.SEMGREP,
        location=Location(file_path="app.py", start_line=10, end_line=10),
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


async def _post(client, finding_ids, *, user=_OWNER, project=_PROJECT):
    return await client.post(
        f"/projects/{project}/briefs",
        json={"finding_ids": finding_ids},
        headers=_auth_headers(user),
    )


async def _list(client, *, user=_OWNER, project=_PROJECT):
    return await client.get(f"/projects/{project}/briefs", headers=_auth_headers(user))


# ---------------------------------------------------------------------------
# Generation and reading, through the real port and repository
# ---------------------------------------------------------------------------


async def test_an_unauthenticated_request_is_rejected(client, db_session):
    await _seed_project(db_session)

    assert (
        await client.post(f"/projects/{_PROJECT}/briefs", json={"finding_ids": ["f"]})
    ).status_code == 401
    assert (await client.get(f"/projects/{_PROJECT}/briefs")).status_code == 401


async def test_a_brief_stores_exactly_the_decision_the_scored_listing_shows(
    client, db_session, fake_provider
):
    await _seed_project(db_session)
    await _seed_findings(
        db_session, _trivy("f-1", "urllib3"), _trivy("f-2", "urllib3"), _trivy("f-3", "flask")
    )
    scored = (
        await client.get(f"/projects/{_PROJECT}/scored-risks", headers=_auth_headers(_OWNER))
    ).json()
    surface = next(item for item in scored["items"] if item["match"]["package"] == "urllib3")

    created = await _post(client, surface["finding_ids"])

    assert created.status_code == 201
    brief = created.json()
    assert brief["finding_ids"] == surface["finding_ids"] == ["f-1", "f-2"]
    assert (brief["priority"], brief["priority_score"]) == (
        surface["priority"],
        surface["priority_score"],
    )
    assert brief["thresholds"] == scored["thresholds"]
    for signal in ("severity", "exposure", "corroboration"):
        stored = {k: v for k, v in brief["reasoning"][signal].items() if k != "definition"}
        assert stored == surface["reasoning"][signal]
        assert brief["reasoning"][signal]["definition"]
    assert brief["why_it_matters"] == (
        f"{surface['priority']} at {surface['priority_score']}: severity "
        f"{surface['reasoning']['severity']['value']} + exposure 0 + corroboration 0."
    )
    assert brief["model"] == "fake"
    assert len(fake_provider.calls) == 1
    # The second narration, from the members' typed titles, with its own producer (ADR-0034).
    assert brief["what_happened"] == {
        "text": "2 findings: trivy title f-1; trivy title f-2",
        "model": "fake",
        "prompt_version": "m7.3-1",
    }
    [(members, member_count)] = fake_provider.describe_calls
    assert [member.finding_id for member in members] == ["f-1", "f-2"]
    assert member_count == 2

    listed = await _list(client)

    assert listed.status_code == 200
    assert listed.json()["total"] == 1
    assert listed.json()["items"] == [brief]


async def test_every_object_in_the_response_has_exactly_its_enumerated_keys(client, db_session):
    """ADR-0033 decision 2's field set, BINDING: an added and a missing key are both red."""
    await _seed_project(db_session)
    await _seed_findings(db_session, _trivy("f-1", "urllib3"))

    brief = (await _post(client, ["f-1"])).json()
    page = (await _list(client)).json()

    assert set(page) == _PAGE_KEYS
    for item in (brief, page["items"][0]):
        assert set(item) == _ITEM_KEYS
        assert set(item["thresholds"]) == {"fix_now_at", "plan_at"}
        assert set(item["reasoning"]) == {"severity", "exposure", "corroboration"}
        for signal in item["reasoning"].values():
            assert set(signal) == _SIGNAL_KEYS
        assert set(item["what_happened"]) == _WHAT_HAPPENED_KEYS


async def test_what_a_brief_does_not_carry(client, db_session):
    """G74, ADR-0025 decision 1 and ADR-0033 decision 4, each anchored on a real body.

    `what_happened` left this list at M7.3 (ADR-0034) and `confidence` at M8.5 (ADR-0037),
    each by decision. `recommended_action` and `estimated_effort` did not leave it — they were
    cut to V2, so nothing will ever produce them here."""
    await _seed_project(db_session)
    await _seed_findings(db_session, _trivy("f-1", "urllib3"))

    brief = (await _post(client, ["f-1"])).json()
    page = (await _list(client)).json()

    for absent in (
        "estimated_effort",
        "recommended_action",
        "risk_id",
        "project_id",
    ):
        assert absent not in brief
        assert absent not in page["items"][0]
    assert "normalization" not in page
    assert "normalization" not in brief


async def test_a_brief_carries_its_confidence_with_the_definition_on_the_item(client, db_session):
    """FR-8's fourth part at the surface. ADR-0037 decisions 8 and 10.

    On the item rather than an envelope, because a Brief is one narrated record and has none —
    the divergence from `/scored-risks` is deliberate and grounded in that ADR, so it is not
    read as **G17**'s shape.

    The value is the ENGINE's for the surface it scored, and `reported` here because the
    member is a Trivy finding keyed on its own package.
    """
    await _seed_project(db_session)
    await _seed_findings(db_session, _trivy("f-1", "urllib3"))

    brief = (await _post(client, ["f-1"])).json()

    assert set(brief["confidence"]) == _CONFIDENCE_KEYS
    assert brief["confidence"]["value"] == Confidence.REPORTED.value
    assert brief["confidence"]["definition"] == CONFIDENCE_DEFINITION


async def test_the_definition_is_byte_identical_on_the_envelope_and_on_a_brief(client, db_session):
    """ONE owner, two placements — and this is what makes that a claim rather than a comment.

    `correlation` declares `CONFIDENCE_DEFINITION` once. `/scored-risks` puts it on its
    envelope and a Brief on its item, for reasons each route's own shape gives. Two placements
    are two chances for somebody to write the text a second time, and a second copy is free to
    drift from the first. Asserted across the two live responses, not against the constant
    alone, because comparing each to the source separately would still pass if one adapter
    reformatted it.
    """
    await _seed_project(db_session)
    await _seed_findings(db_session, _trivy("f-1", "urllib3"))

    brief = (await _post(client, ["f-1"])).json()
    scored = (
        await client.get(f"/projects/{_PROJECT}/scored-risks", headers=_auth_headers(_OWNER))
    ).json()

    assert brief["confidence"]["definition"] == scored["confidence_definition"]
    assert brief["confidence"]["definition"] == CONFIDENCE_DEFINITION


async def test_generation_is_append_only_and_the_list_is_newest_first(client, db_session):
    """ADR-0033 decision 3. Timestamps are made distinct here, so the order asserted is the
    `generated_at` order and never the `id` tie-break (pinned in the repository test)."""

    class _AdvancingClock:
        def __init__(self):
            self._now = _AT

        def now(self):
            self._now += timedelta(seconds=1)
            return self._now

    clock = _AdvancingClock()
    app.dependency_overrides[get_clock] = lambda: clock
    try:
        await _seed_project(db_session)
        await _seed_findings(db_session, _trivy("f-1", "urllib3"))
        first = (await _post(client, ["f-1"])).json()
        second = (await _post(client, ["f-1"])).json()
        listed = (await _list(client)).json()
    finally:
        app.dependency_overrides.pop(get_clock, None)

    assert first["id"] != second["id"]
    assert listed["total"] == 2
    assert [item["id"] for item in listed["items"]] == [second["id"], first["id"]]


async def test_the_list_route_pages_with_the_query_it_is_given(client, db_session):
    """The route's own wiring of `limit` and `offset`, and its bounds (M4.5's, declared locally)."""

    class _AdvancingClock:
        def __init__(self):
            self._now = _AT

        def now(self):
            self._now += timedelta(seconds=1)
            return self._now

    clock = _AdvancingClock()
    app.dependency_overrides[get_clock] = lambda: clock
    try:
        await _seed_project(db_session)
        await _seed_findings(db_session, _trivy("f-1", "urllib3"))
        older = (await _post(client, ["f-1"])).json()
        await _post(client, ["f-1"])
    finally:
        app.dependency_overrides.pop(get_clock, None)

    page = await client.get(
        f"/projects/{_PROJECT}/briefs?limit=1&offset=1", headers=_auth_headers(_OWNER)
    )
    too_large = await client.get(
        f"/projects/{_PROJECT}/briefs?limit=201", headers=_auth_headers(_OWNER)
    )
    too_small = await client.get(
        f"/projects/{_PROJECT}/briefs?limit=0", headers=_auth_headers(_OWNER)
    )

    assert page.status_code == 200
    body = page.json()
    assert (body["limit"], body["offset"], body["total"]) == (1, 1, 2)
    assert [item["id"] for item in body["items"]] == [older["id"]]
    assert too_large.status_code == too_small.status_code == 422


async def test_two_no_signal_surfaces_each_get_their_own_brief(client, db_session):
    """Equal match keys, distinct members: why a Brief never refers to a Risk by its key."""
    await _seed_project(db_session)
    await _seed_findings(db_session, _semgrep_without_signal("s-1"), _semgrep_without_signal("s-2"))

    first = await _post(client, ["s-1"])
    second = await _post(client, ["s-2"])

    assert first.status_code == second.status_code == 201
    assert first.json()["finding_ids"] == ["s-1"]
    assert second.json()["finding_ids"] == ["s-2"]
    assert first.json()["reasoning"]["severity"]["produced_by"] == ["s-1"]
    assert second.json()["reasoning"]["severity"]["produced_by"] == ["s-2"]


async def test_a_set_that_is_not_a_current_surface_is_refused_and_nothing_is_stored(
    client, db_session, fake_provider
):
    """ADR-0033 decision 1: a subset of a surface fails closed; no call, no row."""
    await _seed_project(db_session)
    await _seed_findings(db_session, _trivy("f-1", "urllib3"), _trivy("f-2", "urllib3"))

    response = await _post(client, ["f-1"])

    assert response.status_code == 404
    assert response.json() == {"detail": _NO_CURRENT_RISK}
    assert fake_provider.calls == []
    assert (await _list(client)).json()["total"] == 0


# ---------------------------------------------------------------------------
# Authorization — ADR-0033 decision 7
# ---------------------------------------------------------------------------


async def test_a_non_member_and_an_absent_project_are_indistinguishable(client, db_session):
    await _seed_project(db_session)
    await _seed_findings(db_session, _trivy("f-1", "urllib3"))

    forbidden_post = await _post(client, ["f-1"], user=_STRANGER)
    absent_post = await _post(client, ["f-1"], project=_OTHER_PROJECT)
    forbidden_get = await _list(client, user=_STRANGER)
    absent_get = await _list(client, project=_OTHER_PROJECT)

    assert forbidden_post.status_code == absent_post.status_code == 404
    assert forbidden_get.status_code == absent_get.status_code == 404


async def test_a_member_whose_role_is_not_owner_may_generate_and_read(client, db_session):
    """**G75's pin.** Member-level generation is the decision, not an accident.

    No producer in `src/` creates a non-OWNER membership, so this path is unreachable in
    production today, and member-level and owner-gated are indistinguishable there. This test
    makes the choice explicit, so it cannot flip silently.
    """
    await _seed_project(db_session, member=_PLAIN_MEMBER, role=Role.MEMBER)
    await _seed_findings(db_session, _trivy("f-1", "urllib3"))

    created = await _post(client, ["f-1"], user=_PLAIN_MEMBER)
    listed = await _list(client, user=_PLAIN_MEMBER)

    assert created.status_code == 201
    assert listed.status_code == 200
    assert listed.json()["total"] == 1


# ---------------------------------------------------------------------------
# Failures — ADR-0033 decision 9
# ---------------------------------------------------------------------------


class _EchoingFailingProvider:
    """Fails with a message carrying key-shaped text, as a provider body could (rule 12, G71).

    `describe` is the first call since M7.3, so it is the one that fails here."""

    async def describe(self, *, members, member_count):
        raise ExplanationUnavailable(
            "OpenAI said: Incorrect API key provided: sk-proj-SENTINEL-4f2a"
        )

    async def explain(self, *, decision):
        raise ExplanationUnavailable(
            "OpenAI said: Incorrect API key provided: sk-proj-SENTINEL-4f2a"
        )


async def test_a_provider_failure_is_a_502_with_a_fixed_detail_and_stores_nothing(
    client, db_session
):
    await _seed_project(db_session)
    await _seed_findings(db_session, _trivy("f-1", "urllib3"))
    app.dependency_overrides[get_explanation_provider] = _EchoingFailingProvider

    response = await _post(client, ["f-1"])

    assert response.status_code == 502
    assert response.json() == {"detail": "The Brief could not be generated. Nothing was stored."}
    assert "SENTINEL" not in response.text
    assert (await _list(client)).json()["total"] == 0


async def test_duplicate_or_empty_finding_ids_are_unprocessable(client, db_session):
    await _seed_project(db_session)
    await _seed_findings(db_session, _trivy("f-1", "urllib3"))

    assert (await _post(client, ["f-1", "f-1"])).status_code == 422
    assert (await _post(client, [])).status_code == 422


class _InconsistentRisks:
    """Stands in for `ExplainableRiskPort` to reach the disagreeing-reads case, which nothing
    can produce in production (G11). **This test does NOT exercise the real adapter**; its
    translation is covered by `tests/unit/test_explainable_risk_provider.py`."""

    async def explainable_risk(self, *, project_id, user_id, finding_ids):
        raise ExplainableRiskInconsistent("Finding 'no-such-finding' is in a candidate Risk")


async def test_disagreeing_reads_are_a_500_with_a_fixed_detail(client, db_session):
    await _seed_project(db_session)
    app.dependency_overrides[get_explainable_risk_port] = _InconsistentRisks
    try:
        response = await _post(client, ["f-1"])
    finally:
        app.dependency_overrides.pop(get_explainable_risk_port, None)

    assert response.status_code == 500
    assert response.json() == {"detail": "This project's Risks could not be scored consistently."}


async def test_an_unreadable_stored_brief_fails_the_list_with_a_fixed_500(client, db_session):
    """Never skipped: one bad row is a project-wide read failure (ADR-0033 decision 9)."""
    await _seed_project(db_session)
    await db_session.execute(
        text(
            "INSERT INTO security_briefs (id, project_id, finding_ids, decision, why_it_matters,"
            " model, prompt_version, generated_at) VALUES ('b-bad', :project, ARRAY['f-9'],"
            " CAST(:decision AS JSONB), 'STORED-NARRATIVE-SENTINEL', 'm', 'v', :at)"
        ),
        {"project": _PROJECT, "decision": '{"version": 2, "decision": {}}', "at": _AT},
    )
    await db_session.commit()

    response = await _list(client)

    assert response.status_code == 500
    assert response.json() == {"detail": "A stored Brief for this project could not be read."}
    assert "SENTINEL" not in response.text


# ---------------------------------------------------------------------------
# M7.3: what_happened on the routes (ADR-0034 decisions 5, 6 and 8)
# ---------------------------------------------------------------------------


async def test_the_list_carries_what_happened_whole(client, db_session):
    """Decision 6: kept on the list, never dropped or truncated, because its inputs are fields
    the findings listing already returns in bulk."""
    await _seed_project(db_session)
    await _seed_findings(db_session, _trivy("f-1", "urllib3"))

    created = (await _post(client, ["f-1"])).json()
    listed = (await _list(client)).json()

    assert listed["items"][0]["what_happened"] == created["what_happened"]
    assert listed["items"][0]["what_happened"]["text"] == "1 findings: trivy title f-1"


async def test_a_brief_written_before_m7_3_lists_with_a_null_what_happened(client, db_session):
    await _seed_project(db_session)
    await _seed_findings(db_session, _trivy("f-1", "urllib3"))
    created = (await _post(client, ["f-1"])).json()
    await db_session.execute(
        text(
            "UPDATE security_briefs SET what_happened = NULL, what_happened_model = NULL,"
            " what_happened_prompt_version = NULL WHERE id = :id"
        ),
        {"id": created["id"]},
    )
    await db_session.commit()

    listed = await _list(client)

    assert listed.status_code == 200
    assert listed.json()["items"][0]["what_happened"] is None


class _RejectingProvider:
    """Its describe output names a bucket no member supplied, so M6 rejects it."""

    def __init__(self):
        self.explain_calls = 0

    async def describe(self, *, members, member_count):
        return Explanation(text="This is fix_now.", model="m", prompt_version="m7.3-1")

    async def explain(self, *, decision):
        self.explain_calls += 1
        raise AssertionError("explain must not be called after a rejected describe")


async def test_a_rejected_what_happened_is_the_fixed_502_and_stores_nothing(client, db_session):
    await _seed_project(db_session)
    await _seed_findings(db_session, _trivy("f-1", "urllib3"))
    provider = _RejectingProvider()
    app.dependency_overrides[get_explanation_provider] = lambda: provider

    response = await _post(client, ["f-1"])

    assert response.status_code == 502
    assert response.json() == {"detail": "The Brief could not be generated. Nothing was stored."}
    assert "fix_now" not in response.text
    assert provider.explain_calls == 0
    assert (await _list(client)).json()["total"] == 0


class _MemberMissingUseCase:
    """Stands in for the use case to reach `BriefMemberMissing`, which no real read produces
    (nothing deletes a finding). **This test does NOT exercise the real use case**; its raise
    is covered by `tests/unit/test_generate_security_brief.py`."""

    async def execute(self, *, project_id, user_id, finding_ids):
        raise BriefMemberMissing("Finding 'MEMBER-SENTINEL' is in a scored Risk")


async def test_a_member_that_cannot_be_read_back_is_a_fixed_500(client, db_session):
    await _seed_project(db_session)
    app.dependency_overrides[get_generate_security_brief_use_case] = _MemberMissingUseCase
    try:
        response = await _post(client, ["f-1"])
    finally:
        app.dependency_overrides.pop(get_generate_security_brief_use_case, None)

    assert response.status_code == 500
    assert response.json() == {"detail": "A finding in this Risk could not be read."}
    assert "SENTINEL" not in response.text
