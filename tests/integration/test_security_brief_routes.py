"""`POST`, `GET /projects/{id}/briefs` and the generation poll, end to end. ADR-0033, ADR-0038.

What this file is for:

- **The real port and repository, through real wiring** (**G65**), and since M8.6 **the real
  job**. Generation moved off the request path, so a fake provider no longer reaches it through
  `app.dependency_overrides`: that rewrites FastAPI's request graph, and `generate_brief` builds
  its own from `session_factory()` and `ctx`. `_generate` below calls the job in process with a
  hand-built `ctx`, which is `test_scan_routes.py`'s shape and is also the job's *real* wiring,
  since ADR-0038 decision 9 genuinely puts the provider in `ctx`.
- **The bindings.** Key-set equality for every object in the response — the Brief's, and since
  M8.6 the 202 envelope's and the poll's — and the absences ADR-0033 decision 2 names.
- **The decisions that would flip silently.** Exact-set selection failing closed (now as a
  `surface_changed` generation), the no-signal collision, append-only generation, **G75**'s
  `Role.MEMBER` pin, and **the poll's actor match**, which is what makes ADR-0038 decision 6's
  unobservability real rather than asserted.

**`get_arq_pool` is overridden with a real pool**, never `get_brief_generation_queue`, so every
POST runs through the real `AfterCommitBriefGenerationQueue` and `get_db_session`'s after-commit
hook. Jobs are removed from the shared queue at teardown, so a later burst worker never takes a
job whose row a test wiped.

Findings are hand-written, following `test_scored_risks_routes.py`. Helpers are module-local,
because `tests/` is not a package.
"""

from datetime import UTC, datetime, timedelta

import httpx2
import pytest
import pytest_asyncio
from arq.connections import RedisSettings, create_pool
from arq.constants import default_queue_name, job_key_prefix
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

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
from verion.platform import worker as worker_module
from verion.platform.app import app
from verion.platform.clock import SystemClock
from verion.platform.di import get_arq_pool, get_clock
from verion.platform.settings import get_settings
from verion.platform.worker import generate_brief
from verion.shared_kernel.confidence import Confidence
from verion.shared_kernel.scanner_tools import ScannerTool
from verion.shared_kernel.severity import Severity

_PROJECT = "project-1"
_OTHER_PROJECT = "project-2"
_OWNER = "user-owner"
_PLAIN_MEMBER = "user-plain-member"
_SECOND_MEMBER = "user-second-member"
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
_ACCEPTED_KEYS = {"id", "status"}
_GENERATION_KEYS = {"id", "status", "failure_kind", "detail", "brief_id"}

_NO_CURRENT_RISK = (
    "No current Risk in this project has exactly these findings. Re-read the scored Risks."
)
_RETRYABLE = "The Brief could not be generated. Nothing was stored. Asking again may succeed."
_NOT_RETRYABLE = "This Brief could not be generated. Asking again will not help."


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
    """Every test in this file narrates with the contract-tested fake, never OpenAI.

    Since M8.6 it reaches the narration through the JOB's `ctx` rather than through
    `app.dependency_overrides`, because generation is no longer on the request path. `_generate`
    and `_run_job` below pass it; nothing overrides `get_explanation_provider`, which now has no
    consumer on any route.
    """
    return explanation_provider_factory()


@pytest_asyncio.fixture
async def queue():
    """A REAL arq pool behind `get_arq_pool`, so every POST runs the real after-commit enqueue.

    `test_scan_routes.py`'s fixture, minus its `_SpyPool`: the commit-ordering observation lives
    in one test here and builds its own spy, rather than every test paying for a second session
    on each enqueue.

    Enqueued jobs are deleted at teardown. This file runs the job itself, in process, so a job
    left in the shared queue would be taken twice — once here and once by whatever burst worker
    a later test starts.
    """
    pool = await create_pool(RedisSettings.from_dsn(get_settings().redis_url))
    app.dependency_overrides[get_arq_pool] = lambda: pool
    enqueued: list[str] = []
    yield pool, enqueued
    for generation_id in enqueued:
        await pool.delete(job_key_prefix + f"brief:{generation_id}")
        await pool.zrem(default_queue_name, f"brief:{generation_id}")
    app.dependency_overrides.pop(get_arq_pool, None)
    await pool.aclose()


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


async def _seed_project(
    db_session, *, member: str = _OWNER, role: Role = Role.OWNER, extra_member: str | None = None
) -> None:
    await PostgresProjectRepository(db_session).add(
        Project(id=_PROJECT, owner_id=_OWNER, name="Project", created_at=_AT)
    )
    memberships = PostgresProjectMembershipRepository(db_session)
    await memberships.add(ProjectMembership(project_id=_PROJECT, user_id=member, role=role))
    if extra_member is not None:
        # A SECOND member of the same project, written directly because no producer in `src/`
        # creates a non-OWNER membership (**G75**). It exists for the poll's actor match: the
        # case where `may_read_project` says yes and the generation is still not this caller's.
        await memberships.add(
            ProjectMembership(project_id=_PROJECT, user_id=extra_member, role=Role.MEMBER)
        )
    await db_session.commit()


async def _seed_findings(db_session, *findings: Finding) -> None:
    repository = PostgresFindingRepository(db_session)
    for finding in findings:
        await repository.upsert(finding)
    await db_session.commit()


async def _post(client, finding_ids, *, user=_OWNER, project=_PROJECT):
    """The RAW request. Returns the 202 envelope, or the refusal.

    Deliberately not "post and run the job": three tests here assert that a request is refused
    before any generation exists, and a helper that drained a queue would have nothing to drain.
    Tests that want a Brief use `_generate`.
    """
    return await client.post(
        f"/projects/{project}/briefs",
        json={"finding_ids": finding_ids},
        headers=_auth_headers(user),
    )


async def _poll(client, generation_id, *, user=_OWNER, project=_PROJECT):
    return await client.get(
        f"/projects/{project}/brief-generations/{generation_id}", headers=_auth_headers(user)
    )


async def _run_job(fake_provider, generation_id, queue=None):
    """Run the real worker job in process, with the fake provider in `ctx`.

    `ctx["explanations"]` is the whole of what this hands over, and that is not a shortcut: it
    is exactly what `on_startup` puts there (ADR-0038 decision 9). Everything else the job needs
    it builds itself from `session_factory()`, against the real database — which is the point.
    """
    if queue is not None:
        queue[1].append(generation_id)
    await generate_brief({"explanations": fake_provider}, generation_id)


async def _generate(
    client, fake_provider, finding_ids, *, user=_OWNER, project=_PROJECT, queue=None
):
    """POST, run the job, and return the stored Brief. Asserts the 202 on the way through.

    Returns the Brief as `GET …/briefs` serves it, because the POST no longer returns one. The
    generation id is the route's; the Brief's own id comes back through the poll's `brief_id`.
    """
    accepted = await _post(client, finding_ids, user=user, project=project)
    assert accepted.status_code == 202, accepted.text
    generation_id = accepted.json()["id"]
    await _run_job(fake_provider, generation_id, queue)
    polled = (await _poll(client, generation_id, user=user, project=project)).json()
    assert polled["status"] == "succeeded", polled
    listed = (await _list(client, user=user, project=project)).json()
    return next(item for item in listed["items"] if item["id"] == polled["brief_id"])


async def _list(client, *, user=_OWNER, project=_PROJECT):
    return await client.get(f"/projects/{project}/briefs", headers=_auth_headers(user))


# ---------------------------------------------------------------------------
# Generation and reading, through the real port and repository
# ---------------------------------------------------------------------------


async def test_an_unauthenticated_request_is_rejected(client, db_session):
    """All THREE routes, the poll included. 401 fires before any route body, so this test needs
    no generation to exist and no job to run."""
    await _seed_project(db_session)

    assert (
        await client.post(f"/projects/{_PROJECT}/briefs", json={"finding_ids": ["f"]})
    ).status_code == 401
    assert (await client.get(f"/projects/{_PROJECT}/briefs")).status_code == 401
    assert (await client.get(f"/projects/{_PROJECT}/brief-generations/any-id")).status_code == 401


async def test_a_brief_stores_exactly_the_decision_the_scored_listing_shows(
    client, db_session, fake_provider, queue
):
    await _seed_project(db_session)
    await _seed_findings(
        db_session, _trivy("f-1", "urllib3"), _trivy("f-2", "urllib3"), _trivy("f-3", "flask")
    )
    scored = (
        await client.get(f"/projects/{_PROJECT}/scored-risks", headers=_auth_headers(_OWNER))
    ).json()
    surface = next(item for item in scored["items"] if item["match"]["package"] == "urllib3")

    brief = await _generate(client, fake_provider, surface["finding_ids"], queue=queue)

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


async def test_every_object_in_the_response_has_exactly_its_enumerated_keys(
    client, db_session, fake_provider, queue
):
    """ADR-0033 decision 2's field set, BINDING: an added and a missing key are both red.

    **NARROWED at M8.6.** It used to assert this set twice, on the POST body and on the list
    item, because the POST returned a Brief. It no longer does, so the list item is the only
    anchor left here. The two new envelopes are a different proposition and get their own test
    below rather than this one's name.
    """
    await _seed_project(db_session)
    await _seed_findings(db_session, _trivy("f-1", "urllib3"))

    brief = await _generate(client, fake_provider, ["f-1"], queue=queue)
    page = (await _list(client)).json()

    assert set(page) == _PAGE_KEYS
    for item in (brief, page["items"][0]):
        assert set(item) == _ITEM_KEYS
        assert set(item["thresholds"]) == {"fix_now_at", "plan_at"}
        assert set(item["reasoning"]) == {"severity", "exposure", "corroboration"}
        for signal in item["reasoning"].values():
            assert set(signal) == _SIGNAL_KEYS
        assert set(item["what_happened"]) == _WHAT_HAPPENED_KEYS


async def test_the_two_generation_envelopes_have_exactly_their_enumerated_keys(
    client, db_session, fake_provider, queue
):
    """M8.6's two new rule-10 schemas, by EQUALITY: an added and a missing key are both red.

    A new test rather than a widening of the one above, because this is a different claim about
    different objects — ADR-0038 decision 8's shapes, which M8.2 consumes and which this commit
    makes final.

    The 202's key set is `ScanAcceptedResponse`'s, deliberately. The poll's carries `detail`,
    which is DERIVED from `failure_kind` rather than stored, so it is `null` here exactly
    because `failure_kind` is.
    """
    await _seed_project(db_session)
    await _seed_findings(db_session, _trivy("f-1", "urllib3"))

    accepted = await _post(client, ["f-1"])

    assert accepted.status_code == 202
    assert accepted.json().keys() == _ACCEPTED_KEYS
    assert accepted.json()["status"] == "pending"

    generation_id = accepted.json()["id"]
    pending = await _poll(client, generation_id)

    assert pending.status_code == 200
    assert pending.json().keys() == _GENERATION_KEYS
    assert pending.json() == {
        "id": generation_id,
        "status": "pending",
        "failure_kind": None,
        "detail": None,
        "brief_id": None,
    }

    await _run_job(fake_provider, generation_id, queue)
    done = (await _poll(client, generation_id)).json()

    assert done.keys() == _GENERATION_KEYS
    assert (done["status"], done["failure_kind"], done["detail"]) == ("succeeded", None, None)
    assert done["brief_id"] is not None


async def test_what_a_brief_does_not_carry(client, db_session, fake_provider, queue):
    """G74, ADR-0025 decision 1 and ADR-0033 decision 4, each anchored on a real body.

    `what_happened` left this list at M7.3 (ADR-0034) and `confidence` at M8.5 (ADR-0037),
    each by decision. `recommended_action` and `estimated_effort` did not leave it — they were
    cut to V2, so nothing will ever produce them here."""
    await _seed_project(db_session)
    await _seed_findings(db_session, _trivy("f-1", "urllib3"))

    brief = await _generate(client, fake_provider, ["f-1"], queue=queue)
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


async def test_a_brief_carries_its_confidence_with_the_definition_on_the_item(
    client, db_session, fake_provider, queue
):
    """FR-8's fourth part at the surface. ADR-0037 decisions 8 and 10.

    On the item rather than an envelope, because a Brief is one narrated record and has none —
    the divergence from `/scored-risks` is deliberate and grounded in that ADR, so it is not
    read as **G17**'s shape.

    The value is the ENGINE's for the surface it scored, and `reported` here because the
    member is a Trivy finding keyed on its own package.
    """
    await _seed_project(db_session)
    await _seed_findings(db_session, _trivy("f-1", "urllib3"))

    brief = await _generate(client, fake_provider, ["f-1"], queue=queue)

    assert set(brief["confidence"]) == _CONFIDENCE_KEYS
    assert brief["confidence"]["value"] == Confidence.REPORTED.value
    assert brief["confidence"]["definition"] == CONFIDENCE_DEFINITION


async def test_the_definition_is_byte_identical_on_the_envelope_and_on_a_brief(
    client, db_session, fake_provider, queue
):
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

    brief = await _generate(client, fake_provider, ["f-1"], queue=queue)
    scored = (
        await client.get(f"/projects/{_PROJECT}/scored-risks", headers=_auth_headers(_OWNER))
    ).json()

    assert brief["confidence"]["definition"] == scored["confidence_definition"]
    assert brief["confidence"]["definition"] == CONFIDENCE_DEFINITION


class _AdvancingClock:
    def __init__(self):
        self._now = _AT

    def now(self):
        self._now += timedelta(seconds=1)
        return self._now


def _advance_the_brief_clock(monkeypatch):
    """Make each Brief's `generated_at` distinct, in the process that now sets it.

    **`app.dependency_overrides[get_clock]` no longer reaches a Brief.** Since M8.6 the
    timestamp is stamped by `platform/worker.py`'s own `SystemClock()`, built per job outside
    any FastAPI graph, so the override would leave two Briefs sharing `_AT` and the order under
    test would silently become the `id` tie-break. Patching the worker's symbol is commit 1's
    precedent (`monkeypatch.setattr(openai_adapter_module, "_CALL_DEADLINE_SECONDS", 0.05)`).

    The route's own clock is overridden too, so `requested_at` advances with it — not asserted
    anywhere, and kept consistent so a later test cannot be surprised by two rows minted at the
    same instant.
    """
    clock = _AdvancingClock()
    monkeypatch.setattr(worker_module, "SystemClock", lambda: clock)
    app.dependency_overrides[get_clock] = lambda: clock
    return clock


async def test_generation_is_append_only_and_the_list_is_newest_first(
    client, db_session, fake_provider, queue, monkeypatch
):
    """ADR-0033 decision 3. Timestamps are made distinct here, so the order asserted is the
    `generated_at` order and never the `id` tie-break (pinned in the repository test).

    **Two id spaces since M8.6, and conflating them is how this test would silently pass.** The
    POST returns a GENERATION id; the list returns BRIEF ids. They are different rows in
    different tables, so the Brief ids are reached through each poll's `brief_id` rather than
    off the POST body, which is what the assertion used to do.
    """
    _advance_the_brief_clock(monkeypatch)
    try:
        await _seed_project(db_session)
        await _seed_findings(db_session, _trivy("f-1", "urllib3"))
        first = await _generate(client, fake_provider, ["f-1"], queue=queue)
        second = await _generate(client, fake_provider, ["f-1"], queue=queue)
        listed = (await _list(client)).json()
    finally:
        app.dependency_overrides.pop(get_clock, None)

    assert first["id"] != second["id"]
    assert listed["total"] == 2
    assert [item["id"] for item in listed["items"]] == [second["id"], first["id"]]


async def test_the_list_route_pages_with_the_query_it_is_given(
    client, db_session, fake_provider, queue, monkeypatch
):
    """The route's own wiring of `limit` and `offset`, and its bounds (M4.5's, declared locally)."""
    _advance_the_brief_clock(monkeypatch)
    try:
        await _seed_project(db_session)
        await _seed_findings(db_session, _trivy("f-1", "urllib3"))
        older = await _generate(client, fake_provider, ["f-1"], queue=queue)
        await _generate(client, fake_provider, ["f-1"], queue=queue)
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


async def test_two_no_signal_surfaces_each_get_their_own_brief(
    client, db_session, fake_provider, queue
):
    """Equal match keys, distinct members: why a Brief never refers to a Risk by its key."""
    await _seed_project(db_session)
    await _seed_findings(db_session, _semgrep_without_signal("s-1"), _semgrep_without_signal("s-2"))

    first = await _generate(client, fake_provider, ["s-1"], queue=queue)
    second = await _generate(client, fake_provider, ["s-2"], queue=queue)

    assert first["finding_ids"] == ["s-1"]
    assert second["finding_ids"] == ["s-2"]
    assert first["reasoning"]["severity"]["produced_by"] == ["s-1"]
    assert second["reasoning"]["severity"]["produced_by"] == ["s-2"]


async def test_a_set_that_is_not_a_current_surface_is_refused_and_nothing_is_stored(
    client, db_session, fake_provider, queue
):
    """ADR-0033 decision 1: a subset of a surface fails closed; no call, no row.

    **A DIFFERENT TEST under the same name (M8.6).** It used to assert the REQUEST was refused
    with a 404. The route can no longer refuse: it does not resolve the surface, because
    resolving needs the verdict, the correlation and the scoring, all of which moved to the
    worker. So the request is accepted and the refusal arrives at the poll, as a terminal
    `failed` / `surface_changed` generation (ADR-0038 decision 6).

    **What survives unchanged is the property worth having**: the refusal is still before any
    billed call, and still stores nothing. `fake_provider.calls == []` is what pins that, and it
    is why the old test's `detail` string is reused verbatim — the same refusal, reported later.
    """
    await _seed_project(db_session)
    await _seed_findings(db_session, _trivy("f-1", "urllib3"), _trivy("f-2", "urllib3"))

    accepted = await _post(client, ["f-1"])

    assert accepted.status_code == 202
    generation_id = accepted.json()["id"]
    await _run_job(fake_provider, generation_id, queue)

    polled = (await _poll(client, generation_id)).json()

    assert polled["status"] == "failed"
    assert polled["failure_kind"] == "surface_changed"
    assert polled["detail"] == _NO_CURRENT_RISK
    assert polled["brief_id"] is None
    assert fake_provider.calls == []
    assert fake_provider.describe_calls == []
    assert (await _list(client)).json()["total"] == 0


# ---------------------------------------------------------------------------
# Authorization — ADR-0033 decision 7
# ---------------------------------------------------------------------------


async def test_a_non_member_and_an_absent_project_are_indistinguishable(client, db_session, queue):
    """The POST's denial is now the ROUTE's own `may_read_project`, not one inherited through
    `risk_engine`'s port — ADR-0038 decision 4's first gate. Same status, same body, and no row
    or job either way."""
    await _seed_project(db_session)
    await _seed_findings(db_session, _trivy("f-1", "urllib3"))

    forbidden_post = await _post(client, ["f-1"], user=_STRANGER)
    absent_post = await _post(client, ["f-1"], project=_OTHER_PROJECT)
    forbidden_get = await _list(client, user=_STRANGER)
    absent_get = await _list(client, project=_OTHER_PROJECT)

    assert forbidden_post.status_code == absent_post.status_code == 404
    assert forbidden_get.status_code == absent_get.status_code == 404
    assert forbidden_post.json() == {"detail": f"No readable project with id '{_PROJECT}'"}
    assert absent_post.json() == {"detail": f"No readable project with id '{_OTHER_PROJECT}'"}
    # The POST's and the list's bodies are the same sentence, so neither refusal is
    # distinguishable from the other (**G17**).
    assert forbidden_post.json() == forbidden_get.json()


async def test_a_member_whose_role_is_not_owner_may_generate_and_read(
    client, db_session, fake_provider, queue
):
    """**G75's pin.** Member-level generation is the decision, not an accident.

    No producer in `src/` creates a non-OWNER membership, so this path is unreachable in
    production today, and member-level and owner-gated are indistinguishable there. This test
    makes the choice explicit, so it cannot flip silently.

    Since M8.6 it also pins that BOTH gates admit a plain member — the route's own
    `may_read_project` and the worker's re-authorization — because `_generate` runs the job and
    asserts the generation succeeded.
    """
    await _seed_project(db_session, member=_PLAIN_MEMBER, role=Role.MEMBER)
    await _seed_findings(db_session, _trivy("f-1", "urllib3"))

    await _generate(client, fake_provider, ["f-1"], user=_PLAIN_MEMBER, queue=queue)
    listed = await _list(client, user=_PLAIN_MEMBER)

    assert listed.status_code == 200
    assert listed.json()["total"] == 1


async def test_another_member_of_the_same_project_cannot_read_a_generation(
    client, db_session, fake_provider, queue
):
    """**The poll's ACTOR MATCH** (ADR-0038 decision 8), and nothing else in this file covers it.

    `may_read_project` is True for this caller — they are a member of the same project — and the
    generation is still not theirs. Killed if the poll authorizes on the project verdict alone.

    **Why it matters beyond tidiness:** the actor match is what makes decision 6's claim real
    rather than asserted. `ExplainableRiskAccessDenied` is not a fourth `failure_kind` precisely
    because the only caller who could read a row that terminated on a revoked membership is the
    one the poll refuses — and that argument is worth exactly as much as this assertion.

    The 404's body is the generation-level one. It **echoes the caller's own path id**, on the
    findings routes' and `test_scan_routes.py`'s precedent, so two refusals never carry the same
    literal string — each is the one template filled with that request's id. Comparing the
    templates is what shows a member cannot tell an existing generation from an absent one; a
    literal equality between the two bodies would be asserting the wrong thing.
    """
    await _seed_project(db_session, extra_member=_SECOND_MEMBER)
    await _seed_findings(db_session, _trivy("f-1", "urllib3"))
    accepted = await _post(client, ["f-1"])
    generation_id = accepted.json()["id"]
    await _run_job(fake_provider, generation_id, queue)

    mine = await _poll(client, generation_id)
    theirs = await _poll(client, generation_id, user=_SECOND_MEMBER)
    absent = await _poll(client, "no-such-generation", user=_SECOND_MEMBER)

    assert mine.status_code == 200
    assert theirs.status_code == absent.status_code == 404
    for label, path_id, response in (
        ("another member's", generation_id, theirs),
        ("absent", "no-such-generation", absent),
    ):
        assert response.json() == {
            "detail": f"No brief generation with id '{path_id}' in project '{_PROJECT}'"
        }, label


async def test_a_generation_is_not_readable_through_another_projects_path(
    client, db_session, fake_provider, queue
):
    """**The repository's project scoping**, and the caller is a member of BOTH projects.

    That is the whole difficulty. An earlier version seeded only `_PROJECT`, so both requests
    were refused at `may_read_project` and never reached the repository at all — the mutation
    (deleting `BriefGenerationModel.project_id == project_id` from
    `PostgresBriefGenerationRepository.get`) SURVIVED the whole suite, and the test's stated kill
    was fiction. The guardian found it by applying that mutation.

    Here the owner is a member of `_OTHER_PROJECT` too, so the project gate PASSES and the only
    thing that can refuse is the scoped query. The actor match cannot mask it either: the
    generation is this caller's own.

    The stranger case is kept, and its docstring says what it actually covers: the project gate,
    not the scoping.
    """
    await _seed_project(db_session)
    await _seed_findings(db_session, _trivy("f-1", "urllib3"))
    await PostgresProjectRepository(db_session).add(
        Project(id=_OTHER_PROJECT, owner_id=_OWNER, name="Other", created_at=_AT)
    )
    await PostgresProjectMembershipRepository(db_session).add(
        ProjectMembership(project_id=_OTHER_PROJECT, user_id=_OWNER, role=Role.OWNER)
    )
    await db_session.commit()
    generation_id = (await _post(client, ["f-1"])).json()["id"]

    # The precondition the kill rests on: this caller may read the other project, so the
    # refusal below cannot come from the project verdict.
    assert (await _list(client, project=_OTHER_PROJECT)).status_code == 200

    foreign = await _poll(client, generation_id, project=_OTHER_PROJECT)
    stranger = await _poll(client, generation_id, user=_STRANGER)

    assert foreign.status_code == stranger.status_code == 404
    # Scoped away by the repository, so this is the GENERATION-level sentence.
    assert foreign.json() == {
        "detail": f"No brief generation with id '{generation_id}' in project '{_OTHER_PROJECT}'"
    }
    # Refused by the project verdict, so this is the project-level one.
    assert stranger.json() == {"detail": f"No readable project with id '{_PROJECT}'"}


async def test_the_job_is_enqueued_only_after_the_generation_row_is_committed(
    client, db_session, queue, engine
):
    """ADR-0035 decision 5, through `brief`'s own after-commit wrapper (ADR-0038 decision 3).

    At the moment the job is sent, a SECOND session must already see the row: only a committed
    row is visible to another connection. Kills `get_brief_generation_queue` returning a bare
    `ArqBriefGenerationQueue`, which would enqueue inside `RequestSecurityBriefUseCase` before
    `get_db_session` commits — the second session would then see nothing, every time.

    `test_scan_routes.py`'s `_SpyPool` observation, built locally because only this test needs
    the second session on each enqueue.
    """
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import AsyncSession

    from verion.modules.brief.adapters.outbound.db.models import BriefGenerationModel

    pool, enqueued = queue
    visible: dict[str, bool] = {}

    class _SpyPool:
        async def enqueue_job(self, function, *args, **kwargs):
            generation_id = args[0]
            async with AsyncSession(engine) as second:
                row = await second.execute(
                    select(BriefGenerationModel.id).where(BriefGenerationModel.id == generation_id)
                )
                visible[generation_id] = row.first() is not None
            return await pool.enqueue_job(function, *args, **kwargs)

    app.dependency_overrides[get_arq_pool] = _SpyPool
    await _seed_project(db_session)
    await _seed_findings(db_session, _trivy("f-1", "urllib3"))

    generation_id = (await _post(client, ["f-1"])).json()["id"]
    enqueued.append(generation_id)

    assert visible == {generation_id: True}


# ---------------------------------------------------------------------------
# Failures — ADR-0033 decision 9, remapped onto the poll by ADR-0038 decision 6
#
# **None of these reaches the job through `app.dependency_overrides`.** That rewrites FastAPI's
# request graph, and `generate_brief` has no FastAPI in it: the provider arrives in `ctx`, and
# what `ctx` does not hold is monkeypatched on `worker.py`'s own symbol — commit 1's precedent.
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


async def test_a_provider_failure_is_a_retryable_generation_and_stores_nothing(
    client, db_session, queue
):
    """**A DIFFERENT TEST under a renamed function (M8.6).** There is no 502 any more.

    It used to assert the request answered 502 with a fixed detail. The provider call is in the
    worker now, so the outcome is a terminal `failed` / `provider_unavailable` generation and
    the client's action — retry — is what the kind encodes (ADR-0038 decision 6).

    **Renamed rather than left with the old name**, because the name said `502` and a test whose
    subject changed under an unchanged name is the thing a later reader cannot see.

    **Rule 12 is asserted on both surfaces, and the second is new.** The poll body, as before;
    and the stored row, because a `detail` column would have been the obvious place for a
    provider's message to land. It is derived from the kind and there is no such column.
    """
    await _seed_project(db_session)
    await _seed_findings(db_session, _trivy("f-1", "urllib3"))
    generation_id = (await _post(client, ["f-1"])).json()["id"]

    await _run_job(_EchoingFailingProvider(), generation_id, queue)
    polled = await _poll(client, generation_id)

    assert polled.status_code == 200
    assert polled.json() == {
        "id": generation_id,
        "status": "failed",
        "failure_kind": "provider_unavailable",
        "detail": _RETRYABLE,
        "brief_id": None,
    }
    assert "SENTINEL" not in polled.text
    stored = (
        (
            await db_session.execute(
                text("SELECT * FROM brief_generations WHERE id = :id"), {"id": generation_id}
            )
        )
        .mappings()
        .one()
    )
    assert "SENTINEL" not in str(dict(stored))
    assert (await _list(client)).json()["total"] == 0


async def test_duplicate_or_empty_finding_ids_are_unprocessable(client, db_session, queue):
    """422 from the request schema, before the route body — so the move to a job changes
    nothing here, and no generation is minted either way."""
    await _seed_project(db_session)
    await _seed_findings(db_session, _trivy("f-1", "urllib3"))

    assert (await _post(client, ["f-1", "f-1"])).status_code == 422
    assert (await _post(client, [])).status_code == 422


class _InconsistentRisks:
    """Stands in for `ExplainableRiskPort` to reach the disagreeing-reads case, which nothing
    can produce in production (G11). **This test does NOT exercise the real adapter**; its
    translation is covered by `tests/unit/test_explainable_risk_provider.py`."""

    def __init__(self, _compute=None):
        pass

    async def explainable_risk(self, *, project_id, user_id, finding_ids):
        raise ExplainableRiskInconsistent("Finding 'no-such-finding' is in a candidate Risk")


async def test_disagreeing_reads_are_a_generation_that_must_not_be_retried(
    client, db_session, fake_provider, queue, monkeypatch
):
    """**A DIFFERENT TEST under a renamed function (M8.6).** There is no 500 any more.

    `ExplainableRiskInconsistent` is raised in the worker, so the outcome is `internal_error` —
    the kind that tells the client not to retry, because nothing it does will clear a broken
    server-side invariant.

    **The injection changed too, and it had to.** The old test overrode
    `get_explainable_risk_port`; that dependency is never resolved on this path now. The stand-in
    is patched onto `worker.py`'s `ScoredExplainableRisks`, which is the symbol the job actually
    constructs.
    """
    await _seed_project(db_session)
    await _seed_findings(db_session, _trivy("f-1", "urllib3"))
    generation_id = (await _post(client, ["f-1"])).json()["id"]
    monkeypatch.setattr(worker_module, "ScoredExplainableRisks", _InconsistentRisks)

    await _run_job(fake_provider, generation_id, queue)
    polled = (await _poll(client, generation_id)).json()

    assert polled["status"] == "failed"
    assert polled["failure_kind"] == "internal_error"
    assert polled["detail"] == _NOT_RETRYABLE
    assert polled["brief_id"] is None
    assert "no-such-finding" not in str(polled)


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


async def test_the_list_carries_what_happened_whole(client, db_session, fake_provider, queue):
    """Decision 6: kept on the list, never dropped or truncated, because its inputs are fields
    the findings listing already returns in bulk."""
    await _seed_project(db_session)
    await _seed_findings(db_session, _trivy("f-1", "urllib3"))

    created = await _generate(client, fake_provider, ["f-1"], queue=queue)
    listed = (await _list(client)).json()

    assert listed["items"][0]["what_happened"] == created["what_happened"]
    assert listed["items"][0]["what_happened"]["text"] == "1 findings: trivy title f-1"


async def test_a_brief_written_before_m7_3_lists_with_a_null_what_happened(
    client, db_session, fake_provider, queue
):
    await _seed_project(db_session)
    await _seed_findings(db_session, _trivy("f-1", "urllib3"))
    created = await _generate(client, fake_provider, ["f-1"], queue=queue)
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


async def test_a_rejected_what_happened_is_a_retryable_generation_and_stores_nothing(
    client, db_session, queue
):
    """**A DIFFERENT TEST under a renamed function (M8.6).** There is no 502 any more.

    `WhatHappenedRejected` is `ExplanationUnavailable`'s subclass and lands on the same
    `provider_unavailable` kind, because to a client the two are one outcome: no usable
    narrative and nothing stored (ADR-0034 decision 5, carried into ADR-0038 decision 6).

    **`explain_calls == 0` is the clause that survives untouched** and is the one worth having:
    a rejected `describe` still costs one billed call rather than two.
    """
    await _seed_project(db_session)
    await _seed_findings(db_session, _trivy("f-1", "urllib3"))
    provider = _RejectingProvider()
    generation_id = (await _post(client, ["f-1"])).json()["id"]

    await _run_job(provider, generation_id, queue)
    polled = await _poll(client, generation_id)

    assert polled.json()["status"] == "failed"
    assert polled.json()["failure_kind"] == "provider_unavailable"
    assert polled.json()["detail"] == _RETRYABLE
    assert "fix_now" not in polled.text
    assert provider.explain_calls == 0
    assert (await _list(client)).json()["total"] == 0


class _MemberMissingUseCase:
    """Stands in for the use case to reach `BriefMemberMissing`, which no real read produces
    (nothing deletes a finding). **This test does NOT exercise the real use case**; its raise
    is covered by `tests/unit/test_generate_security_brief.py`."""

    def __init__(self, **_kwargs):
        pass

    async def execute(self, *, project_id, user_id, finding_ids):
        raise BriefMemberMissing("Finding 'MEMBER-SENTINEL' is in a scored Risk")


async def test_a_member_that_cannot_be_read_back_is_a_generation_that_must_not_be_retried(
    client, db_session, fake_provider, queue, monkeypatch
):
    """**A DIFFERENT TEST under a renamed function (M8.6).** There is no 500 any more.

    Same remapping as the disagreeing-reads case, and the same injection change: the old test
    overrode `get_generate_security_brief_use_case`, which no request resolves now, so the
    stand-in is patched onto the symbol `worker.py` constructs.
    """
    await _seed_project(db_session)
    await _seed_findings(db_session, _trivy("f-1", "urllib3"))
    generation_id = (await _post(client, ["f-1"])).json()["id"]
    monkeypatch.setattr(worker_module, "GenerateSecurityBriefUseCase", _MemberMissingUseCase)

    await _run_job(fake_provider, generation_id, queue)
    polled = await _poll(client, generation_id)

    assert polled.json()["status"] == "failed"
    assert polled.json()["failure_kind"] == "internal_error"
    assert polled.json()["detail"] == _NOT_RETRYABLE
    assert "SENTINEL" not in polled.text


# ---------------------------------------------------------------------------
# The two decisions with a cost if they are wrong (ADR-0038 decisions 4 and 7)
#
# Each of these is paired with an applied mutation, recorded in the commit message. A decision
# that is only argued in an ADR is a decision on paper.
# ---------------------------------------------------------------------------


async def test_a_membership_revoked_between_enqueue_and_run_fails_the_generation(
    client, db_session, fake_provider, queue
):
    """**The security decision: the job re-authorizes, and the route's verdict is not inherited.**

    The member POSTs while they may read the project, the membership is deleted, and only then
    does the job run. The route's gate has already passed, so it cannot fire; if the worker does
    not run its own, a Brief is stored for a caller who may no longer read the project.

    **There is ONE verdict in the job's chain, not two, and this test names which.**
    `ScoredExplainableRisks` holds no `ProjectAccessPort` and takes no session; it delegates
    through `ComputeRiskUseCase` and `CorrelationCandidateRisks` to `CorrelateFindingsUseCase`,
    whose `may_read_project` call is the only one, raising `ProjectAccessDenied` and surfacing as
    `ExplainableRiskAccessDenied`. So what the job contributes is **which `user_id` reaches it**,
    and the mutation is on the subject rather than on the call.

    **The mutation, applied and recorded**: `RunBriefGenerationUseCase` passes a hardcoded id
    instead of `generation.user_id`. The verdict still runs and still returns True, so nothing
    raises and the generation succeeds, storing a Brief for a caller who may no longer read the
    project.

    **A SECOND member is seeded, and that is load-bearing rather than scenery.** The first
    version of this test seeded only the requester, and the mutation SURVIVED: with no other
    membership row in the project, every substituted id fails `may_read_project` too, so the
    test went green for the wrong reason and proved nothing. `_SECOND_MEMBER` keeps their
    membership through the revocation, so a substituted id is one the verdict accepts — which is
    what makes this a kill rather than a coincidence.

    **Three assertions identify the link rather than just the outcome**: the row is `failed`;
    the kind is `surface_changed`, which is `ExplainableRiskAccessDenied`'s mapping and not
    `internal_error`'s or `provider_unavailable`'s; and the provider recorded **zero** calls,
    which places the refusal at the verdict rather than at the member reads or the narration.

    `surface_changed` and not a kind naming the denial, because **G17** forbids a response body
    that names one — and the caller who could read this row is the one the poll now refuses,
    which is what makes that unobservable rather than merely unlabelled (ADR-0038 decision 6).
    """
    await _seed_project(
        db_session, member=_PLAIN_MEMBER, role=Role.MEMBER, extra_member=_SECOND_MEMBER
    )
    await _seed_findings(db_session, _trivy("f-1", "urllib3"))

    accepted = await _post(client, ["f-1"], user=_PLAIN_MEMBER)
    assert accepted.status_code == 202, "the route's gate must pass while the membership stands"
    generation_id = accepted.json()["id"]

    await db_session.execute(
        text("DELETE FROM project_memberships WHERE project_id = :p AND user_id = :u"),
        {"p": _PROJECT, "u": _PLAIN_MEMBER},
    )
    await db_session.commit()
    # The precondition the mutation is measured against: somebody in this project CAN still read
    # it, so an id substituted for the stored one would pass the verdict.
    assert (await _list(client, user=_SECOND_MEMBER)).status_code == 200, (
        "the second member must retain access, or the mutation cannot be killed"
    )

    await _run_job(fake_provider, generation_id, queue)

    row = (
        (
            await db_session.execute(
                text("SELECT status, failure_kind, brief_id FROM brief_generations WHERE id = :i"),
                {"i": generation_id},
            )
        )
        .mappings()
        .one()
    )
    assert row["status"] == "failed"
    assert row["failure_kind"] == "surface_changed"
    assert row["brief_id"] is None
    assert fake_provider.calls == []
    assert fake_provider.describe_calls == []
    assert (
        await db_session.execute(text("SELECT count(*) FROM security_briefs"))
    ).scalar_one() == 0
    # And the poll refuses the revoked caller on its own verdict, which is the other half of
    # decision 6's argument.
    assert (await _poll(client, generation_id, user=_PLAIN_MEMBER)).status_code == 404


async def test_a_succeeded_generation_with_no_brief_id_is_refused_by_the_database(db_session):
    """**`ck_brief_generations_outcome_shape`, by raw INSERT past every layer above it.**

    Written rather than inherited (ADR-0038 decision 7): `scans` enforces no such correlation —
    `ScanModel` has no `__table_args__` at all — so its `status`/`failure_reason` pairing is a
    convention, and this table copies the constraint from `ck_scan_results_outcome_shape`
    instead of copying the convention.

    **The mutation, applied and recorded**: the `CheckConstraint` removed from the model and the
    migration, then `alembic downgrade -1 && upgrade head`. Every insert below is then accepted.

    Three shapes, one per branch of the CHECK, because a constraint that only refuses one of
    them would pass a single-case test.
    """
    illegal = (
        ("succeeded with nothing to point at", "succeeded", None, None),
        ("failed with no reason", "failed", None, None),
        ("pending that already has a brief", "pending", "b-1", None),
    )
    for label, status_value, brief_id, failure_kind in illegal:
        with pytest.raises(IntegrityError) as raised:
            await db_session.execute(
                text(
                    "INSERT INTO brief_generations (id, project_id, user_id, finding_ids,"
                    " status, brief_id, failure_kind, requested_at) VALUES (:i, :p, :u,"
                    " ARRAY['f-1'], :s, :b, :k, :at)"
                ),
                {
                    "i": f"g-{status_value}-{brief_id}",
                    "p": _PROJECT,
                    "u": _OWNER,
                    "s": status_value,
                    "b": brief_id,
                    "k": failure_kind,
                    "at": _AT,
                },
            )
        assert "ck_brief_generations_outcome_shape" in str(raised.value), label
        await db_session.rollback()
