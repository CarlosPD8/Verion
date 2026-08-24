"""`GET /projects/{id}/findings` and its evidence route against real Postgres (M4.5).

Three groups here carry more than ordinary coverage:

- **Authorization**, because this is the first project-scoped read outside
  `projects` and the first route that answers 404 where a non-member would
  elsewhere get 403.
- **Rule 12**, which is why the listing and the evidence route are two routes at
  all. `test_a_listing_never_carries_a_finding_s_scanned_payload` is the
  assertion the split exists to make true, and it was mutation-tested by adding
  `raw_payload` to `FindingResponse` and confirming it fails.
- **G9/G10's third consequence.** Both register entries name "M4.5 returns an
  absolute worker filesystem path in a response body". M4.4 fixed the cause; this
  is the effect, checked at the surface that would have shown it.
"""

import json
from datetime import UTC, datetime

import httpx2
import pytest_asyncio
from sqlalchemy import text

from verion.modules.identity.adapters.outbound.security.jwt_issuer import JwtAccessTokenIssuer
from verion.modules.normalization.adapters.outbound.db.repository import (
    PostgresFindingRepository,
    PostgresNormalizationRunRepository,
)
from verion.modules.normalization.domain.finding import (
    MAX_RAW_PAYLOAD_CHARS,
    Evidence,
    Finding,
    FindingSighting,
    Location,
)
from verion.modules.projects.adapters.outbound.db.repository import (
    PostgresProjectMembershipRepository,
    PostgresProjectRepository,
)
from verion.modules.projects.domain.project import Project, ProjectMembership, Role
from verion.platform.app import app
from verion.platform.clock import SystemClock
from verion.platform.settings import get_settings
from verion.shared_kernel.scanner_tools import ScannerTool
from verion.shared_kernel.severity import Severity

_PROJECT = "project-1"
_OTHER_PROJECT = "project-2"
_MEMBER = "user-member"
_STRANGER = "user-stranger"
_SCAN = "scan-1"
_AT = datetime(2026, 1, 1, tzinfo=UTC)


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


def _finding(
    *,
    finding_id: str,
    severity: Severity = Severity.HIGH,
    source: ScannerTool = ScannerTool.SEMGREP,
    rule_id: str | None = None,
    file_path: str = "vulnerable.py",
    raw_payload: str = '{"check_id": "dangerous-eval"}',
    project_id: str = _PROJECT,
) -> Finding:
    """A distinct finding per `finding_id`, and the default is load-bearing.

    `rule_id` defaults to one derived from `finding_id` because `severity` is NOT
    a `dedup_hash` input (ADR-0019 decision 3) — so a helper that pinned `rule_id`
    while varying only `severity` would produce N findings with ONE identity, and
    the upsert would correctly collapse them into a single row carrying whichever
    severity was written last. That is dedup working exactly as designed, and it
    silently turns a five-finding ordering test into a one-row one. Tests that
    want a specific identity pass `rule_id` explicitly.
    """
    return Finding(
        id=finding_id,
        project_id=project_id,
        source=source,
        rule_id=rule_id if rule_id is not None else f"rule-{finding_id}",
        severity=severity,
        native_severity="ERROR",
        title=f"title {finding_id}",
        location=Location(file_path=file_path, start_line=2, end_line=2),
        evidence=Evidence(
            id=f"evidence-{finding_id}",
            finding_id=finding_id,
            scan_id=_SCAN,
            raw_payload=raw_payload,
            source_tool=source,
            captured_at=_AT,
        ),
    )


async def _seed_project(db_session, *, project_id: str = _PROJECT, member: str = _MEMBER) -> None:
    await PostgresProjectRepository(db_session).add(
        Project(id=project_id, owner_id=member, name=f"Project {project_id}", created_at=_AT)
    )
    await PostgresProjectMembershipRepository(db_session).add(
        ProjectMembership(project_id=project_id, user_id=member, role=Role.OWNER)
    )
    await db_session.commit()


async def _seed_finding(
    db_session, finding: Finding, *, scan_id: str = _SCAN, at: datetime = _AT
) -> Finding:
    repository = PostgresFindingRepository(db_session)
    stored = await repository.upsert(finding)
    await repository.record_sighting(
        FindingSighting(finding_id=stored.id, scan_id=scan_id, observed_at=at, match_count=1)
    )
    await db_session.commit()
    return stored


# ---------------------------------------------------------------------------
# Authorization
# ---------------------------------------------------------------------------


async def test_an_unauthenticated_request_is_rejected(client, db_session):
    await _seed_project(db_session)

    response = await client.get(f"/projects/{_PROJECT}/findings")

    # 401 from `HTTPBearer` before the handler runs — the route never sees it, so
    # there is no path on which findings are read without a caller identity.
    assert response.status_code == 401


async def test_a_member_gets_the_project_s_findings(client, db_session):
    await _seed_project(db_session)
    await _seed_finding(db_session, _finding(finding_id="finding-1"))

    response = await client.get(f"/projects/{_PROJECT}/findings", headers=_auth_headers(_MEMBER))

    assert response.status_code == 200
    body = response.json()
    assert [item["id"] for item in body["items"]] == ["finding-1"]
    assert body["total"] == 1


async def test_a_non_member_gets_404_not_403(client, db_session):
    """The divergence from `projects`' routes, asserted rather than assumed.

    A 403 here would confirm the project exists to somebody with no access to it,
    which on a findings endpoint is project enumeration against the most
    sensitive read in the system. `ProjectAccessPort` returns one bool and cannot
    say which reason applied, so this cannot drift back to a 403 without changing
    the port.

    G17 records what this does NOT achieve on its own: `projects`' own routes
    still answer 403, so the same caller can recover existence from a sibling
    route. Converging them is M10.2's.
    """
    await _seed_project(db_session)
    await _seed_finding(db_session, _finding(finding_id="finding-1"))

    response = await client.get(f"/projects/{_PROJECT}/findings", headers=_auth_headers(_STRANGER))

    assert response.status_code == 404


async def test_a_project_that_does_not_exist_is_indistinguishable_from_one_you_cannot_read(
    client, db_session
):
    await _seed_project(db_session)

    absent = await client.get("/projects/no-such-project/findings", headers=_auth_headers(_MEMBER))
    forbidden = await client.get(f"/projects/{_PROJECT}/findings", headers=_auth_headers(_STRANGER))

    assert absent.status_code == forbidden.status_code == 404


# ---------------------------------------------------------------------------
# Rule 12 — the reason the listing and the evidence route are two routes
# ---------------------------------------------------------------------------


async def test_a_listing_never_carries_a_finding_s_scanned_payload(client, db_session):
    """The assertion the split endpoint exists to make true.

    `raw_payload` is a verbatim copy of a scanned source element. The check is
    over the SERIALIZED body rather than over named fields, so it fails for any
    route that adds the payload anywhere — nested, renamed, or inside a new
    object — rather than only for the field shape anticipated here.

    Mutation-tested: adding `raw_payload` to `FindingResponse` and populating it
    fails this test.
    """
    secret = "AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG'"
    await _seed_project(db_session)
    await _seed_finding(
        db_session,
        _finding(finding_id="finding-1", raw_payload=json.dumps({"extra": {"lines": secret}})),
    )

    response = await client.get(f"/projects/{_PROJECT}/findings", headers=_auth_headers(_MEMBER))

    assert response.status_code == 200
    assert secret not in response.text
    assert "raw_payload" not in response.text
    # The metadata that replaces it is present, so a client can decide whether to
    # fetch the payload without being handed it.
    assert response.json()["items"][0]["evidence"]["payload_chars"] > 0


async def test_the_evidence_route_returns_the_payload_verbatim(client, db_session):
    payload = json.dumps({"check_id": "dangerous-eval", "extra": {"lines": "eval(x)"}})
    await _seed_project(db_session)
    await _seed_finding(db_session, _finding(finding_id="finding-1", raw_payload=payload))

    response = await client.get(
        f"/projects/{_PROJECT}/findings/finding-1/evidence", headers=_auth_headers(_MEMBER)
    )

    assert response.status_code == 200
    body = response.json()
    assert body["raw_payload"] == payload
    assert body["payload_truncated"] is False
    assert body["scan_id"] == _SCAN


async def test_a_payload_cut_by_the_character_cap_is_flagged(client, db_session):
    """`raw_payload[:MAX_RAW_PAYLOAD_CHARS]` cuts mid-structure — M4.1's open defect.

    Built at the cap deliberately: the mappers slice, so a real over-long element
    arrives as a prefix of valid JSON. The flag says the payload is INCOMPLETE,
    which is what a client needs to know before parsing it.
    """
    whole = json.dumps({"lines": "x" * (MAX_RAW_PAYLOAD_CHARS * 2)})
    await _seed_project(db_session)
    await _seed_finding(
        db_session, _finding(finding_id="finding-1", raw_payload=whole[:MAX_RAW_PAYLOAD_CHARS])
    )

    response = await client.get(
        f"/projects/{_PROJECT}/findings/finding-1/evidence", headers=_auth_headers(_MEMBER)
    )

    assert response.json()["payload_truncated"] is True


async def test_evidence_for_another_project_s_finding_is_not_reachable(client, db_session):
    """Cross-tenant read of scanned source, refused at the query rather than after it."""
    await _seed_project(db_session)
    await _seed_project(db_session, project_id=_OTHER_PROJECT, member=_STRANGER)
    await _seed_finding(db_session, _finding(finding_id="theirs", project_id=_OTHER_PROJECT))

    response = await client.get(
        f"/projects/{_PROJECT}/findings/theirs/evidence", headers=_auth_headers(_MEMBER)
    )

    assert response.status_code == 404


# ---------------------------------------------------------------------------
# Filtering, ordering, paging
# ---------------------------------------------------------------------------


async def test_findings_come_back_most_severe_first(client, db_session):
    await _seed_project(db_session)
    for member in Severity:
        await _seed_finding(db_session, _finding(finding_id=str(member), severity=member))

    response = await client.get(
        f"/projects/{_PROJECT}/findings?limit=100", headers=_auth_headers(_MEMBER)
    )

    expected = [str(m) for m in sorted(Severity, key=lambda m: m.rank, reverse=True)]
    assert [item["severity"] for item in response.json()["items"]] == expected


async def test_min_severity_filters_by_rank_and_drops_unknown(client, db_session):
    await _seed_project(db_session)
    await _seed_finding(db_session, _finding(finding_id="high", severity=Severity.HIGH))
    await _seed_finding(db_session, _finding(finding_id="low", severity=Severity.LOW))
    await _seed_finding(db_session, _finding(finding_id="unknown", severity=Severity.UNKNOWN))

    filtered = await client.get(
        f"/projects/{_PROJECT}/findings?min_severity=low", headers=_auth_headers(_MEMBER)
    )
    assert {item["id"] for item in filtered.json()["items"]} == {"high", "low"}
    assert filtered.json()["total"] == 2

    everything = await client.get(
        f"/projects/{_PROJECT}/findings?min_severity=unknown", headers=_auth_headers(_MEMBER)
    )
    assert everything.json()["total"] == 3


async def test_an_unknown_severity_is_rejected_with_the_alternatives_named(client, db_session):
    await _seed_project(db_session)

    response = await client.get(
        f"/projects/{_PROJECT}/findings?min_severity=urgent", headers=_auth_headers(_MEMBER)
    )

    assert response.status_code == 422
    assert "critical" in response.json()["detail"]


async def test_severity_coercion_is_case_sensitive(client, db_session):
    """One canonical spelling, so a client cannot half-work against a second one."""
    await _seed_project(db_session)

    response = await client.get(
        f"/projects/{_PROJECT}/findings?min_severity=HIGH", headers=_auth_headers(_MEMBER)
    )

    assert response.status_code == 422


async def test_source_filters_by_tool_and_rejects_an_unknown_one(client, db_session):
    await _seed_project(db_session)
    await _seed_finding(db_session, _finding(finding_id="s", source=ScannerTool.SEMGREP))
    await _seed_finding(
        db_session,
        _finding(finding_id="t", source=ScannerTool.TRIVY, rule_id="CVE-2019-11324"),
    )

    filtered = await client.get(
        f"/projects/{_PROJECT}/findings?source=trivy", headers=_auth_headers(_MEMBER)
    )
    assert [item["id"] for item in filtered.json()["items"]] == ["t"]

    rejected = await client.get(
        f"/projects/{_PROJECT}/findings?source=nessus", headers=_auth_headers(_MEMBER)
    )
    assert rejected.status_code == 422


async def test_paging_bounds_are_enforced(client, db_session):
    await _seed_project(db_session)

    for query in ("limit=0", "limit=201", "offset=-1"):
        response = await client.get(
            f"/projects/{_PROJECT}/findings?{query}", headers=_auth_headers(_MEMBER)
        )
        assert response.status_code == 422, query


async def test_total_counts_the_filtered_set_not_the_page(client, db_session):
    await _seed_project(db_session)
    for index in range(5):
        await _seed_finding(db_session, _finding(finding_id=f"finding-{index}"))

    response = await client.get(
        f"/projects/{_PROJECT}/findings?limit=2&offset=2", headers=_auth_headers(_MEMBER)
    )

    body = response.json()
    assert len(body["items"]) == 2
    assert body["total"] == 5
    assert (body["limit"], body["offset"]) == (2, 2)


# ---------------------------------------------------------------------------
# Sightings — derived per request (ADR-0019 decision 1)
# ---------------------------------------------------------------------------


async def test_a_finding_seen_in_two_scans_reports_both_ends_of_its_history(client, db_session):
    await _seed_project(db_session)
    finding = _finding(finding_id="finding-1")
    await _seed_finding(db_session, finding, scan_id="scan-1", at=_AT)
    await _seed_finding(db_session, finding, scan_id="scan-2", at=datetime(2026, 3, 1, tzinfo=UTC))

    response = await client.get(f"/projects/{_PROJECT}/findings", headers=_auth_headers(_MEMBER))

    [item] = response.json()["items"]
    assert item["sighting_count"] == 2
    assert item["last_seen_scan_id"] == "scan-2"
    assert item["first_seen_at"].startswith("2026-01-01")
    assert item["last_seen_at"].startswith("2026-03-01")


async def test_nothing_in_the_response_claims_a_finding_is_resolved(client, db_session):
    """M4.5 exposes WHEN a finding was last seen and never WHETHER it is resolved.

    Turning the first into the second needs the succeeded-tools scoping ADR-0019's
    Consequences requires; without it, one failed Trivy run silently resolves
    every dependency finding in a project. That is M9.1's, and this asserts M4.5
    did not quietly ship half of it.
    """
    await _seed_project(db_session)
    await _seed_finding(db_session, _finding(finding_id="finding-1"))

    response = await client.get(f"/projects/{_PROJECT}/findings", headers=_auth_headers(_MEMBER))

    for forbidden in ("resolved", "is_open", "status"):
        assert forbidden not in response.json()["items"][0]


# ---------------------------------------------------------------------------
# What the response says about its own completeness (G15)
# ---------------------------------------------------------------------------


async def test_a_failed_normalization_is_visible_in_the_envelope(client, db_session):
    """The half of G15 this issue closes: `failure_reason` reaches a human.

    Until now it was reachable only by querying Postgres by hand. It is safe to
    return because M4.4 made the transient branch persist the exception TYPE only,
    and the assertion that pins that is `test_normalize_scan.py`'s, in this
    repository but not in this file. This test asserts only the round trip:
    whatever was written comes back.
    """
    await _seed_project(db_session)
    runs = PostgresNormalizationRunRepository(db_session)
    await runs.request(id="run-1", scan_id=_SCAN, project_id=_PROJECT, requested_at=_AT)
    run = await runs.get_by_scan_id(_SCAN)
    assert run is not None
    await runs.update(run.start(_AT).fail(_AT, "Normalization failed with OSError."))
    await db_session.commit()

    response = await client.get(f"/projects/{_PROJECT}/findings", headers=_auth_headers(_MEMBER))

    state = response.json()["normalization"]
    assert state["unfinished_runs"] == 1
    assert state["latest_run"]["status"] == "failed"
    assert state["latest_run"]["failure_reason"] == "Normalization failed with OSError."


async def test_an_empty_project_and_a_broken_one_are_distinguishable(client, db_session):
    """Two empty lists that must not read the same.

    Without `unfinished_runs`, a project whose scans never normalized returns
    exactly what a clean project returns — G15's own words. This is that
    difference, asserted at the surface where a human would meet it.
    """
    await _seed_project(db_session)

    clean = (
        await client.get(f"/projects/{_PROJECT}/findings", headers=_auth_headers(_MEMBER))
    ).json()
    assert clean["total"] == 0
    assert clean["normalization"] == {"latest_run": None, "unfinished_runs": 0}

    runs = PostgresNormalizationRunRepository(db_session)
    await runs.request(id="run-1", scan_id=_SCAN, project_id=_PROJECT, requested_at=_AT)
    await db_session.commit()

    broken = (
        await client.get(f"/projects/{_PROJECT}/findings", headers=_auth_headers(_MEMBER))
    ).json()
    assert broken["total"] == 0
    assert broken["normalization"]["unfinished_runs"] == 1


async def test_a_completed_latest_run_does_not_hide_an_earlier_failure(client, db_session):
    await _seed_project(db_session)
    runs = PostgresNormalizationRunRepository(db_session)

    await runs.request(id="run-old", scan_id="scan-old", project_id=_PROJECT, requested_at=_AT)
    old = await runs.get_by_scan_id("scan-old")
    assert old is not None
    await runs.update(old.start(_AT).fail(_AT, "Normalization failed with OSError."))

    later = datetime(2026, 6, 1, tzinfo=UTC)
    await runs.request(id="run-new", scan_id="scan-new", project_id=_PROJECT, requested_at=later)
    new = await runs.get_by_scan_id("scan-new")
    assert new is not None
    await runs.update(new.start(later).complete(later))
    await db_session.commit()

    state = (
        await client.get(f"/projects/{_PROJECT}/findings", headers=_auth_headers(_MEMBER))
    ).json()["normalization"]

    assert state["latest_run"]["status"] == "completed"
    assert state["unfinished_runs"] == 1


async def test_another_project_s_runs_are_not_counted(client, db_session):
    await _seed_project(db_session)
    await _seed_project(db_session, project_id=_OTHER_PROJECT, member=_STRANGER)
    runs = PostgresNormalizationRunRepository(db_session)
    await runs.request(
        id="run-other", scan_id="scan-other", project_id=_OTHER_PROJECT, requested_at=_AT
    )
    await db_session.commit()

    state = (
        await client.get(f"/projects/{_PROJECT}/findings", headers=_auth_headers(_MEMBER))
    ).json()["normalization"]

    assert state == {"latest_run": None, "unfinished_runs": 0}


# ---------------------------------------------------------------------------
# G9 / G10's third consequence, closed at the surface that would have shown it
# ---------------------------------------------------------------------------


async def test_no_response_field_carries_an_absolute_worker_path(client, db_session):
    """G9 and G10 both name this endpoint as where their defect would surface.

    Before M4.4, `rule_id` was the ruleset path relative to the worker's CWD
    (`C.Users.…Verion.src.…dangerous-eval` from outside the repo) and
    `location.file_path` was an absolute `mkdtemp` path. Both were `dedup_hash`
    inputs, and both would have been returned here verbatim.

    The seeded values are the post-fix shapes `test_semgrep_adapter.py` pins
    against the real binary, so this asserts the CONSEQUENCE rather than
    re-measuring the cause: whatever those fields hold must not look like a
    filesystem path from the machine that ran the scan.
    """
    await _seed_project(db_session)
    await _seed_finding(
        db_session,
        _finding(finding_id="finding-1", rule_id="dangerous-eval", file_path="vulnerable.py"),
    )

    body = (
        await client.get(f"/projects/{_PROJECT}/findings", headers=_auth_headers(_MEMBER))
    ).json()
    item = body["items"][0]

    for field in (item["rule_id"], item["location"]["file_path"]):
        assert not field.startswith("/")
        assert not field.startswith("C.Users")
        assert ":\\" not in field
        assert "verion-scan-" not in field


async def test_the_dedup_hash_is_never_a_field_of_a_finding(client, db_session):
    """Internal identity with a version prefix, deliberately not a response FIELD.

    A client keying on it would make a `DEDUP_HASH_VERSION` bump — already a
    re-normalization (ADR-0019 decision 6) — a breaking API change on top of one.

    **Named "never a field" rather than "never exposed", because the second would
    be false and this test could not have caught that.** It seeds a healthy
    project, so it never visits the one branch that does put a hash in a
    response — see the next test, which does.
    """
    await _seed_project(db_session)
    stored = await _seed_finding(db_session, _finding(finding_id="finding-1"))

    response = await client.get(f"/projects/{_PROJECT}/findings", headers=_auth_headers(_MEMBER))

    assert "dedup_hash" not in response.text
    assert stored.dedup_hash not in response.text


async def test_a_skipped_group_s_hash_does_reach_the_response_via_failure_reason(
    client, db_session
):
    """The exception to the test above, asserted rather than left implicit.

    When `collapse_by_identity` rejects a group, `NormalizeScanUseCase` records
    the skipped groups' `dedup_hash` values in `failure_reason` — deliberately,
    because that identifier is how a person finds which groups were dropped — and
    this endpoint returns that field. So "dedup_hash is never exposed" is false as
    a blanket claim, and the true one is "never as a field of a finding".

    Pinned because the distinction is easy to lose in either direction: a future
    reader tightening the previous test into a whole-response ban would break this
    diagnostic, and a future reader adding `dedup_hash` to `FindingResponse` could
    point at this test as precedent. They are different claims and both are here.
    """
    await _seed_project(db_session)
    runs = PostgresNormalizationRunRepository(db_session)
    await runs.request(id="run-1", scan_id=_SCAN, project_id=_PROJECT, requested_at=_AT)
    run = await runs.get_by_scan_id(_SCAN)
    assert run is not None
    await runs.update(run.start(_AT).fail(_AT, "1 finding group(s) … dedup_hash: v1:abc123"))
    await db_session.commit()

    response = await client.get(f"/projects/{_PROJECT}/findings", headers=_auth_headers(_MEMBER))

    assert "v1:abc123" in response.json()["normalization"]["latest_run"]["failure_reason"]
    # And still not as a field on any finding, which is the property that holds.
    for item in response.json()["items"]:
        assert "dedup_hash" not in item


# ---------------------------------------------------------------------------
# The index this issue ships is actually used
# ---------------------------------------------------------------------------


async def test_the_project_scoped_run_lookup_uses_its_index(db_session):
    """`ix_normalization_runs_project_id` serves the query it shipped with.

    ADR-0017's rule is that an index ships in the migration carrying its query.
    The converse — that the query actually reaches the index — is what this
    checks, because an index nothing uses is the same cost with none of the
    benefit and nothing else would notice.

    Postgres will prefer a seq scan on a tiny table however good the index is, so
    `enable_seqscan` is turned off for this statement: the question here is
    whether the planner CAN use it, which is a property of the index and the
    query, not of the row count.
    """
    runs = PostgresNormalizationRunRepository(db_session)
    await runs.request(id="run-1", scan_id=_SCAN, project_id=_PROJECT, requested_at=_AT)
    await db_session.flush()

    await db_session.execute(text("SET LOCAL enable_seqscan = off"))
    plan = await db_session.execute(
        text(
            "EXPLAIN SELECT * FROM normalization_runs WHERE project_id = :p "
            "ORDER BY requested_at DESC, id DESC LIMIT 1"
        ),
        {"p": _PROJECT},
    )

    assert "ix_normalization_runs_project_id" in "\n".join(row[0] for row in plan)
