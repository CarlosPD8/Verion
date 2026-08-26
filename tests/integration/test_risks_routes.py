"""`GET /projects/{id}/risks` end to end, against real Postgres.

**The eight negative-claim tests are the point of this file**, not its authorization cases.
ADR-0025 decision 5 lists what this response deliberately does not claim. **All four of
`test_findings_routes.py`'s have counterparts here**, written to their counterparts' shape so
the pair reads as one habit rather than two inventions — including the `dedup_hash` pair, whose
second half asserts the one path that DOES put a hash in this body. An earlier draft shipped
five and justified the two omissions with a claim about this response that was false; that is
recorded in ADR-0025 decision 5 rather than only here.

Every one of the eight anchors on a non-empty body, so a regression that empties `items` turns
them red rather than green.

Helpers are module-local, following `test_findings_routes.py` — `tests/` is not a package,
so importing across test modules is not available and duplication is the convention here.
"""

from datetime import UTC, datetime

import httpx2
import pytest_asyncio

from verion.modules.identity.adapters.outbound.security.jwt_issuer import JwtAccessTokenIssuer
from verion.modules.normalization.adapters.outbound.db.repository import (
    PostgresFindingRepository,
    PostgresNormalizationRunRepository,
)
from verion.modules.normalization.domain.finding import Evidence, Finding, Location
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


def _trivy_finding(
    *,
    finding_id: str,
    package: str,
    severity: Severity = Severity.HIGH,
    raw_payload: str = '{"VulnerabilityID": "CVE-0000-0000"}',
    project_id: str = _PROJECT,
) -> Finding:
    """A Trivy-shaped finding, which is the shape that carries a `package` signal.

    `rule_id` derives from `finding_id` for the reason `test_findings_routes.py`'s helper
    gives: severity is not a `dedup_hash` input, so a pinned `rule_id` would collapse
    several findings into one row.
    """
    return Finding(
        id=finding_id,
        project_id=project_id,
        source=ScannerTool.TRIVY,
        rule_id=f"rule-{finding_id}",
        severity=severity,
        native_severity="HIGH",
        title=f"title {finding_id}",
        location=Location(file_path="requirements.txt", package=package, installed_version="1.0"),
        evidence=Evidence(
            id=f"evidence-{finding_id}",
            finding_id=finding_id,
            scan_id=_SCAN,
            raw_payload=raw_payload,
            source_tool=ScannerTool.TRIVY,
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


async def _seed_finding(db_session, finding: Finding) -> Finding:
    """No sighting written, deliberately.

    Correlation reads `get_by_project_id`, which does not require the sighting invariant —
    see that port method's docstring. Seeding one anyway would hide a dependency on the
    read path's join if this route ever grew one.
    """
    stored = await PostgresFindingRepository(db_session).upsert(finding)
    await db_session.commit()
    return stored


# ---------------------------------------------------------------------------
# Authorization — ADR-0022 decision 2, inherited
# ---------------------------------------------------------------------------


async def test_an_unauthenticated_request_is_rejected(client, db_session):
    await _seed_project(db_session)

    response = await client.get(f"/projects/{_PROJECT}/risks")

    assert response.status_code == 401


async def test_a_member_gets_the_project_s_risks(client, db_session):
    await _seed_project(db_session)
    for finding_id, package in (("f-1", "urllib3"), ("f-2", "urllib3"), ("f-3", "flask")):
        await _seed_finding(db_session, _trivy_finding(finding_id=finding_id, package=package))

    response = await client.get(f"/projects/{_PROJECT}/risks", headers=_auth_headers(_MEMBER))

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == len(body["items"]) == 2
    by_package = {item["match"]["package"]: item for item in body["items"]}
    assert by_package.keys() == {"urllib3", "flask"}
    # Three findings, two Risks: the grouping is what this route exists to show.
    assert by_package["urllib3"]["finding_count"] == 2
    assert sorted(by_package["urllib3"]["finding_ids"]) == ["f-1", "f-2"]


async def test_a_non_member_and_an_absent_project_are_indistinguishable(client, db_session):
    """Both 404, with no vocabulary for which — `ProjectAccessPort` returns one bool."""
    await _seed_project(db_session)

    forbidden = await client.get(f"/projects/{_PROJECT}/risks", headers=_auth_headers(_STRANGER))
    absent = await client.get(f"/projects/{_OTHER_PROJECT}/risks", headers=_auth_headers(_MEMBER))

    assert forbidden.status_code == absent.status_code == 404


# ---------------------------------------------------------------------------
# What the response deliberately does NOT claim — ADR-0025 decision 5
# ---------------------------------------------------------------------------


async def test_a_risk_listing_never_carries_a_finding_s_scanned_payload(client, db_session):
    """Counterpart of `test_findings_routes.py`'s, written to its shape.

    Checked over the SERIALIZED body rather than named fields, so it fails for any future
    route that adds the payload anywhere — nested, renamed, or inside a new object. A Risk
    correlating N findings is the bulk shape ADR-0022 decision 1 refused, worse.

    Mutation-tested: adding a payload field to `RiskResponse` and populating it fails here.
    """
    secret = "AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG'"
    await _seed_project(db_session)
    await _seed_finding(
        db_session,
        _trivy_finding(finding_id="f-1", package="urllib3", raw_payload=f'{{"lines": "{secret}"}}'),
    )

    response = await client.get(f"/projects/{_PROJECT}/risks", headers=_auth_headers(_MEMBER))

    assert response.status_code == 200
    assert secret not in response.text
    assert "raw_payload" not in response.text
    # The positive anchor its counterpart has, so the two absences above are asserted about a
    # NON-EMPTY body. Without it a regression that emptied `items` would turn this green.
    assert response.json()["items"][0]["finding_count"] == 1


async def test_nothing_in_the_response_claims_a_risk_is_resolved(client, db_session):
    """Counterpart of `test_nothing_in_the_response_claims_a_finding_is_resolved`.

    Item-scoped for the same reason that one is: the envelope legitimately carries
    `normalization.latest_run.status`, so a whole-body ban would forbid a field this
    response is required to have. M9.1 owns resolution and M8.1 the lifecycle.
    """
    await _seed_project(db_session)
    await _seed_finding(db_session, _trivy_finding(finding_id="f-1", package="urllib3"))

    response = await client.get(f"/projects/{_PROJECT}/risks", headers=_auth_headers(_MEMBER))

    for forbidden in ("resolved", "is_open", "status"):
        assert forbidden not in response.json()["items"][0]


async def test_a_risk_carries_no_score_and_no_priority(client, db_session):
    """M5.2's Risk is a candidate. Scoring is M6 and this route must not imply it exists."""
    await _seed_project(db_session)
    await _seed_finding(db_session, _trivy_finding(finding_id="f-1", package="urllib3"))

    response = await client.get(f"/projects/{_PROJECT}/risks", headers=_auth_headers(_MEMBER))

    item = response.json()["items"][0]
    for forbidden in ("priority", "confidence", "reasoning", "score"):
        assert forbidden not in item


async def test_a_risk_carries_no_id(client, db_session):
    """The one with no M4.5 counterpart, and the one decision 1 makes necessary.

    A candidate Risk is not stored and has no stable referent. Without this assertion a
    later reader adds a surrogate and the response starts implying one.
    """
    await _seed_project(db_session)
    await _seed_finding(db_session, _trivy_finding(finding_id="f-1", package="urllib3"))

    response = await client.get(f"/projects/{_PROJECT}/risks", headers=_auth_headers(_MEMBER))

    item = response.json()["items"][0]
    assert "id" not in item
    assert "risk_id" not in item


async def test_the_item_order_is_not_a_priority_order(client, db_session):
    """Deterministic is not the same as ranked, and the two are seeded to disagree here."""
    await _seed_project(db_session)
    await _seed_finding(
        db_session, _trivy_finding(finding_id="f-1", package="zzz", severity=Severity.CRITICAL)
    )
    await _seed_finding(
        db_session, _trivy_finding(finding_id="f-2", package="aaa", severity=Severity.LOW)
    )

    response = await client.get(f"/projects/{_PROJECT}/risks", headers=_auth_headers(_MEMBER))

    assert [item["match"]["package"] for item in response.json()["items"]] == ["aaa", "zzz"]


async def test_the_dedup_hash_is_never_a_field_of_a_risk(client, db_session):
    """Counterpart of `test_the_dedup_hash_is_never_a_field_of_a_finding`, and named its way.

    **"Never a field of a Risk", not "never exposed"** — the second would be false, and the
    next test is the path that makes it false. A client keying on a hash would turn a
    `DEDUP_HASH_VERSION` bump, already a re-normalization, into a breaking API change on top
    of one. This test seeds a healthy project, so it never visits that path.
    """
    await _seed_project(db_session)
    stored = await _seed_finding(db_session, _trivy_finding(finding_id="f-1", package="urllib3"))

    response = await client.get(f"/projects/{_PROJECT}/risks", headers=_auth_headers(_MEMBER))

    assert response.json()["items"][0]["finding_count"] == 1
    assert "dedup_hash" not in response.text
    assert stored.dedup_hash not in response.text


async def test_a_skipped_group_s_hash_does_reach_the_response_via_failure_reason(
    client, db_session
):
    """The exception to the test above, asserted rather than left implicit.

    `NormalizeScanUseCase` records skipped groups' `dedup_hash` values in `failure_reason`,
    and this route returns that field verbatim in its envelope. So "no `dedup_hash`" is true
    of a Risk's fields and false of the body, exactly as on the findings route.

    Pinned because the distinction is losable in both directions: a future reader tightening
    the previous test into a whole-body ban would break this diagnostic, and a future reader
    adding `dedup_hash` to `RiskResponse` could point at this test as precedent.

    **A finding is seeded even though the subject is the envelope**, so that the closing loop
    over `items` iterates something. Without it that half is vacuous — a guard asserting
    nothing, in the file whose subject is guards that assert nothing.
    """
    await _seed_project(db_session)
    await _seed_finding(db_session, _trivy_finding(finding_id="f-1", package="urllib3"))
    runs = PostgresNormalizationRunRepository(db_session)
    await runs.request(id="run-1", scan_id=_SCAN, project_id=_PROJECT, requested_at=_AT)
    run = await runs.get_by_scan_id(_SCAN)
    assert run is not None
    await runs.update(run.start(_AT).fail(_AT, "1 finding group(s) … dedup_hash: v1:abc123"))
    await db_session.commit()

    response = await client.get(f"/projects/{_PROJECT}/risks", headers=_auth_headers(_MEMBER))

    assert "v1:abc123" in response.json()["normalization"]["latest_run"]["failure_reason"]
    # And still not as a field on any Risk, which is the property that holds. Non-vacuous
    # because a finding was seeded above: this loop runs.
    assert response.json()["items"][0]["finding_count"] == 1
    for item in response.json()["items"]:
        assert "dedup_hash" not in item


async def test_no_response_field_carries_an_absolute_worker_path(client, db_session):
    """Counterpart of the findings route's, and it asserts the CONSEQUENCE, as that one does.

    G9 and G10 record that Semgrep's invocation could put an absolute worker path into a
    finding's `rule_id` and `location.file_path`; M4.4 closed it with `cwd=target` and
    `--no-rewrite-rule-ids`. This checks the surface that would have shown it — no response
    field carries such a path — rather than re-measuring the cause.

    **What it does not do**, said because the seeding makes it easy to over-read: it does not
    prove a future `MatchKeyResponse` field would be caught. Nothing seeded here contains a
    absolute worker path — `requirements.txt` is seeded and is neither — so a new field
    carrying one would need its own case with data that has one.
    """
    await _seed_project(db_session)
    await _seed_finding(db_session, _trivy_finding(finding_id="f-1", package="urllib3"))

    response = await client.get(f"/projects/{_PROJECT}/risks", headers=_auth_headers(_MEMBER))

    assert response.json()["items"][0]["finding_count"] == 1
    # Over the whole body rather than named fields, because the fields that would carry a path
    # are absent — so there is nothing to enumerate and a body-wide check is the honest form.
    assert ":\\" not in response.text
    assert "verion-scan-" not in response.text


# ---------------------------------------------------------------------------
# The completeness envelope (G15)
# ---------------------------------------------------------------------------


async def test_an_empty_project_and_a_broken_one_are_distinguishable(client, db_session):
    """The same difference `test_findings_routes.py` asserts, one layer up.

    A Risk is only as complete as the findings it correlated, so a project whose scans never
    normalized returns an empty Risk list that would otherwise read as a clean project.
    """
    await _seed_project(db_session)

    clean = (await client.get(f"/projects/{_PROJECT}/risks", headers=_auth_headers(_MEMBER))).json()
    assert clean["total"] == 0
    assert clean["normalization"] == {"latest_run": None, "unfinished_runs": 0}

    runs = PostgresNormalizationRunRepository(db_session)
    await runs.request(id="run-1", scan_id=_SCAN, project_id=_PROJECT, requested_at=_AT)
    await db_session.commit()

    broken = (
        await client.get(f"/projects/{_PROJECT}/risks", headers=_auth_headers(_MEMBER))
    ).json()
    assert broken["total"] == 0
    assert broken["normalization"]["unfinished_runs"] == 1


async def test_the_envelope_reports_a_failed_run_with_its_reason(client, db_session):
    await _seed_project(db_session)
    runs = PostgresNormalizationRunRepository(db_session)
    await runs.request(id="run-1", scan_id=_SCAN, project_id=_PROJECT, requested_at=_AT)
    run = await runs.get_by_scan_id(_SCAN)
    assert run is not None
    await runs.update(run.start(_AT).fail(_AT, "Normalization failed with OSError."))
    await db_session.commit()

    state = (
        await client.get(f"/projects/{_PROJECT}/risks", headers=_auth_headers(_MEMBER))
    ).json()["normalization"]

    assert state["latest_run"]["status"] == "failed"
    assert state["latest_run"]["failure_reason"] == "Normalization failed with OSError."
    assert state["unfinished_runs"] == 1
