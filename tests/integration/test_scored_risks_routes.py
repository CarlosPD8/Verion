"""`GET /projects/{id}/scored-risks` end to end, against real Postgres.

Three things here are the point of the file:

- **The key-set equality assertion.** ADR-0030 decision 3 enumerates what an item carries,
  and **G66**'s claim that this response is a strict superset of `RiskResponse` is true only
  while that enumeration ships. Absence tests constrain what must not appear and say nothing
  about what must, so an equality assertion is what binds the decision.
- **The real adapter, exercised through real wiring** (**G65**). These tests override neither
  `get_candidate_risk_port` nor `get_compute_risk_use_case`, so `CorrelationCandidateRisks`
  is genuinely constructed; the denial case is the one whose mutation survived 923 tests at
  M6.2, and it is covered here on purpose.
- **G64 at the surface**: a `CRITICAL` package item comes back `plan`, which is the first
  time that closure is shown to anyone rather than asserted in a unit test.

Findings are hand-written here, following `test_findings_routes.py` and
`test_risks_routes.py`: a route test seeds rows, and running mappers is the unit suite's job.

Helpers are module-local — `tests/` is not a package, so duplication is the convention here.
"""

from datetime import UTC, datetime

import httpx2
import pytest_asyncio

from verion.modules.correlation.ports.candidate_risk import (
    CONFIDENCE_DEFINITION,
    CandidateRiskAccessDenied,
)
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
from verion.modules.risk_engine.domain.scoring import FIX_NOW_AT, PLAN_AT
from verion.platform.app import app
from verion.platform.clock import SystemClock
from verion.platform.di import get_candidate_risk_port
from verion.platform.settings import get_settings
from verion.shared_kernel.confidence import Confidence
from verion.shared_kernel.scanner_tools import ScannerTool
from verion.shared_kernel.severity import Severity

_PROJECT = "project-1"
_OTHER_PROJECT = "project-2"
_MEMBER = "user-member"
_STRANGER = "user-stranger"
_SCAN = "scan-1"
_AT = datetime(2026, 1, 1, tzinfo=UTC)

_ITEM_KEYS = {
    "match",
    "finding_ids",
    "finding_count",
    "priority_score",
    "priority",
    "reasoning",
    "confidence",
}
# ADR-0030 decision 3's enumeration for the ENVELOPE, binding since its M8.5 amendment.
_ENVELOPE_KEYS = {
    "items",
    "total",
    "limit",
    "offset",
    "thresholds",
    "confidence_definition",
    "normalization",
}
_SIGNAL_KEYS = {"name", "value", "produced_by", "note"}


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
) -> Finding:
    """A Trivy-shaped finding — the shape that carries a `package` signal.

    `rule_id` derives from `finding_id` for the reason `test_risks_routes.py`'s helper
    gives: severity is not a `dedup_hash` input, so a pinned `rule_id` would collapse
    several findings into one row.
    """
    return Finding(
        id=finding_id,
        project_id=_PROJECT,
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
    stored = await PostgresFindingRepository(db_session).upsert(finding)
    await db_session.commit()
    return stored


# ---------------------------------------------------------------------------
# Authorization — ADR-0022 decision 2, inherited indirectly through CandidateRiskPort
# ---------------------------------------------------------------------------


async def test_an_unauthenticated_request_is_rejected(client, db_session):
    await _seed_project(db_session)

    response = await client.get(f"/projects/{_PROJECT}/scored-risks")

    assert response.status_code == 401


async def test_a_member_gets_the_project_s_scored_risks(client, db_session):
    """The happy path through the REAL `CorrelationCandidateRisks` — **G65**.

    Nothing here overrides `get_candidate_risk_port`, so the adapter whose translation could
    be deleted with 923 tests still green is genuinely constructed and exercised.
    """
    await _seed_project(db_session)
    for finding_id, package in (("f-1", "urllib3"), ("f-2", "urllib3"), ("f-3", "flask")):
        await _seed_finding(db_session, _trivy_finding(finding_id=finding_id, package=package))

    response = await client.get(
        f"/projects/{_PROJECT}/scored-risks", headers=_auth_headers(_MEMBER)
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == len(body["items"]) == 2
    by_package = {item["match"]["package"]: item for item in body["items"]}
    assert by_package.keys() == {"urllib3", "flask"}
    assert by_package["urllib3"]["finding_count"] == 2
    assert sorted(by_package["urllib3"]["finding_ids"]) == ["f-1", "f-2"]


async def test_a_non_member_and_an_absent_project_are_indistinguishable(client, db_session):
    """Both 404 — and through the REAL adapter, which is the half **G65** is about.

    `CorrelateFindingsUseCase` raises `correlation`'s own `ProjectAccessDenied`;
    `CorrelationCandidateRisks` translates it to `CandidateRiskAccessDenied`, which this
    route catches by that exact type. Delete the translation and the domain exception escapes
    uncaught and this returns 500, so this assertion is what kills that mutation.
    """
    await _seed_project(db_session)

    forbidden = await client.get(
        f"/projects/{_PROJECT}/scored-risks", headers=_auth_headers(_STRANGER)
    )
    absent = await client.get(
        f"/projects/{_OTHER_PROJECT}/scored-risks", headers=_auth_headers(_MEMBER)
    )

    assert forbidden.status_code == absent.status_code == 404


# ---------------------------------------------------------------------------
# The response shape — ADR-0030 decision 3, and it is BINDING
# ---------------------------------------------------------------------------


async def test_an_items_key_set_equals_the_decisions_enumeration_exactly(client, db_session):
    """**The assertion that binds ADR-0030 decision 3, and with it G66.**

    Equality, not containment: an extra field and a missing field are both red. Without it
    the enumeration is prose, and decision 3 and **G66** could go false together with every
    gate green — G66's superset claim holds only while `match` and `finding_count` ship.
    """
    await _seed_project(db_session)
    await _seed_finding(db_session, _trivy_finding(finding_id="f-1", package="urllib3"))

    response = await client.get(
        f"/projects/{_PROJECT}/scored-risks", headers=_auth_headers(_MEMBER)
    )

    item = response.json()["items"][0]
    assert set(item) == _ITEM_KEYS
    assert set(item["match"]) == {"package", "url"}
    assert set(item["reasoning"]) == {"severity", "exposure", "corroboration"}
    for signal in item["reasoning"].values():
        assert set(signal) == _SIGNAL_KEYS


async def test_the_bucket_is_re_derivable_from_the_response_alone(client, db_session):
    """Rule 5 at the surface: the signals sum to the score, and the envelope says the
    boundaries, so a reader can check the bucket by hand without reading `scoring.py`."""
    await _seed_project(db_session)
    await _seed_finding(db_session, _trivy_finding(finding_id="f-1", package="urllib3"))

    body = (
        await client.get(f"/projects/{_PROJECT}/scored-risks", headers=_auth_headers(_MEMBER))
    ).json()

    item = body["items"][0]
    assert sum(signal["value"] for signal in item["reasoning"].values()) == item["priority_score"]
    thresholds = body["thresholds"]
    expected = (
        "fix_now"
        if item["priority_score"] >= thresholds["fix_now_at"]
        else "plan"
        if item["priority_score"] >= thresholds["plan_at"]
        else "monitor"
    )
    assert item["priority"] == expected


async def test_the_envelope_thresholds_are_the_domains_own_constants(client, db_session):
    """Read from `scoring.py` by name, so the field cannot drift from `bucket_for`."""
    await _seed_project(db_session)
    await _seed_finding(db_session, _trivy_finding(finding_id="f-1", package="urllib3"))

    body = (
        await client.get(f"/projects/{_PROJECT}/scored-risks", headers=_auth_headers(_MEMBER))
    ).json()

    assert body["thresholds"] == {"fix_now_at": FIX_NOW_AT, "plan_at": PLAN_AT}


# ---------------------------------------------------------------------------
# Ranking, and the closure G64 records
# ---------------------------------------------------------------------------


async def test_the_item_order_IS_a_priority_order(client, db_session):
    """The mirror of `test_risks_routes.py::test_the_item_order_is_not_a_priority_order`,
    on the same seed and asserting the opposite.

    `zzz`/`CRITICAL` scores `5 + 0 + 0 = 5 → plan`; `aaa`/`LOW` scores `2 + 0 + 0 = 2 →
    monitor`. The unscored route returns them `aaa, zzz` because its order is the key's; this
    one returns `zzz, aaa` because its order is the score's.
    """
    await _seed_project(db_session)
    await _seed_finding(
        db_session, _trivy_finding(finding_id="f-1", package="zzz", severity=Severity.CRITICAL)
    )
    await _seed_finding(
        db_session, _trivy_finding(finding_id="f-2", package="aaa", severity=Severity.LOW)
    )

    body = (
        await client.get(f"/projects/{_PROJECT}/scored-risks", headers=_auth_headers(_MEMBER))
    ).json()

    assert [item["match"]["package"] for item in body["items"]] == ["zzz", "aaa"]
    assert [item["priority"] for item in body["items"]] == ["plan", "monitor"]


async def test_a_critical_package_surface_is_shown_as_plan_and_never_fix_now(client, db_session):
    """**G64 at the surface — the endpoint-level twin of the unit closure.**

    `fix_now` has exactly one reachable decomposition, and a package surface cannot reach it:
    `CRITICAL` is Trivy-only, every Trivy finding is package-keyed or a no-signal singleton,
    and corroboration implies exposure. So the most severe dependency CVE this system can
    represent is presented to a developer as `plan`. This is the first place that ordering is
    shown to anyone, which is why the docstrings' claim is asserted here rather than trusted.
    """
    await _seed_project(db_session)
    await _seed_finding(
        db_session, _trivy_finding(finding_id="f-1", package="urllib3", severity=Severity.CRITICAL)
    )

    body = (
        await client.get(f"/projects/{_PROJECT}/scored-risks", headers=_auth_headers(_MEMBER))
    ).json()

    item = body["items"][0]
    assert item["priority_score"] == 5
    assert item["priority"] == "plan"
    assert all(other["priority"] != "fix_now" for other in body["items"])


# ---------------------------------------------------------------------------
# What the response deliberately does NOT claim
# ---------------------------------------------------------------------------


async def test_a_scored_risk_carries_its_confidence_and_the_envelope_defines_it(client, db_session):
    """**G63** discharged at the surface, replacing M6.2's absence assertion. ADR-0037.

    Three things, and the third is the one a later reader would drop. The item carries the
    value; the envelope carries the definition ONCE, because it is a constant and the
    thresholds sit there for the same reason (ADR-0030 decision 3); and the definition is
    `correlation`'s own constant forwarded verbatim rather than a string this adapter wrote.

    The value here is `reported`: a Trivy finding keyed on the package its own scanner named.
    """
    await _seed_project(db_session)
    await _seed_finding(db_session, _trivy_finding(finding_id="f-1", package="urllib3"))

    body = (
        await client.get(f"/projects/{_PROJECT}/scored-risks", headers=_auth_headers(_MEMBER))
    ).json()

    item = body["items"][0]
    assert item["confidence"] == Confidence.REPORTED.value
    # Not a signal: it is summed into nothing, so it has no place in the reasoning.
    assert "confidence" not in item["reasoning"]
    assert body["confidence_definition"] == CONFIDENCE_DEFINITION


async def test_the_envelope_key_set_equals_its_enumeration(client, db_session):
    """ADR-0030 decision 3's binding assertion, widened to the envelope by its M8.5 amendment.

    The item has had one since M6.3. The envelope did not, so `confidence_definition` could
    have been dropped with every other test green — the same hole that decision names for the
    item, where **G66**'s superset claim rests on fields no absence test would miss.
    """
    await _seed_project(db_session)
    await _seed_finding(db_session, _trivy_finding(finding_id="f-1", package="urllib3"))

    body = (
        await client.get(f"/projects/{_PROJECT}/scored-risks", headers=_auth_headers(_MEMBER))
    ).json()

    assert set(body) == _ENVELOPE_KEYS


async def test_a_scored_risk_carries_no_id(client, db_session):
    """A candidate Risk is not stored and has no stable referent (ADR-0025 decision 1).
    Scoring adds a number to it, not a row."""
    await _seed_project(db_session)
    await _seed_finding(db_session, _trivy_finding(finding_id="f-1", package="urllib3"))

    item = (
        await client.get(f"/projects/{_PROJECT}/scored-risks", headers=_auth_headers(_MEMBER))
    ).json()["items"][0]

    assert "id" not in item
    assert "risk_id" not in item


async def test_a_scored_listing_never_carries_a_findings_scanned_payload(client, db_session):
    """Counterpart of the two sibling routes', over the SERIALIZED body rather than named
    fields, so it fails for any future field that adds the payload anywhere."""
    secret = "AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG'"
    await _seed_project(db_session)
    await _seed_finding(
        db_session,
        _trivy_finding(finding_id="f-1", package="urllib3", raw_payload=f'{{"lines": "{secret}"}}'),
    )

    response = await client.get(
        f"/projects/{_PROJECT}/scored-risks", headers=_auth_headers(_MEMBER)
    )

    assert secret not in response.text
    assert "raw_payload" not in response.text
    # The positive anchor, so the two absences are asserted about a NON-EMPTY body.
    assert response.json()["items"][0]["finding_count"] == 1


async def test_the_dedup_hash_is_never_a_field_of_a_scored_risk(client, db_session):
    """ "Never a field of a Risk", not "never exposed" — the envelope's `failure_reason` can
    legitimately carry one, exactly as on the two sibling routes."""
    await _seed_project(db_session)
    stored = await _seed_finding(db_session, _trivy_finding(finding_id="f-1", package="urllib3"))

    response = await client.get(
        f"/projects/{_PROJECT}/scored-risks", headers=_auth_headers(_MEMBER)
    )

    assert response.json()["items"][0]["finding_count"] == 1
    assert stored.dedup_hash not in response.text


async def test_a_skipped_groups_hash_does_reach_the_response_via_failure_reason(client, db_session):
    """**The counter-test to the one above, and it ships for the reason ADR-0025 gives.**

    That decision's item 7 pins this path at the sibling route precisely so *"neither a future
    whole-body ban nor a future `dedup_hash` field can cite the other's test as precedent"*.
    Without it, "never a field of a Risk" drifts into "never exposed", which is false:
    `NormalizeScanUseCase` writes skipped groups' `dedup_hash` values into `failure_reason`
    deliberately, and this route returns that field verbatim in its envelope.

    **A finding is seeded although the subject is the envelope**, so the closing loop over
    `items` iterates something — a guard that asserts nothing would be the defect this file
    exists to prevent.
    """
    await _seed_project(db_session)
    await _seed_finding(db_session, _trivy_finding(finding_id="f-1", package="urllib3"))
    runs = PostgresNormalizationRunRepository(db_session)
    await runs.request(id="run-1", scan_id=_SCAN, project_id=_PROJECT, requested_at=_AT)
    run = await runs.get_by_scan_id(_SCAN)
    assert run is not None
    await runs.update(run.start(_AT).fail(_AT, "1 finding group(s) … dedup_hash: v1:abc123"))
    await db_session.commit()

    response = await client.get(
        f"/projects/{_PROJECT}/scored-risks", headers=_auth_headers(_MEMBER)
    )

    body = response.json()
    assert "v1:abc123" in body["normalization"]["latest_run"]["failure_reason"]
    # And still not as a field on any scored Risk, which is the property that holds.
    assert body["items"][0]["finding_count"] == 1
    for item in body["items"]:
        assert "dedup_hash" not in item


async def test_nothing_in_the_response_claims_a_scored_risk_is_resolved(client, db_session):
    """Counterpart of `test_nothing_in_the_response_claims_a_risk_is_resolved`, item-scoped.

    Item-scoped for the same reason that one is: the envelope legitimately carries
    `normalization.latest_run.status`, so a whole-body ban would forbid a field this response
    is required to have. Scoring says nothing about lifecycle — M9.1 owns resolution and M8.1
    the lifecycle — and a `priority` is emphatically not a status.
    """
    await _seed_project(db_session)
    await _seed_finding(db_session, _trivy_finding(finding_id="f-1", package="urllib3"))

    response = await client.get(
        f"/projects/{_PROJECT}/scored-risks", headers=_auth_headers(_MEMBER)
    )

    for forbidden in ("resolved", "is_open", "status"):
        assert forbidden not in response.json()["items"][0]


async def test_no_response_field_carries_an_absolute_worker_path(client, db_session):
    """Counterpart of both sibling routes', and **it is not subsumed by the key-set assertion.**

    That assertion constrains an item's KEYS; a worker path would arrive as a VALUE — through
    `normalization.latest_run.failure_reason`, or through a signal's `note` or `produced_by` —
    so it is checked over the whole serialized body, which is the shape the siblings use.

    G9 and G10 record that Semgrep's invocation could put an absolute worker path into a
    finding's `rule_id` and `location.file_path`; M4.4 closed it with `cwd=target` and
    `--no-rewrite-rule-ids`. This asserts the CONSEQUENCE at the surface that would have shown
    it, rather than re-measuring the cause.

    **What it does not do**, said because the seeding makes it easy to over-read: nothing
    seeded here contains an absolute worker path, so a new field carrying one would need its
    own case with data that has one.
    """
    await _seed_project(db_session)
    await _seed_finding(db_session, _trivy_finding(finding_id="f-1", package="urllib3"))

    response = await client.get(
        f"/projects/{_PROJECT}/scored-risks", headers=_auth_headers(_MEMBER)
    )

    assert response.json()["items"][0]["finding_count"] == 1
    assert ":\\" not in response.text
    assert "verion-scan-" not in response.text


# ---------------------------------------------------------------------------
# The completeness envelope, and the one deliberate 500
# ---------------------------------------------------------------------------


async def test_an_empty_project_and_a_broken_one_are_distinguishable(client, db_session):
    """A priority order built on findings that were never produced is worse than a short
    list, which is why this route carries the envelope rather than dropping it."""
    await _seed_project(db_session)

    clean = (
        await client.get(f"/projects/{_PROJECT}/scored-risks", headers=_auth_headers(_MEMBER))
    ).json()
    assert clean["total"] == 0
    assert clean["normalization"] == {"latest_run": None, "unfinished_runs": 0}

    runs = PostgresNormalizationRunRepository(db_session)
    await runs.request(id="run-1", scan_id=_SCAN, project_id=_PROJECT, requested_at=_AT)
    await db_session.commit()

    broken = (
        await client.get(f"/projects/{_PROJECT}/scored-risks", headers=_auth_headers(_MEMBER))
    ).json()
    assert broken["total"] == 0
    assert broken["normalization"]["unfinished_runs"] == 1


class _GroupNamingAnAbsentFinding:
    """`CandidateRiskPort` returning a group whose member the findings read will not return.

    The only way to reach `MemberFindingMissing` from outside: nothing deletes a finding
    today (**G11**), so the two reads cannot disagree in production. **This test therefore
    does NOT exercise the real adapter** — unlike every other test in this file — and it is
    named here so the two are not confused.
    """

    async def candidate_risks(self, *, project_id, user_id):
        from verion.modules.correlation.domain.match_key import MatchKey
        from verion.modules.correlation.domain.matching import MatchGroup

        return [
            MatchGroup(
                key=MatchKey(project_id=project_id, package="ghost", url=None),
                finding_ids=("no-such-finding",),
                member_confidence=(Confidence.REPORTED,),
            )
        ]


async def test_disagreeing_reads_are_a_500_rather_than_a_confident_wrong_bucket(client, db_session):
    """ADR-0030 decision 5, chosen rather than inherited from the framework's default.

    Scoring a short surface would return a confident bucket computed from incomplete
    members — an untraceable score, which is the one thing rule 5 forbids. The route maps it
    to 500 because the server's two reads disagreed: not the caller's doing, and not
    retryable.
    """
    await _seed_project(db_session)
    app.dependency_overrides[get_candidate_risk_port] = _GroupNamingAnAbsentFinding
    try:
        response = await client.get(
            f"/projects/{_PROJECT}/scored-risks", headers=_auth_headers(_MEMBER)
        )
    finally:
        app.dependency_overrides.pop(get_candidate_risk_port, None)

    assert response.status_code == 500
    # The message names an internal invariant, so the body stays generic.
    assert "no-such-finding" not in response.text


def test_the_ports_denial_type_is_what_the_route_catches():
    """A narrowing guard: the route catches `CandidateRiskAccessDenied` specifically, and a
    broader `except` would let the deleted-translation mutation through as a 404 anyway."""
    import inspect

    from verion.modules.risk_engine.adapters.inbound.api import router as route_module

    source = inspect.getsource(route_module.list_scored_risks)
    assert "except CandidateRiskAccessDenied" in source
    assert CandidateRiskAccessDenied.__name__ in source
