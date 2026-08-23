"""`PostgresFindingRepository` against real Postgres.

The schema here is the migrated one (see `conftest.migrated_schema`), so the
constraint tests at the bottom assert against what production runs rather than
against what the models declare.

**The dedup and idempotency tests build `Finding`s by hand rather than by running
a mapper over a fixture, and that is deliberate.** G9: Semgrep emits an absolute
per-scan temp path in production, and the committed fixture's `path` was redacted
to the relative `vulnerable.py`. A fixture-driven "the same finding upserts to
one row across two scans" test would therefore demonstrate dedup working for a
shape production does not emit — a green test disconnected from reality, which is
G8's failure with a redaction in the tool's place. Hand-built findings make the
adapter the subject. The one test that does read fixtures uses them only as a
supply of realistic field values, where the path's shape is irrelevant, and
`test_a_different_file_path_is_a_different_finding` states the G9 consequence as
intended behaviour so a reader meets it here rather than in an incident.
"""

import dataclasses
import inspect
from datetime import UTC, datetime

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from verion.modules.normalization.adapters.outbound.db.models import (
    EvidenceModel,
    FindingModel,
    FindingSightingModel,
)
from verion.modules.normalization.adapters.outbound.db.repository import (
    _REFRESHED_COLUMNS,
    PostgresFindingRepository,
)
from verion.modules.normalization.domain.dedup import compute_dedup_hash
from verion.modules.normalization.domain.finding import (
    _RULE_LEVEL_ATTRIBUTES,
    MAX_RAW_PAYLOAD_CHARS,
    Evidence,
    Finding,
    FindingSighting,
    Location,
    merge_observation,
)
from verion.modules.normalization.domain.mappers.semgrep import map_semgrep_output
from verion.modules.normalization.domain.mappers.trivy import map_trivy_output
from verion.modules.normalization.domain.mappers.zap import map_zap_output
from verion.platform.clock import SystemClock
from verion.platform.id_generator import UuidIdGenerator
from verion.shared_kernel.scanner_tools import ScannerTool
from verion.shared_kernel.severity import Severity

_CAPTURED_AT = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
_OBSERVED_AT = datetime(2026, 1, 2, 12, 0, tzinfo=UTC)
_PROJECT_ID = "project-1"


def _finding(
    *,
    id: str = "finding-1",
    project_id: str = _PROJECT_ID,
    source: ScannerTool = ScannerTool.SEMGREP,
    rule_id: str = "dangerous-eval",
    severity: Severity = Severity.HIGH,
    native_severity: str = "ERROR",
    title: str = "Avoid eval() on untrusted input.",
    location: Location | None = None,
    cwe: str | None = None,
    owasp_category: str | None = None,
    cvss: float | None = None,
    evidence_id: str = "evidence-1",
    scan_id: str = "scan-1",
    raw_payload: str = '{"check_id":"dangerous-eval"}',
    captured_at: datetime = _CAPTURED_AT,
) -> Finding:
    return Finding(
        id=id,
        project_id=project_id,
        source=source,
        rule_id=rule_id,
        severity=severity,
        native_severity=native_severity,
        title=title,
        location=location if location is not None else Location(file_path="app.py", start_line=2),
        evidence=Evidence(
            id=evidence_id,
            finding_id=id,
            scan_id=scan_id,
            raw_payload=raw_payload,
            source_tool=source,
            captured_at=captured_at,
        ),
        cwe=cwe,
        owasp_category=owasp_category,
        cvss=cvss,
    )


async def _row_count(db_session, table: str) -> int:
    result = await db_session.execute(text(f"SELECT count(*) FROM {table}"))
    return int(result.scalar_one())


# ---------------------------------------------------------------------------
# The SET clause and the domain agree, checked three ways.
#
# These three need no database. They live here rather than in tests/unit/ so they
# sit next to the adapter they constrain — a reader changing `_REFRESHED_COLUMNS`
# finds them in the same file.
# ---------------------------------------------------------------------------


def test_every_findings_column_is_a_surrogate_an_identity_input_or_refreshed():
    """The partition is total and disjoint, so a column cannot be added without
    somebody deciding which kind it is. A new column left out of the SET clause
    would silently never refresh, while `merge_observation` says it does — the
    drift this whole trio exists to make impossible.
    """
    surrogate_and_scope = {"id", "project_id", "dedup_hash"}
    identity = set(inspect.signature(compute_dedup_hash).parameters)
    refreshed = set(_REFRESHED_COLUMNS)

    assert surrogate_and_scope & identity == set()
    assert surrogate_and_scope & refreshed == set()
    assert identity & refreshed == set()
    assert surrogate_and_scope | identity | refreshed == {
        column.name for column in FindingModel.__table__.columns
    }


def test_the_refreshed_columns_are_derived_from_what_the_domain_declares():
    """`merge_observation` refreshes the rule-level attributes and the whole
    `Location`; identity pins the rest. So the SET clause is exactly the
    rule-level attributes plus the Location fields the hash excludes — derived
    here from both domain declarations rather than retyped, so changing either
    without changing the adapter fails.
    """
    location_fields = {field.name for field in dataclasses.fields(Location)}
    positionally_excluded = location_fields - set(inspect.signature(compute_dedup_hash).parameters)

    assert positionally_excluded == {"start_line", "end_line", "installed_version"}
    assert set(_REFRESHED_COLUMNS) == set(_RULE_LEVEL_ATTRIBUTES) | positionally_excluded


def test_every_domain_field_maps_to_a_column():
    """Catches the case the partition test cannot: a field added to the domain
    with no column at all, which would be dropped on write rather than merely
    not refreshed.
    """
    finding_fields = {field.name for field in dataclasses.fields(Finding)} - {
        # Not columns because they are not scalars: Location is flattened into
        # the eight columns below, and Evidence has its own table.
        "location",
        "evidence",
    }
    finding_columns = {column.name for column in FindingModel.__table__.columns}
    assert finding_fields <= finding_columns
    assert {field.name for field in dataclasses.fields(Location)} <= finding_columns

    assert {field.name for field in dataclasses.fields(Evidence)} == {
        column.name for column in EvidenceModel.__table__.columns
    }
    assert {field.name for field in dataclasses.fields(FindingSighting)} == {
        column.name for column in FindingSightingModel.__table__.columns
    }


# ---------------------------------------------------------------------------
# Round trip and hydration
# ---------------------------------------------------------------------------


async def test_a_new_finding_round_trips(db_session):
    repository = PostgresFindingRepository(db_session)
    finding = _finding(cwe="CWE-95", owasp_category="A03:2021", cvss=9.8)

    stored = await repository.upsert(finding)

    assert stored == finding
    assert await repository.get_by_project_id(_PROJECT_ID) == [finding]


async def test_hydration_reconstructs_the_enums_rather_than_leaving_bare_strings(db_session):
    """`Severity.HIGH == "high"` is True but `Severity.HIGH >= "high"` raises, and
    ordering is the half M5, M6 and M8 use (ADR-0018 decision 2). Equality
    therefore cannot detect a bare `str` coming back out of a String column —
    `stored == finding` above would pass either way — so the type is asserted
    directly, and then exercised through the operation that would actually break.
    """
    repository = PostgresFindingRepository(db_session)
    await repository.upsert(_finding())

    [stored] = await repository.get_by_project_id(_PROJECT_ID)

    assert type(stored.severity) is Severity
    assert type(stored.source) is ScannerTool
    assert type(stored.evidence.source_tool) is ScannerTool
    # Enum on the right: SIM300 rewrites constant-on-left comparisons, and this
    # assertion's subject is the operand TYPE, not its position (G8).
    assert stored.severity >= Severity.LOW


# ---------------------------------------------------------------------------
# The upsert IS merge_observation
# ---------------------------------------------------------------------------


async def test_upserting_an_observed_finding_produces_exactly_merge_observation(db_session):
    """One whole-object assertion, on purpose. Comparing field by field would
    need editing every time `Finding` grows one; comparing against
    `merge_observation`'s own output covers every field at once and keeps doing
    so. `observed` differs from `existing` in every mutable field, so a SET
    clause missing any one of them fails here.

    Non-vacuous because `upsert` returns a row read back from the database via
    RETURNING rather than the object it was handed — if the SET clause did not
    write a column, the returned value would carry the stale one.
    """
    repository = PostgresFindingRepository(db_session)
    existing = _finding(
        severity=Severity.MEDIUM,
        native_severity="WARNING",
        title="old title",
        cwe=None,
        owasp_category=None,
        cvss=None,
        location=Location(file_path="app.py", start_line=2, end_line=2),
        raw_payload='{"first":true}',
    )
    await repository.upsert(existing)

    observed = _finding(
        # A fresh surrogate id and evidence id, as a mapper would mint: the
        # stored ones must win, which is merge_observation's whole job.
        id="finding-2",
        evidence_id="evidence-2",
        severity=Severity.CRITICAL,
        native_severity="ERROR",
        title="new title",
        cwe="CWE-95",
        owasp_category="A03:2021",
        cvss=9.8,
        # Identity fields unchanged (file_path), positional ones moved.
        location=Location(file_path="app.py", start_line=41, end_line=42),
        scan_id="scan-2",
        raw_payload='{"second":true}',
        captured_at=datetime(2026, 2, 2, 12, 0, tzinfo=UTC),
    )

    merged = await repository.upsert(observed)

    assert merged == merge_observation(existing, observed)
    assert merged.id == existing.id
    assert merged.evidence.id == existing.evidence.id
    assert await _row_count(db_session, "findings") == 1
    assert await _row_count(db_session, "evidence") == 1
    assert await repository.get_by_project_id(_PROJECT_ID) == [merged]


async def test_the_same_finding_in_two_projects_is_two_rows(db_session):
    """The project is the scope, not a hash input (ADR-0019 decision 3), so two
    projects with the same vulnerable dependency share a `dedup_hash` and must
    not share a row — a shared row would make one tenant's dismissal another
    tenant's.
    """
    repository = PostgresFindingRepository(db_session)
    ours = _finding(id="finding-ours", evidence_id="evidence-ours", project_id="project-1")
    theirs = _finding(id="finding-theirs", evidence_id="evidence-theirs", project_id="project-2")

    await repository.upsert(ours)
    await repository.upsert(theirs)

    assert ours.dedup_hash == theirs.dedup_hash
    assert await repository.get_by_project_id("project-1") == [ours]
    assert await repository.get_by_project_id("project-2") == [theirs]


async def test_a_different_file_path_is_a_different_finding(db_session):
    """`file_path` is a `dedup_hash` input, so this is correct — and it is also
    exactly what **G9** causes in production, where Semgrep reports an absolute
    path under a fresh `tempfile.mkdtemp` on every scan and therefore re-keys
    every SAST finding. Asserted as intended behaviour so the consequence is
    visible here rather than discovered as duplicate rows later. The fix belongs
    to `scanning`'s adapter and lands in M4.4, before any production writer.
    """
    repository = PostgresFindingRepository(db_session)
    here = _finding(id="finding-1", evidence_id="evidence-1", location=Location(file_path="a.py"))
    there = _finding(id="finding-2", evidence_id="evidence-2", location=Location(file_path="b.py"))

    await repository.upsert(here)
    await repository.upsert(there)

    assert here.dedup_hash != there.dedup_hash
    assert await _row_count(db_session, "findings") == 2


async def test_a_different_start_line_is_the_same_finding_and_the_line_refreshes(db_session):
    """The other half of the same decision. Line numbers are excluded from the
    hash because an edit *above* a finding shifts it, and re-keying would report
    a resolve-plus-reopen that never happened — but the stored line still tracks
    the current state of the code, because `merge_observation` refreshes the
    whole `Location`.
    """
    repository = PostgresFindingRepository(db_session)
    before = _finding(location=Location(file_path="app.py", start_line=2, end_line=2))
    await repository.upsert(before)

    after = _finding(
        id="finding-2",
        evidence_id="evidence-2",
        location=Location(file_path="app.py", start_line=41, end_line=41),
    )
    stored = await repository.upsert(after)

    assert await _row_count(db_session, "findings") == 1
    assert stored.location.start_line == 41


async def test_the_stored_dedup_hash_equals_the_hash_of_the_row_it_is_stored_on(
    db_session, scanner_fixture
):
    """The column is a materialization of `Finding.dedup_hash`, not a second
    source of truth (ADR-0019 decision 3) — so it must be recomputable from the
    row itself, not merely from the object that wrote it.

    Recomputed from the STORED identity columns, read back with raw SQL: a
    version that recomputed from the in-memory `Finding` would pass even if the
    adapter wrote a constant. That is only possible because `Location` is
    flattened onto this table, which puts all seven hash inputs on the row.

    Driven by all three committed fixtures rather than by hand-built findings,
    because the point is coverage of real field shapes — nulls where a tool
    supplies nothing, a URL and method and parameter for ZAP, a package for
    Trivy. The Semgrep fixture's redacted relative path is irrelevant here: the
    assertion is an equality between two derivations of the same row, not a
    claim about what the path looks like.
    """
    repository = PostgresFindingRepository(db_session)
    id_generator, clock = UuidIdGenerator(), SystemClock()
    findings = [
        *map_semgrep_output(
            project_id=_PROJECT_ID,
            scan_id="scan-1",
            raw_output=scanner_fixture("semgrep_scan.json"),
            id_generator=id_generator,
            clock=clock,
        ),
        *map_trivy_output(
            project_id=_PROJECT_ID,
            scan_id="scan-1",
            raw_output=scanner_fixture("trivy_scan.json"),
            id_generator=id_generator,
            clock=clock,
        ),
        *map_zap_output(
            project_id=_PROJECT_ID,
            scan_id="scan-1",
            raw_output=scanner_fixture("zap_scan.json"),
            id_generator=id_generator,
            clock=clock,
        ),
    ]
    for finding in findings:
        await repository.upsert(finding)

    result = await db_session.execute(
        text(
            "SELECT dedup_hash, source, rule_id, file_path, package, url, http_method, parameter "
            "FROM findings"
        )
    )
    rows = result.all()

    assert len(rows) == len(findings) > 0
    for row in rows:
        assert row.dedup_hash == compute_dedup_hash(
            source=ScannerTool(row.source),
            rule_id=row.rule_id,
            file_path=row.file_path,
            package=row.package,
            url=row.url,
            http_method=row.http_method,
            parameter=row.parameter,
        )


# ---------------------------------------------------------------------------
# Sightings
# ---------------------------------------------------------------------------


async def test_two_scans_observing_one_finding_are_two_sightings(db_session):
    repository = PostgresFindingRepository(db_session)
    stored = await repository.upsert(_finding())

    await repository.record_sighting(
        FindingSighting(finding_id=stored.id, scan_id="scan-1", observed_at=_OBSERVED_AT)
    )
    await repository.record_sighting(
        FindingSighting(finding_id=stored.id, scan_id="scan-2", observed_at=_OBSERVED_AT)
    )

    sightings = await repository.get_sightings_by_finding_id(stored.id)
    assert [sighting.scan_id for sighting in sightings] == ["scan-1", "scan-2"]
    assert all(sighting.match_count == 1 for sighting in sightings)


async def test_re_recording_a_sighting_overwrites_the_total_rather_than_summing(db_session):
    """`match_count` is a per-scan TOTAL, never an increment, and this is the
    test that pins it.

    Overwriting is what makes re-recording idempotent, and idempotency is the
    requirement: `ARCHITECTURE.md` §9 says re-normalizing a scan refreshes rows
    rather than adding them, and an arq retry re-running every enabled scanner is
    guaranteed (ADR-016 decision 1). Summing would therefore double-count on
    every retry, silently — so a caller computing the total in more than one pass
    must aggregate before calling, not call twice. `collapse_by_identity`
    produces the total in one pass, which is how M4.4 satisfies it.
    """
    repository = PostgresFindingRepository(db_session)
    stored = await repository.upsert(_finding())

    await repository.record_sighting(
        FindingSighting(
            finding_id=stored.id, scan_id="scan-1", observed_at=_OBSERVED_AT, match_count=3
        )
    )
    later = datetime(2026, 3, 3, 12, 0, tzinfo=UTC)
    await repository.record_sighting(
        FindingSighting(finding_id=stored.id, scan_id="scan-1", observed_at=later, match_count=5)
    )

    [sighting] = await repository.get_sightings_by_finding_id(stored.id)
    assert sighting.match_count == 5
    assert sighting.observed_at == later
    assert await _row_count(db_session, "finding_sightings") == 1


async def test_a_sighting_of_a_finding_that_does_not_exist_is_rejected(db_session):
    """The FK is within the module, so it is a real constraint rather than the
    unconstrained cross-module reference `scan_id` is.
    """
    repository = PostgresFindingRepository(db_session)

    with pytest.raises(IntegrityError):
        await repository.record_sighting(
            FindingSighting(finding_id="no-such-finding", scan_id="s1", observed_at=_OBSERVED_AT)
        )
    await db_session.rollback()


# ---------------------------------------------------------------------------
# Constraints, asserted against the migrated schema via raw SQL.
#
# Deliberately bypassing the domain dataclasses: what these prove is that the
# invariant holds for ANY writer, not only for code that constructs a Finding
# first. That is the whole point of ADR-016 decision 2's two-place idiom, and it
# is why these use text() rather than the repository.
# ---------------------------------------------------------------------------


_INSERT_FINDING = text(
    "INSERT INTO findings (id, project_id, dedup_hash, source, rule_id, severity, "
    "native_severity, title) VALUES (:id, :project_id, :dedup_hash, :source, :rule_id, "
    ":severity, :native_severity, :title)"
)

_VALID_FINDING_ROW = {
    "id": "raw-1",
    "project_id": _PROJECT_ID,
    "dedup_hash": "v1:deadbeef",
    "source": "semgrep",
    "rule_id": "dangerous-eval",
    "severity": "high",
    "native_severity": "ERROR",
    "title": "t",
}


@pytest.mark.parametrize(
    ("column", "value", "constraint"),
    [
        ("rule_id", "", "ck_findings_rule_id_present"),
        ("native_severity", "", "ck_findings_native_severity_present"),
        ("severity", "severe", "ck_findings_severity"),
        ("source", "nessus", "ck_findings_source"),
    ],
)
async def test_a_findings_row_violating_a_check_constraint_is_rejected(
    db_session, column, value, constraint
):
    with pytest.raises(IntegrityError, match=constraint):
        await db_session.execute(_INSERT_FINDING, {**_VALID_FINDING_ROW, column: value})
    await db_session.rollback()


@pytest.mark.parametrize("severity", list(Severity))
async def test_every_severity_member_satisfies_the_check_constraint(db_session, severity):
    """The enum and the CHECK must agree on the same strings. Parametrized over
    the members rather than over a literal list, so adding one to `Severity`
    without widening the constraint fails here — the constraint is spelled out in
    the migration, which is a point-in-time record and cannot be generated from a
    type that changes underneath it.
    """
    await db_session.execute(_INSERT_FINDING, {**_VALID_FINDING_ROW, "severity": str(severity)})
    assert await _row_count(db_session, "findings") == 1


@pytest.mark.parametrize("tool", list(ScannerTool))
async def test_every_scanner_tool_member_satisfies_the_check_constraint(db_session, tool):
    await db_session.execute(_INSERT_FINDING, {**_VALID_FINDING_ROW, "source": str(tool)})
    assert await _row_count(db_session, "findings") == 1


async def test_a_duplicate_project_and_dedup_hash_is_rejected(db_session):
    await db_session.execute(_INSERT_FINDING, _VALID_FINDING_ROW)
    with pytest.raises(IntegrityError, match="uq_findings_project_id_dedup_hash"):
        await db_session.execute(_INSERT_FINDING, {**_VALID_FINDING_ROW, "id": "raw-2"})
    await db_session.rollback()


async def test_a_second_evidence_row_for_one_finding_is_rejected(db_session):
    """Evidence is 1:1 with Finding, and that is a constraint rather than a
    convention — which is what lets the evidence upsert target it with
    ON CONFLICT instead of hoping no second row appears.
    """
    repository = PostgresFindingRepository(db_session)
    stored = await repository.upsert(_finding())

    with pytest.raises(IntegrityError, match="uq_evidence_finding_id"):
        await db_session.execute(
            text(
                "INSERT INTO evidence (id, finding_id, scan_id, raw_payload, source_tool, "
                "captured_at) VALUES ('e-raw', :finding_id, 's1', '{}', 'semgrep', now())"
            ),
            {"finding_id": stored.id},
        )
    await db_session.rollback()


async def test_an_oversized_raw_payload_is_rejected(db_session):
    """`Evidence.__post_init__` already refuses this, so the row can only be
    reached by writing past the domain — which is exactly the writer this
    constraint exists for.

    Length taken from `MAX_RAW_PAYLOAD_CHARS` rather than hardcoded, and paired
    with the boundary test below, because on its own this is vacuous in one
    direction: the constraint is a literal `20000` in the migration, so if
    somebody *raised* the constant without touching the migration, a payload of
    the new limit plus one would still be rejected by the old, lower bound and
    this would pass while the two had silently drifted. The pair closes both
    directions — raising the constant fails the boundary test, lowering it fails
    this one.
    """
    repository = PostgresFindingRepository(db_session)
    stored = await repository.upsert(_finding())

    with pytest.raises(IntegrityError, match="ck_evidence_raw_payload_length"):
        await db_session.execute(
            text("UPDATE evidence SET raw_payload = repeat('x', :length) WHERE finding_id = :id"),
            {"id": stored.id, "length": MAX_RAW_PAYLOAD_CHARS + 1},
        )
    await db_session.rollback()


async def test_a_raw_payload_of_exactly_the_limit_is_accepted(db_session):
    """The other half of the pair above. `<=` in the constraint, not `<`, and the
    migration's literal bound is the same number the domain enforces.
    """
    repository = PostgresFindingRepository(db_session)
    stored = await repository.upsert(_finding())

    await db_session.execute(
        text("UPDATE evidence SET raw_payload = repeat('x', :length) WHERE finding_id = :id"),
        {"id": stored.id, "length": MAX_RAW_PAYLOAD_CHARS},
    )

    result = await db_session.execute(
        text("SELECT length(raw_payload) FROM evidence WHERE finding_id = :id"),
        {"id": stored.id},
    )
    assert result.scalar_one() == MAX_RAW_PAYLOAD_CHARS


async def test_a_sighting_with_a_non_positive_match_count_is_rejected(db_session):
    repository = PostgresFindingRepository(db_session)
    stored = await repository.upsert(_finding())

    with pytest.raises(IntegrityError, match="ck_finding_sightings_match_count"):
        await db_session.execute(
            text(
                "INSERT INTO finding_sightings (finding_id, scan_id, observed_at, match_count) "
                "VALUES (:id, 's1', now(), 0)"
            ),
            {"id": stored.id},
        )
    await db_session.rollback()
