from collections.abc import Iterable
from datetime import datetime
from enum import StrEnum

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from verion.modules.normalization.domain.finding import MAX_RAW_PAYLOAD_CHARS
from verion.platform.db import Base
from verion.shared_kernel.scanner_tools import ScannerTool
from verion.shared_kernel.severity import Severity


def _sql_vocabulary(members: Iterable[StrEnum]) -> str:
    """Render an enum's members as the body of a SQL `IN (...)` list.

    **What deriving this from the enum buys, and what it does not**, said plainly
    because the obvious reading is wrong. It keeps *this declaration* in step
    with `shared_kernel/`, which is worth something — `normalization_runs` types
    its four status values out by hand, but those live in this module's own
    domain, while `Severity` and `ScannerTool` can grow without anyone opening
    this file.

    It does **not** stop a widened enum from leaving the deployed constraint
    narrower, and cannot. The constraint any database actually carries is the
    hand-written one in the migration, which is a point-in-time record and must
    not change meaning when the enum changes underneath it; and since the test
    schema is built by Alembic rather than by `create_all`, the expression below
    is applied to no database at all. `test_schema_matches_models.py` compares
    constraint *names*, so it would not notice either.

    The guard that actually catches it is
    `test_every_severity_member_satisfies_the_check_constraint` and its
    `ScannerTool` twin, which insert every member against the real migrated
    table. That is where to look when adding a member, not here.
    """
    return ", ".join(f"'{value}'" for value in sorted(str(member) for member in members))


class NormalizationRunModel(Base):
    __tablename__ = "normalization_runs"
    __table_args__ = (
        # The idempotency key. A retried run_scan job re-requests normalization
        # for a scan it already requested it for; this constraint is what turns
        # that into a no-op instead of a second row (ADR-0017 decision 2).
        UniqueConstraint("scan_id", name="uq_normalization_runs_scan_id"),
        # Deliberately more defence than scan_results gives its own status
        # column, for one specific reason: this column is what a reconciliation
        # sweep selects on, so an unrecognised value would make the row
        # *invisible to the sweep* rather than merely odd — a scan that silently
        # never gets normalized, which is the exact failure this record exists
        # to prevent.
        CheckConstraint(
            "status IN ('pending', 'running', 'completed', 'failed')",
            name="ck_normalization_runs_status",
        ),
        # The same invariant NormalizationRun.__post_init__ enforces, enforced
        # again where nothing can route around it — the idiom ADR-016 decision 2
        # established with ck_scan_results_outcome_shape.
        CheckConstraint(
            "(status = 'failed' AND failure_reason IS NOT NULL)"
            " OR (status <> 'failed' AND failure_reason IS NULL)",
            name="ck_normalization_runs_failure_reason_shape",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    # No FK to scans — scans belongs to `scanning`, and cross-module references
    # go unconstrained at the persistence layer too, the same precedent as
    # ScanModel.project_id and ProjectModel.owner_id.
    scan_id: Mapped[str] = mapped_column(String(36), nullable=False)
    # The dedup scope (ADR-0019 decision 7). No FK either, for the same reason
    # scan_id has none: projects belongs to another module. NOT NULL, reached by
    # an add-nullable → backfill-from-scans → SET NOT NULL migration rather than
    # a bare NOT NULL add, since rows written before M4.3 carry no project.
    project_id: Mapped[str] = mapped_column(String(36), nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # Unconstrained on purpose: these belong to transitions M4.4 writes.
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    failure_reason: Mapped[str | None] = mapped_column(String, nullable=True)


class FindingModel(Base):
    """One durable, project-scoped `Finding`. See ADR-0019.

    `Location` is flattened into the eight columns below rather than given a
    table of its own: it is an embedded value object (`ARCHITECTURE.md` §4), and
    flattening is also what makes the stored `dedup_hash` auditable — every one
    of its inputs is a column on this row, so the hash can be recomputed from the
    row itself rather than from the object that wrote it.
    """

    __tablename__ = "findings"
    __table_args__ = (
        # Identity is the hash; the project is the SCOPE, deliberately not a hash
        # input (ADR-0019 decision 3). Two projects with the same vulnerable
        # dependency produce the same hash and two rows. This is also the
        # ON CONFLICT target for the upsert, which is why it is named.
        UniqueConstraint("project_id", "dedup_hash", name="uq_findings_project_id_dedup_hash"),
        # The same invariants Finding.__post_init__ enforces, enforced again
        # where nothing can route around them — ADR-016 decision 2's idiom.
        CheckConstraint("rule_id <> ''", name="ck_findings_rule_id_present"),
        CheckConstraint("native_severity <> ''", name="ck_findings_native_severity_present"),
        # These two go beyond what the domain guards, on a stated principle:
        # pin a closed vocabulary in SQL where an unrecognised value would fail
        # at READ time with a blast radius wider than its own row. Hydration
        # calls Severity(...) and ScannerTool(...) for every row of a listing, so
        # one bad value raises mid-listing and takes down a whole response — the
        # PRODUCT_SPEC.md §12 partial-failure corruption arriving through a
        # validation rule. The CHECK converts that into a single-row write
        # failure. scan_results.tool deliberately has no such CHECK, and the
        # difference is exactly this: ScanResult.tool is a plain str that is
        # never reconstructed, so there is no read-time failure to convert.
        CheckConstraint(
            f"severity IN ({_sql_vocabulary(Severity)})",
            name="ck_findings_severity",
        ),
        CheckConstraint(
            f"source IN ({_sql_vocabulary(ScannerTool)})",
            name="ck_findings_source",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    # No FK to projects — cross-module reference, same precedent as
    # ScanModel.project_id and NormalizationRunModel.scan_id above.
    project_id: Mapped[str] = mapped_column(String(36), nullable=False)
    # A materialization of Finding.dedup_hash, not a second source of truth: the
    # adapter writes the property and there is no parameter through which a
    # caller could supply anything else. Bare String rather than String(67) —
    # "v1:" + 64 hex is 67 today, but the version prefix is a contract that can
    # widen, and nobody queries this by prefix.
    dedup_hash: Mapped[str] = mapped_column(String, nullable=False)

    # Identity inputs, in compute_dedup_hash's own parameter order.
    source: Mapped[str] = mapped_column(String, nullable=False)
    rule_id: Mapped[str] = mapped_column(String, nullable=False)
    file_path: Mapped[str | None] = mapped_column(String, nullable=True)
    package: Mapped[str | None] = mapped_column(String, nullable=True)
    url: Mapped[str | None] = mapped_column(String, nullable=True)
    http_method: Mapped[str | None] = mapped_column(String, nullable=True)
    parameter: Mapped[str | None] = mapped_column(String, nullable=True)

    # Refreshed on every observation — the rule-level attributes, plus the three
    # Location fields the hash excludes for positional reasons. This set is
    # exactly what merge_observation takes from the later observation, and the
    # adapter's _REFRESHED_COLUMNS is pinned against it by a test.
    severity: Mapped[str] = mapped_column(String, nullable=False)
    native_severity: Mapped[str] = mapped_column(String, nullable=False)
    title: Mapped[str] = mapped_column(String, nullable=False)
    cwe: Mapped[str | None] = mapped_column(String, nullable=True)
    owasp_category: Mapped[str | None] = mapped_column(String, nullable=True)
    cvss: Mapped[float | None] = mapped_column(Float, nullable=True)
    start_line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    end_line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    installed_version: Mapped[str | None] = mapped_column(String, nullable=True)


class EvidenceModel(Base):
    """The latest observation's verbatim tool payload for one `Finding`.

    One row per finding, and that is a CONSTRAINT rather than a convention:
    `uq_evidence_finding_id` both states the 1:1 and serves as the upsert's
    ON CONFLICT target, so it does work rather than documenting. Its domain
    counterpart is structural instead of a validation — `Finding.evidence` is a
    single field, and `__post_init__` pins `evidence.finding_id == finding.id`.

    One invariant is deliberately NOT mirrored here:
    `Finding.__post_init__` requires `evidence.source_tool is finding.source`,
    which spans two tables, so no CHECK constraint can express it. **Not
    impossible, though — chosen against**, which is worth saying because "no
    CHECK can do it" invites the conclusion that nothing can: a composite
    `FOREIGN KEY (finding_id, source_tool) REFERENCES findings (id, source)` over
    a redundant `UNIQUE (id, source)` states it exactly, and is the standard
    idiom. It is not used because it buys a duplicated index and a second
    reference into `findings` to re-assert something a single writer already
    guarantees — the adapter builds both rows from one `Finding`, whose own
    constructor refuses the mismatch. Revisit if a second writer ever appears.
    """

    __tablename__ = "evidence"
    __table_args__ = (
        UniqueConstraint("finding_id", name="uq_evidence_finding_id"),
        # Evidence.__post_init__'s bound, enforced again in SQL. Mappers truncate
        # before constructing, so a row over the limit means something wrote past
        # the domain entirely.
        CheckConstraint(
            f"char_length(raw_payload) <= {MAX_RAW_PAYLOAD_CHARS}",
            name="ck_evidence_raw_payload_length",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    # FK: both tables belong to this module. No ondelete — nothing deletes a
    # finding today, and choosing CASCADE now would decide M9's retention policy
    # ahead of M9.
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), nullable=False)
    # Which scan produced the retained payload. Cross-module, so unconstrained —
    # nothing at this layer stops that scan being deleted out from under the row.
    scan_id: Mapped[str] = mapped_column(String(36), nullable=False)
    raw_payload: Mapped[str] = mapped_column(String, nullable=False)
    source_tool: Mapped[str] = mapped_column(String, nullable=False)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class FindingSightingModel(Base):
    """One scan's observation of one `Finding`.

    Composite natural key, no surrogate id — `ProjectMembership`'s shape, for the
    same reason: there is nothing to address a sighting by other than the pair it
    joins. Absence of a row is the signal M9.1 reads (ADR-0019 decision 1).

    Column order is `(finding_id, scan_id)` and that is shape rather than
    tuning: it is the primary key, so changing it later is a real migration. It
    serves finding-first lookups; the scan-first query M4.5 and M9.1 need is
    served by an index on `scan_id`, which is additive and ships with the query
    that wants it.
    """

    __tablename__ = "finding_sightings"
    __table_args__ = (
        # FindingSighting.__post_init__'s invariant, enforced again in SQL.
        CheckConstraint("match_count >= 1", name="ck_finding_sightings_match_count"),
    )

    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), primary_key=True)
    # Cross-module, so no FK even though it is half of the primary key.
    scan_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # How many source elements collapsed into this identity in THIS scan — a
    # total, never an increment. See FindingRepositoryPort.record_sighting.
    match_count: Mapped[int] = mapped_column(Integer, nullable=False)
