"""create findings tables and add normalization_runs.project_id

Revision ID: e5b3f7c19d42
Revises: d4a7c1b8e630
Create Date: 2026-08-23 17:10:00.000000

One revision rather than two, deliberately. The three new tables and the new
column on normalization_runs are one logical unit — the persistence layer for the
identity model ADR-0019 decided, of which the dedup scope is a part — and
Postgres runs DDL inside a transaction, so a failure in the backfill below rolls
the table creation back with it rather than leaving a half-built schema.

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "e5b3f7c19d42"
down_revision: str | Sequence[str] | None = "d4a7c1b8e630"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "findings",
        sa.Column("id", sa.String(length=36), primary_key=True),
        # No ForeignKey to projects.id: projects belongs to another module, and
        # cross-module references go unconstrained at the persistence layer too
        # (ADR-0017 decision 1, same precedent as scans.project_id). The visible
        # consequence, stated rather than left to be discovered: nothing at this
        # layer stops a project being deleted out from under its findings.
        sa.Column("project_id", sa.String(length=36), nullable=False),
        # A materialization of Finding.dedup_hash, not a second source of truth:
        # the adapter writes the derived property and no parameter exists through
        # which a caller could supply anything else. Not length-capped —
        # "v1:" + 64 hex is 67 today but the version prefix is a contract that
        # can widen, and nothing queries this by prefix.
        sa.Column("dedup_hash", sa.String(), nullable=False),
        # Identity inputs, in compute_dedup_hash's own parameter order.
        sa.Column("source", sa.String(), nullable=False),
        sa.Column("rule_id", sa.String(), nullable=False),
        sa.Column("file_path", sa.String(), nullable=True),
        sa.Column("package", sa.String(), nullable=True),
        sa.Column("url", sa.String(), nullable=True),
        sa.Column("http_method", sa.String(), nullable=True),
        sa.Column("parameter", sa.String(), nullable=True),
        # Refreshed on every observation: the rule-level attributes plus the
        # three Location fields the hash excludes for positional reasons.
        sa.Column("severity", sa.String(), nullable=False),
        sa.Column("native_severity", sa.String(), nullable=False),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("cwe", sa.String(), nullable=True),
        sa.Column("owasp_category", sa.String(), nullable=True),
        sa.Column("cvss", sa.Float(), nullable=True),
        sa.Column("start_line", sa.Integer(), nullable=True),
        sa.Column("end_line", sa.Integer(), nullable=True),
        sa.Column("installed_version", sa.String(), nullable=True),
        # The scope is the constraint, not a hash input (ADR-0019 decision 3),
        # and this is the upsert's ON CONFLICT target, which is why it is named.
        sa.UniqueConstraint("project_id", "dedup_hash", name="uq_findings_project_id_dedup_hash"),
        sa.CheckConstraint("rule_id <> ''", name="ck_findings_rule_id_present"),
        sa.CheckConstraint("native_severity <> ''", name="ck_findings_native_severity_present"),
        # Vocabulary CHECKs, on the principle that a closed vocabulary is pinned
        # in SQL wherever an unrecognised value would fail at READ time with a
        # blast radius wider than its own row: hydration calls Severity(...) and
        # ScannerTool(...) for every row of a listing. scan_results.tool has no
        # such CHECK because ScanResult.tool is a plain str that is never
        # reconstructed. Spelled out here rather than generated, because a
        # migration is a point-in-time record and must not change meaning when
        # the enum it was written against gains a member.
        sa.CheckConstraint(
            "severity IN ('critical', 'high', 'info', 'low', 'medium', 'unknown')",
            name="ck_findings_severity",
        ),
        sa.CheckConstraint(
            "source IN ('semgrep', 'trivy', 'zap')",
            name="ck_findings_source",
        ),
    )
    op.create_table(
        "evidence",
        sa.Column("id", sa.String(length=36), primary_key=True),
        # FK: both tables belong to `normalization`. No ondelete — nothing
        # deletes a finding today, and choosing CASCADE now would decide M9's
        # retention policy ahead of M9.
        sa.Column("finding_id", sa.String(length=36), nullable=False),
        # Cross-module, so unconstrained, like project_id above.
        sa.Column("scan_id", sa.String(length=36), nullable=False),
        sa.Column("raw_payload", sa.String(), nullable=False),
        sa.Column("source_tool", sa.String(), nullable=False),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"]),
        # Evidence is 1:1 with Finding, and this constraint is what makes that
        # true for any writer rather than only for code that goes through the
        # repository. It is also the evidence upsert's ON CONFLICT target.
        sa.UniqueConstraint("finding_id", name="uq_evidence_finding_id"),
        # Mirrors Evidence.__post_init__'s MAX_RAW_PAYLOAD_CHARS bound.
        sa.CheckConstraint(
            "char_length(raw_payload) <= 20000", name="ck_evidence_raw_payload_length"
        ),
    )
    op.create_table(
        "finding_sightings",
        # Composite natural key, no surrogate id — ProjectMembership's shape.
        sa.Column("finding_id", sa.String(length=36), nullable=False),
        sa.Column("scan_id", sa.String(length=36), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("match_count", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"]),
        sa.PrimaryKeyConstraint("finding_id", "scan_id"),
        sa.CheckConstraint("match_count >= 1", name="ck_finding_sightings_match_count"),
    )
    # No index on finding_sightings.scan_id. The scan-first query it would serve
    # — "which findings were sighted in scan N", and M9.1's absence check —
    # belongs to M4.5 and M9.1, and ships in the migration that carries it, the
    # same way d4a7c1b8e630 left the sweep's partial index to M4.4. Every query
    # M4.3 and M4.4 make is already served by a constraint index above: the
    # upsert by uq_findings_project_id_dedup_hash, whose leading column also
    # serves project-scoped listing; the evidence upsert by
    # uq_evidence_finding_id; the sighting upsert by the primary key.

    # normalization_runs gains the dedup scope (ADR-0019 decision 7). Three
    # steps, not a bare NOT NULL add: rows written before this revision have no
    # project.
    op.add_column(
        "normalization_runs",
        sa.Column("project_id", sa.String(length=36), nullable=True),
    )
    # This is the only place `normalization`'s schema reads `scanning`'s, and it
    # is one-time. Rule 3 governs module code importing another module's domain
    # or adapters; a migration imports neither, and speaks SQL to one shared
    # database at exactly the layer where normalization_runs.scan_id already
    # references scans.id without a foreign key. The alternative does not exist:
    # a data migration that cannot see `scans` cannot backfill, and a
    # normalization -> scanning read port was already rejected because the
    # reconciliation sweep selects on this table alone and a read port cannot
    # serve a WHERE clause (ADR-0019 decision 7).
    op.execute(
        "UPDATE normalization_runs SET project_id = scans.project_id "
        "FROM scans WHERE normalization_runs.scan_id = scans.id"
    )
    # A row that cannot be backfilled HALTS THE DEPLOY, and is never deleted. It
    # cannot exist by construction — the run row is written in the same
    # transaction as a scan that already exists, and nothing deletes scans — so
    # this failing is a genuine anomaly rather than an expected case. Deleting
    # such a row instead would silently discard the durable record of OWED
    # normalization, which is the precise failure ADR-0017's outbox exists to
    # prevent; a halted deploy with the rows intact is strictly better.
    op.alter_column("normalization_runs", "project_id", nullable=False)


def downgrade() -> None:
    """Downgrade schema.

    Dropping project_id is recoverable rather than lossy: the value is derived
    from scans.project_id and re-running the backfill above restores it exactly.
    """
    op.drop_column("normalization_runs", "project_id")
    # Children before parent: both reference findings.id.
    op.drop_table("finding_sightings")
    op.drop_table("evidence")
    op.drop_table("findings")
