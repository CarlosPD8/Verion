"""create normalization_runs table

Revision ID: d4a7c1b8e630
Revises: c2d5e8f31b14
Create Date: 2026-08-23 09:40:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d4a7c1b8e630"
down_revision: str | Sequence[str] | None = "c2d5e8f31b14"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "normalization_runs",
        sa.Column("id", sa.String(length=36), primary_key=True),
        # No ForeignKey to scans.id: scans belongs to `scanning`, and
        # cross-module references go unconstrained at the persistence layer,
        # the same precedent as scans.project_id and projects.owner_id.
        sa.Column("scan_id", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failure_reason", sa.String(), nullable=True),
        sa.UniqueConstraint("scan_id", name="uq_normalization_runs_scan_id"),
        sa.CheckConstraint(
            "status IN ('pending', 'running', 'completed', 'failed')",
            name="ck_normalization_runs_status",
        ),
        sa.CheckConstraint(
            "(status = 'failed' AND failure_reason IS NOT NULL)"
            " OR (status <> 'failed' AND failure_reason IS NULL)",
            name="ck_normalization_runs_failure_reason_shape",
        ),
    )
    # No backfill. Scans that predate this table have no row and will never get
    # one: the sweep selects on this table, so a scan without a row is simply
    # not owed normalization. Backfilling would instead queue every historical
    # scan for a stage that did not exist when they ran. See ADR-0017 decision 3
    # — a row exists iff ScanResult rows were persisted *by a run that knew
    # about this table*.
    #
    # No index on (status, requested_at) either. The sweep that would use one
    # ships with M4.1; indexing ahead of it would be a guess at its shape.


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table("normalization_runs")
