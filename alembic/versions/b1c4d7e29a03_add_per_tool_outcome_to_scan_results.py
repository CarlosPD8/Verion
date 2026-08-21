"""add per-tool outcome to scan_results

Revision ID: b1c4d7e29a03
Revises: f9b177a99710
Create Date: 2026-08-21 10:12:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b1c4d7e29a03"
down_revision: str | Sequence[str] | None = "f9b177a99710"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    # server_default backfills every existing row as the success it was — until
    # now a row only ever existed when a scanner returned output. Dropped again
    # immediately below so application code has to state the outcome
    # explicitly; leaving it would make 'succeeded' the silent default for a
    # future insert that forgot the column.
    op.add_column(
        "scan_results",
        sa.Column("status", sa.String(), nullable=False, server_default="succeeded"),
    )
    op.alter_column("scan_results", "status", server_default=None)

    op.add_column("scan_results", sa.Column("failure_reason", sa.String(), nullable=True))

    # Null exactly when the tool failed, which is why it can no longer be NOT
    # NULL. The CHECK below is what keeps that "exactly" true.
    op.alter_column("scan_results", "raw_output", existing_type=sa.String(), nullable=True)

    op.create_check_constraint(
        "ck_scan_results_outcome_shape",
        "scan_results",
        "(status = 'succeeded' AND raw_output IS NOT NULL AND failure_reason IS NULL)"
        " OR (status = 'failed' AND raw_output IS NULL AND failure_reason IS NOT NULL)",
    )


def downgrade() -> None:
    """Downgrade schema.

    Lossy, unavoidably: the pre-M3.7 schema has no way to represent a scanner
    that ran and failed (raw_output was NOT NULL), so those rows are deleted
    rather than being given a fabricated empty output that a reader would
    mistake for a real, empty scan result.
    """
    op.drop_constraint("ck_scan_results_outcome_shape", "scan_results", type_="check")
    op.execute("DELETE FROM scan_results WHERE status = 'failed'")
    op.alter_column("scan_results", "raw_output", existing_type=sa.String(), nullable=False)
    op.drop_column("scan_results", "failure_reason")
    op.drop_column("scan_results", "status")
