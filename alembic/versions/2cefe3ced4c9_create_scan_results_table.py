"""create scan_results table

Revision ID: 2cefe3ced4c9
Revises: 9fafbe6b7393
Create Date: 2026-08-20 16:30:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "2cefe3ced4c9"
down_revision: str | Sequence[str] | None = "9fafbe6b7393"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "scan_results",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("scan_id", sa.String(length=36), nullable=False),
        sa.Column("tool", sa.String(), nullable=False),
        sa.Column("raw_output", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(
            ["scan_id"],
            ["scans.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id", "tool", name="uq_scan_results_scan_id_tool"),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table("scan_results")
