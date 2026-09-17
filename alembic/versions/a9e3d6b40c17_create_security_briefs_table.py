"""create security_briefs table

Revision ID: a9e3d6b40c17
Revises: f3c9a1d27b58
Create Date: 2026-09-17 12:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "a9e3d6b40c17"
down_revision: str | Sequence[str] | None = "f3c9a1d27b58"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    # M7.2, ADR-0033. Append-only, so no unique constraint: two rows for one member set are
    # two generations. No foreign key on `project_id` (cross-module) or on `finding_ids`
    # (cross-module, and an ARRAY cannot carry one) — G11.
    op.create_table(
        "security_briefs",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("finding_ids", sa.ARRAY(sa.String()), nullable=False),
        # Versioned JSON: {"version": 1, "decision": {...}}. See SecurityBriefModel.
        sa.Column("decision", postgresql.JSONB(), nullable=False),
        sa.Column("why_it_matters", sa.Text(), nullable=False),
        sa.Column("model", sa.String(), nullable=False),
        sa.Column("prompt_version", sa.String(), nullable=False),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "cardinality(finding_ids) >= 1", name="ck_security_briefs_finding_ids_not_empty"
        ),
    )
    # Shipped with its query, `list_for_project`, as ix_normalization_runs_project_id was.
    op.create_index(
        "ix_security_briefs_project_id",
        "security_briefs",
        ["project_id", sa.text("generated_at DESC")],
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index("ix_security_briefs_project_id", table_name="security_briefs")
    op.drop_table("security_briefs")
