"""create brief_generations table

Revision ID: e4b7c1d90a36
Revises: d8f2a5c61e47
Create Date: 2026-09-21 12:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "e4b7c1d90a36"
down_revision: str | Sequence[str] | None = "d8f2a5c61e47"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    # M8.6, ADR-0038. A table of its own rather than a pending row in `security_briefs`
    # (decision 2), which leaves that table, `SecurityBrief`, ADR-0033 decision 3 and both
    # pinned field-set tests untouched.
    #
    # No foreign key on `project_id` or `user_id` (cross-module, `security_briefs`' precedent),
    # and none on `brief_id` either: it is NULL until `succeeded` and the CHECK below is what
    # governs when it may be set.
    #
    # **No index.** `security_briefs` has one because `list_for_project` exists; nothing lists
    # generations (ADR-0038 puts that out of scope) and the poll addresses one row by id.
    op.create_table(
        "brief_generations",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        # Stored because the JOB re-authorizes with it (decision 4).
        sa.Column("user_id", sa.String(length=36), nullable=False),
        # The caller's REQUESTED set. The engine's members are what a stored Brief carries.
        sa.Column("finding_ids", sa.ARRAY(sa.String()), nullable=False),
        # pending | running | succeeded | failed. A plain String, not a DB enum, so adding a
        # value needs no type migration (security_briefs.confidence's ground).
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("brief_id", sa.String(length=36), nullable=True),
        # surface_changed | provider_unavailable | internal_error. The poll's `detail` is DERIVED
        # from this at the adapter and is not a column, so nothing here can carry provider text.
        sa.Column("failure_kind", sa.String(), nullable=True),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        # **Written, not inherited, and `scans` is not the precedent**: `ScanModel` has no
        # `__table_args__` at all, so its status/failure_reason pairing is a convention nothing
        # enforces. This copies `ck_scan_results_outcome_shape` on `ScanResultModel` — the table
        # in this project that actually has one. ADR-0038 decision 7.
        sa.CheckConstraint(
            "(status IN ('pending','running') AND brief_id IS NULL AND failure_kind IS NULL)"
            " OR (status = 'succeeded' AND brief_id IS NOT NULL AND failure_kind IS NULL)"
            " OR (status = 'failed' AND brief_id IS NULL AND failure_kind IS NOT NULL)",
            name="ck_brief_generations_outcome_shape",
        ),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table("brief_generations")
