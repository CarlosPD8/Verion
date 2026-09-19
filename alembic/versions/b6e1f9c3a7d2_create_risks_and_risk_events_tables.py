"""create risks and risk_events tables

Revision ID: b6e1f9c3a7d2
Revises: c5d2e8f41a93
Create Date: 2026-09-19 12:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b6e1f9c3a7d2"
down_revision: str | Sequence[str] | None = "c5d2e8f41a93"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    # M8.1, ADR-0036. A dismissal record: identity columns only, written once, never updated
    # (G37). No foreign key on `project_id` (cross-module) or on `finding_ids` (cross-module, and
    # an ARRAY cannot carry one): G11.
    op.create_table(
        "risks",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("finding_ids", sa.ARRAY(sa.String()), nullable=False),
        sa.CheckConstraint("cardinality(finding_ids) >= 1", name="ck_risks_finding_ids_not_empty"),
    )
    op.create_index("ix_risks_project_id", "risks", ["project_id"])

    # Append-only. `ordinal` is the order, and the unique constraint is what makes two
    # concurrent appends collide. The reason is required for a dismissal, never blank, and at
    # most 2,000 characters, the figure `RiskEvent` also enforces.
    op.create_table(
        "risk_events",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("risk_id", sa.String(length=36), sa.ForeignKey("risks.id"), nullable=False),
        sa.Column("ordinal", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("actor_user_id", sa.String(length=36), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("risk_id", "ordinal", name="uq_risk_events_risk_id_ordinal"),
        sa.CheckConstraint("ordinal >= 1", name="ck_risk_events_ordinal_positive"),
        sa.CheckConstraint("kind IN ('dismissed', 'undismissed')", name="ck_risk_events_kind"),
        sa.CheckConstraint(
            "kind <> 'dismissed' OR reason IS NOT NULL", name="ck_risk_events_dismissal_has_reason"
        ),
        # `btrim` strips only the characters it is given: the domain's ASCII whitespace set.
        sa.CheckConstraint(
            "reason IS NULL OR btrim(reason, E' \\t\\n\\r\\x0B\\f') <> ''",
            name="ck_risk_events_reason_not_blank",
        ),
        sa.CheckConstraint(
            "reason IS NULL OR char_length(reason) <= 2000", name="ck_risk_events_reason_length"
        ),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table("risk_events")
    op.drop_index("ix_risks_project_id", table_name="risks")
    op.drop_table("risks")
