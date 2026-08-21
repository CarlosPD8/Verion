"""create scanner_configs table

Revision ID: c2d5e8f31b14
Revises: b1c4d7e29a03
Create Date: 2026-08-21 10:14:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c2d5e8f31b14"
down_revision: str | Sequence[str] | None = "b1c4d7e29a03"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "scanner_configs",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("project_id", sa.String(length=36), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("enabled_tools", sa.ARRAY(sa.String()), nullable=False),
        sa.Column("zap_target_url", sa.String(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("project_id", name="uq_scanner_configs_project_id"),
    )
    # No backfill. A project with no row here is "never configured", which
    # resolve_enabled_tools answers with the default (Semgrep + Trivy) — so
    # every project that predates this table works immediately, with no rows to
    # keep in sync and nothing to go stale. See ADR-016 decision 3.


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table("scanner_configs")
