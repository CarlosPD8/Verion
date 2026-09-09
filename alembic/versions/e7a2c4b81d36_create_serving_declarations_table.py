"""create serving_declarations table

Revision ID: e7a2c4b81d36
Revises: d3f8a06c5e11
Create Date: 2026-09-09 10:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "e7a2c4b81d36"
down_revision: str | Sequence[str] | None = "d3f8a06c5e11"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "serving_declarations",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("project_id", sa.String(length=36), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("declared_target_url", sa.String(), nullable=False),
        sa.Column("declared_repo_url", sa.String(), nullable=False),
        sa.Column("declared_default_branch", sa.String(), nullable=False),
        sa.Column("declared_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("declared_by", sa.String(length=36), nullable=False),
        sa.UniqueConstraint("project_id", name="uq_serving_declarations_project_id"),
    )
    # No backfill, and the reason differs from c2d5e8f31b14's. That one had a
    # default to fall back on; this has none by design — ADR-0028 decision 2 makes a
    # declaration in force only if "a row exists for the project", so a project with
    # no row has declared nothing, and inventing one from the current zap_target_url
    # and connected repo would fabricate exactly the human assertion this table
    # exists to record.


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table("serving_declarations")
