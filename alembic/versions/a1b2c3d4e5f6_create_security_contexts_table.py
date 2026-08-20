"""create security contexts table

Revision ID: a1b2c3d4e5f6
Revises: 7c9de4c89ae8
Create Date: 2026-08-20 00:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a1b2c3d4e5f6"
down_revision: str | Sequence[str] | None = "7c9de4c89ae8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "security_contexts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("language", sa.String(), nullable=True),
        sa.Column("framework", sa.String(), nullable=True),
        sa.Column("database", sa.String(), nullable=True),
        sa.Column("deployment_target", sa.String(), nullable=True),
        sa.Column("ci_provider", sa.String(), nullable=True),
        sa.Column("exposure_tags", sa.ARRAY(sa.String()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table("security_contexts")
