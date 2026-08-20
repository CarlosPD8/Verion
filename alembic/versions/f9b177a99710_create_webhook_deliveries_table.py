"""create webhook_deliveries table

Revision ID: f9b177a99710
Revises: f1f03b76e2f2
Create Date: 2026-08-20 17:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f9b177a99710"
down_revision: str | Sequence[str] | None = "f1f03b76e2f2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "webhook_deliveries",
        sa.Column("delivery_id", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("delivery_id"),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table("webhook_deliveries")
