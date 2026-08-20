"""add failure_reason to scans

Revision ID: f1f03b76e2f2
Revises: 2cefe3ced4c9
Create Date: 2026-08-20 16:31:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f1f03b76e2f2"
down_revision: str | Sequence[str] | None = "2cefe3ced4c9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column("scans", sa.Column("failure_reason", sa.String(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("scans", "failure_reason")
