"""add active-scan consent to scanner_configs

Revision ID: d3f8a06c5e11
Revises: c8d1a4f70b26
Create Date: 2026-08-27 11:20:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d3f8a06c5e11"
down_revision: str | Sequence[str] | None = "c8d1a4f70b26"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "scanner_configs",
        sa.Column("active_scan_consent_target", sa.String(), nullable=True),
    )
    op.add_column(
        "scanner_configs",
        sa.Column("active_scan_consent_granted_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "scanner_configs",
        sa.Column("active_scan_consent_granted_by", sa.String(length=36), nullable=True),
    )
    # No backfill, and unlike c2d5e8f31b14's no-backfill note this one needs no
    # default to fall back on: three NULLs is exactly "no consent", which is the
    # answer ADR-0024 decision 2 gives for a project that never granted any. So
    # every existing row is correct the moment this runs, and an active scan
    # cannot be reached by any of them.


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("scanner_configs", "active_scan_consent_granted_by")
    op.drop_column("scanner_configs", "active_scan_consent_granted_at")
    op.drop_column("scanner_configs", "active_scan_consent_target")
