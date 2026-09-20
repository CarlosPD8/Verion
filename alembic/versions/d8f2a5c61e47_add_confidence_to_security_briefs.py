"""add confidence to security_briefs

Revision ID: d8f2a5c61e47
Revises: b6e1f9c3a7d2
Create Date: 2026-09-20 12:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d8f2a5c61e47"
down_revision: str | Sequence[str] | None = "b6e1f9c3a7d2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    # M8.5, ADR-0037 decision 8. FR-8's fourth part: the surface's grouping provenance as the
    # engine computed it, stored because the map it describes can be rebuilt under it (G93).
    #
    # Nullable and NOT backfilled, on `c5d2e8f41a93`'s precedent for `what_happened`: every
    # existing row predates M8.5, and there is nothing to compute a value from — the surface a
    # stored Brief describes may have moved since it was narrated. NULL therefore has exactly
    # one meaning, "written before M8.5", and generation never writes it.
    #
    # A plain String rather than a DB enum: `Confidence` is `shared_kernel`'s vocabulary, and
    # adding a value to it must not require a type migration. The domain and the repository
    # are what keep the column honest — `Confidence(...)` reconstructs on read and raises on
    # an unrecognised value.
    #
    # No CHECK constraint: one column, with nothing to be all-or-none with, unlike the three
    # `what_happened` columns that migration had to pair.
    op.add_column("security_briefs", sa.Column("confidence", sa.String(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("security_briefs", "confidence")
