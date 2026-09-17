"""add what_happened to security_briefs

Revision ID: c5d2e8f41a93
Revises: a9e3d6b40c17
Create Date: 2026-09-17 18:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c5d2e8f41a93"
down_revision: str | Sequence[str] | None = "a9e3d6b40c17"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    # M7.3, ADR-0034 decision 3. The second narration of a Brief and its producer. Nullable, and
    # NOT backfilled: every existing row predates M7.3, and a narration is a billed call over a
    # decision that may have moved since. The check makes the three columns all-or-none.
    op.add_column("security_briefs", sa.Column("what_happened", sa.Text(), nullable=True))
    op.add_column("security_briefs", sa.Column("what_happened_model", sa.String(), nullable=True))
    op.add_column(
        "security_briefs", sa.Column("what_happened_prompt_version", sa.String(), nullable=True)
    )
    op.create_check_constraint(
        "ck_security_briefs_what_happened_all_or_none",
        "security_briefs",
        "(what_happened IS NULL) = (what_happened_model IS NULL)"
        " AND (what_happened IS NULL) = (what_happened_prompt_version IS NULL)",
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_constraint(
        "ck_security_briefs_what_happened_all_or_none", "security_briefs", type_="check"
    )
    op.drop_column("security_briefs", "what_happened_prompt_version")
    op.drop_column("security_briefs", "what_happened_model")
    op.drop_column("security_briefs", "what_happened")
