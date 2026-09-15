"""create route_maps table

Revision ID: f3c9a1d27b58
Revises: e7a2c4b81d36
Create Date: 2026-09-15 12:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "f3c9a1d27b58"
down_revision: str | Sequence[str] | None = "e7a2c4b81d36"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "route_maps",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("project_id", sa.String(length=36), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("framework", sa.String(), nullable=True),
        sa.Column("source_archive_commit_sha", sa.String(length=40), nullable=True),
        sa.Column("unread_tree", sa.String(), nullable=True),
        sa.Column("routes", postgresql.JSONB(), nullable=False),
        sa.Column("unresolved_routes", postgresql.JSONB(), nullable=False),
        sa.Column("unparsed_files", sa.ARRAY(sa.String()), nullable=False),
        sa.Column("derived_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("project_id", name="uq_route_maps_project_id"),
        sa.CheckConstraint(
            "unread_tree IS NULL OR unread_tree IN ('fetch_failed', 'malformed', 'too_large')",
            name="ck_route_maps_unread_tree_values",
        ),
        sa.CheckConstraint(
            "unread_tree IS NULL OR source_archive_commit_sha IS NULL",
            name="ck_route_maps_unread_tree_excludes_commit_sha",
        ),
    )
    # No backfill, and none is possible: a route map is derived from a fetched source
    # archive, and a migration has neither a token nor a network. Every project that exists
    # at upgrade time therefore reads as NOT_BUILT.
    #
    # **What that means for those projects is worse than "until their next detect", and it
    # is recorded here because this is where a reader looks.** Every one of them that ran
    # detect before this revision already holds a security_contexts row, so its next detect
    # is a SECOND detect, which writes a duplicate row and breaks that project's context
    # reads (G55). So a pre-existing project cannot obtain a route map without breaking its
    # context reads, until G55 is fixed.


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table("route_maps")
