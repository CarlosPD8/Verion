"""add the project-scoped index normalization_runs' read queries need

Revision ID: c8d1a4f70b26
Revises: b7e4c2a91f05
Create Date: 2026-08-23 22:40:00.000000

M4.5's only schema change: one index, no table, no column, no data.

**It ships here because its queries ship here** — ADR-0017's "an index without its
query is a guess at that query's shape", which is also why `ix_normalization_runs_sweep`
waited for M4.4 and why `ix_finding_sightings_scan_id` is deliberately NOT in this
revision. `GET /projects/{id}/findings` surfaces normalization state so a caller can
tell "this project is clean" from "this project's last three scans were never
normalized" (G15), and that needs two queries `normalization_runs` had no index for:

    get_latest_by_project_id       WHERE project_id = ? ORDER BY requested_at DESC LIMIT 1
    count_unfinished_by_project_id WHERE project_id = ? AND status <> 'completed'

Both were seq scans over the whole table before this, on a table that grows one row
per scan forever.

**Not partial, unlike the sweep's index on the same table**, and the contrast is
worth stating because they look like they should match. The sweep only ever asks
about `pending`/`running` rows, so restricting its index to those keeps it
proportional to the backlog. This one has to answer "the latest run" for a project
whose runs are ALL completed — the ordinary, healthy case — so the same predicate
would exclude exactly the rows it is for.

`ix_finding_sightings_scan_id` is not here, and ADR-0020 named M4.5 as one of the two
issues that might carry it. It does not, because this endpoint has no scan-first
query: the per-finding sighting summary is a LATERAL correlated to one finding at
a time, served by the sightings primary key's leading column. It ships with
M9.1's absence check, in the migration carrying the query that wants it. See
ADR-0022.

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c8d1a4f70b26"
down_revision: str | Sequence[str] | None = "b7e4c2a91f05"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    # (project_id, requested_at DESC). The column order is what makes one index
    # serve both queries: `project_id` leading serves the count's equality filter,
    # and `requested_at DESC` after it lets the latest-run query take the first
    # matching entry without a sort.
    op.create_index(
        "ix_normalization_runs_project_id",
        "normalization_runs",
        ["project_id", sa.text("requested_at DESC")],
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index("ix_normalization_runs_project_id", table_name="normalization_runs")
