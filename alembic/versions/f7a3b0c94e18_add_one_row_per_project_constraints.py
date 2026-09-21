"""add one-row-per-project constraints to connected_repos and security_contexts

Revision ID: f7a3b0c94e18
Revises: e4b7c1d90a36
Create Date: 2026-09-21 16:30:00.000000

M8.7, ADR-0039. The two one-per-project relations in `projects` that never got a
constraint: a second write added a second row, after which every read of that project
raised `MultipleResultsFound`. G51 (scanning stops, and the failure lands on the pipeline
rather than on the route that caused it) and G55 (the route map freezes at the project's
first detect and a failed archive fetch is permanent).

**The constraints go on BARE. No dedupe, and that answers the question rather than
deferring it** — ADR-0039 decision 7. The answer is: this upgrade fails, and whoever
holds duplicate rows decides then, with the data in front of them. That is the right
behaviour for a state nobody can know in advance, and it discharges the second of the
four things G55's deferral rationale says the fix needs.

A dedupe was refused on a measurement rather than a preference: **`connected_repos`
carries no time column at all**, so a survivor would be chosen by `id` or by `ctid` —
deleting a row that may hold the only URL the project has, by physical insertion order.
A migration does not do that on its own. The fact outlives this revision: if a dedupe is
ever needed there, no non-arbitrary way to do one exists.

**The precedent inverts rather than transfers.** `c2d5e8f31b14` argued why it backfilled
no *absent* rows; this argues why it deletes no *excess* ones. Same shape, opposite sign.

**Measured, not predicted** (M8.7 commit 1, 2026-09-21): against a scratch database at
`e4b7c1d90a36` carrying two rows per table for one project, these two statements returned

    ERROR:  could not create unique index "uq_connected_repos_project_id"
    DETAIL:  Key (project_id)=(p-1) is duplicated.

    ERROR:  could not create unique index "uq_security_contexts_project_id"
    DETAIL:  Key (project_id)=(p-1) is duplicated.

`pg_constraint` held neither afterwards, so nothing applies partially; deleting one
duplicate per table and re-running both succeeded, which separates *refused because of
the data* from *refused because the statement was wrong*. That harness is not committed:
it is a record of one run, not a re-runnable claim. **What is measured is the `ALTER`'s
refusal; that `alembic upgrade` fails is inferred from it**, because on an existing table
Alembic can only emit that same `ALTER`.

At the time of writing both tables held 0 rows and no deployment existed.
"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f7a3b0c94e18"
down_revision: str | Sequence[str] | None = "e4b7c1d90a36"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    # Named so the repositories' ON CONFLICT can target them by name, and named the same
    # in both models — `test_schema_matches_models` compares the two sets in both
    # directions, so a name here and not there fails the suite.
    op.create_unique_constraint("uq_connected_repos_project_id", "connected_repos", ["project_id"])
    op.create_unique_constraint(
        "uq_security_contexts_project_id", "security_contexts", ["project_id"]
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_constraint("uq_security_contexts_project_id", "security_contexts", type_="unique")
    op.drop_constraint("uq_connected_repos_project_id", "connected_repos", type_="unique")
