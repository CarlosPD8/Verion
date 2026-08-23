"""add normalization_runs timestamp CHECK and the reconciliation sweep's index

Revision ID: b7e4c2a91f05
Revises: e5b3f7c19d42
Create Date: 2026-08-23 20:15:00.000000

Both halves of M4.4's schema change, in one revision because they are one unit:
the state machine that makes `started_at`/`finished_at` mean something, and the
index for the query that reads the states it produces.

**No data migration, and that is checked rather than assumed.** Every row written
before this revision was produced by `NormalizationRunRepository.request`, which
constructs `NormalizationRun.requested()` — `pending`, both timestamps NULL. That
is the first arm of the CHECK below, so every existing row already satisfies it.
Nothing has ever advanced one of these rows: the enqueue, the job and the sweep
are all shipped in this same issue (ADR-0017 decision 2's four deferrals), which
is exactly why no `running`/`completed`/`failed` row can exist yet.

If that turns out to be false in some environment, this migration FAILS rather
than repairing: a row in a shape the domain rejects is a row somebody wrote
around the repository, and silently coercing it would discard the evidence.

"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b7e4c2a91f05"
down_revision: str | Sequence[str] | None = "e5b3f7c19d42"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    # NormalizationRun.__post_init__'s timestamp invariant, enforced again where
    # nothing can route around it — the two-place idiom ADR-016 decision 2
    # established with ck_scan_results_outcome_shape.
    #
    # One clause per status, each an IMPLICATION (`status <> X OR <shape>`)
    # rather than an arm of an exhaustive disjunction. Both forms accept exactly
    # the same rows for the four statuses that exist; they differ only on a
    # status that is none of them, and that difference is the point.
    #
    # A disjunction also rejects an unrecognised status — which sounds stricter
    # and is actually worse, because `ck_normalization_runs_status` already
    # rejects it. A row with a bad status would then violate two constraints at
    # once, Postgres reports whichever it evaluates first, and
    # `test_the_database_rejects_an_unknown_status`'s assertion that the *status*
    # constraint fired would be depending on constraint evaluation order. It
    # passed for that reason before this was rewritten. One constraint, one
    # concern, one test that cannot pass by luck.
    #
    # What the disjunction would have bought — a fifth enum member being rejected
    # until somebody gives it a timestamp rule — is bought instead by
    # `test_every_domain_status_is_accepted_by_the_check_constraint`, which is
    # parametrised over `list(NormalizationRunStatus)`: a new member gets a case
    # automatically, and that case cannot be written without choosing a shape.
    # The same "a partition test makes an unclassified field visible" mechanism
    # ADR-0020 decision 4 relies on.
    #
    # This literal text is the constraint any database actually carries — see
    # `_sql_vocabulary`'s docstring in the models module for why a migration's
    # constraint is a point-in-time record and must not change meaning when a
    # model changes underneath it.
    op.create_check_constraint(
        "ck_normalization_runs_timestamp_shape",
        "normalization_runs",
        "(status <> 'pending' OR (started_at IS NULL AND finished_at IS NULL))"
        " AND (status <> 'running' OR (started_at IS NOT NULL AND finished_at IS NULL))"
        " AND (status NOT IN ('completed', 'failed') OR (started_at IS NOT NULL"
        " AND finished_at IS NOT NULL AND finished_at >= started_at))",
    )

    # The reconciliation sweep's index, in the migration that carries the query
    # it serves (ADR-0017's Consequences, ADR-0020's "an index without its query
    # is a guess"). Partial on the two non-terminal statuses, so it stays
    # proportional to the backlog rather than to scan history: this table grows
    # one row per scan forever, and pending/running rows become a shrinking
    # fraction of it once the sweep starts closing them.
    #
    # The predicate matches PostgresNormalizationRunRepository.get_stale's WHERE
    # exactly. Postgres only uses a partial index when it can prove the query's
    # predicate implies the index's, so a divergence here does not corrupt
    # anything — it silently stops using the index, which is why the two are
    # written to match rather than left to drift.
    op.create_index(
        "ix_normalization_runs_sweep",
        "normalization_runs",
        ["requested_at"],
        postgresql_where="status IN ('pending', 'running')",
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index("ix_normalization_runs_sweep", table_name="normalization_runs")
    op.drop_constraint("ck_normalization_runs_timestamp_shape", "normalization_runs", type_="check")
