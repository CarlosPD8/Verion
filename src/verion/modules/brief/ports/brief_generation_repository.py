from typing import Protocol

from verion.modules.brief.domain.brief_generation import (
    BriefGeneration,
    BriefGenerationFailureKind,
)


class BriefGenerationRepositoryPort(Protocol):
    """Persist and read Brief generations. Async by rule 7. M8.6, ADR-0038.

    **Narrow on purpose: there is no list method.** ADR-0038 puts a list of generations out of
    scope, and the poll addresses one row by id. `security_briefs`' index exists because
    `list_for_project` exists; this table ships no index beyond its primary key, for the same
    reason read the other way round.

    **Four writes and one read, and each write is one state transition.** A single `save(row)`
    would let a caller write any state from any other, which is the state machine expressed as a
    convention — the shape decision 7 declines to copy from `scans`. These four are what the job
    needs and nothing else.
    """

    async def add(self, generation: BriefGeneration) -> None:
        """Write the row at `PENDING`, before the job is asked for.

        Called inside the request's transaction, which `get_db_session` commits. The enqueue is
        deferred past that commit by `BriefGenerationQueuePort`'s after-commit wrapper, so a
        worker never takes a job whose row it cannot see (ADR-0035 decision 5).
        """
        ...

    async def claim(self, generation_id: str) -> BriefGeneration | None:
        """Move `PENDING` → `RUNNING` and return the row, or `None` if it was not `PENDING`.

        **Conditional on the current state, so a redelivered job is a no-op rather than a second
        run.** `PostgresNormalizationRunRepository.claim`'s shape, and committed alone in its own
        session for that method's reason: in one transaction `RUNNING` would be written and
        overwritten before anything could observe it.

        **It takes no `now`**, unlike normalization's. That one stamps a start time so its
        **sweep** can judge staleness, and ADR-0038 decision 11 declines the sweep — so there is
        nothing to read a start time, and a column exists here only if something reads it.

        `None` means one of: no such row, already claimed by another worker, or already terminal.
        The job treats all three alike and returns.
        """
        ...

    async def succeed(self, *, generation_id: str, brief_id: str) -> None:
        """`RUNNING` → `SUCCEEDED`, setting `brief_id`.

        `brief_id` is required by the signature and by `ck_brief_generations_outcome_shape`, so
        a succeeded row with nothing to point at cannot be written from here or by raw SQL.
        """
        ...

    async def fail(self, *, generation_id: str, failure_kind: BriefGenerationFailureKind) -> None:
        """`RUNNING` → `FAILED`, setting `failure_kind` and leaving `brief_id` NULL.

        The kind is the enum, never a message: `detail` is derived from it at the adapter and is
        not stored, so no provider text can reach a column (rule 12, decision 6).
        """
        ...

    async def get(self, *, project_id: str, generation_id: str) -> BriefGeneration | None:
        """The row, scoped to the project in the caller's own path.

        Scoped rather than looked up bare so a generation of another project is `None` here and
        indistinguishable from an absent id at the route (**G17**). The actor match is the use
        case's, because it is an authorization rule and not a lookup.
        """
        ...
