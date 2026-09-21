from typing import Protocol


class BriefGenerationQueuePort(Protocol):
    """Ask for one Brief to be generated. Never the record that it is owed. M8.6, ADR-0038.

    **A port of this module's own**, not a second method on `scanning`'s `JobQueuePort`, for the
    reason `NormalizationQueuePort`'s docstring already gives: the job belongs here, and
    `scanning` publishing an `enqueue_brief_generation` would make it the owner of a stage it
    does not run.

    **Unlike normalization's, losing a message here is NOT recovered.** That port can say a lost
    message is only a latency cost because a sweep collects the row; ADR-0038 decision 11
    declines a sweep on a stated distinction — a normalization run is owed work with no user
    attached, while a generation is user-initiated and the user is already polling it. So a lost
    enqueue leaves a `PENDING` row forever, the poll is what makes that visible, and the recovery
    is the user asking again, which ADR-0033 decision 3 already makes a regeneration rather than
    a no-op. That cost is stated rather than denied, and it **confirms G87**.

    The production implementation defers the real send past the request's commit
    (`platform/db.py`'s `after_commit`), so a 202 means the row exists and the job is queued.
    """

    async def enqueue_brief_generation(self, generation_id: str) -> None: ...
