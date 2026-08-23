from typing import Protocol


class NormalizationQueuePort(Protocol):
    """Prompt normalization for a scan. Never the record that it is owed.

    A separate port from `scanning`'s `JobQueuePort` rather than a second method
    on it, because the job belongs to this module: `scanning` publishing a
    `enqueue_normalization` would make it the owner of a stage it does not run,
    and adding a scanner or a stage would then mean editing another module's port
    (rule 4's shape, applied to queues).

    **Losing a message here is not an error, and callers must not treat it as
    one.** The `normalization_runs` row written in the same transaction as the
    `ScanResult` rows is the durable record of owed work; this is a latency
    optimization on top of it, and the reconciliation sweep recovers anything
    dropped (ADR-0017 decision 2). Raising past a caller that has already
    committed would make Redis a correctness dependency of a finished scan.
    """

    async def enqueue_normalization(self, scan_id: str) -> None: ...
