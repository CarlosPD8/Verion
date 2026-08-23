from datetime import datetime
from typing import Protocol

from verion.modules.normalization.domain.normalization_run import NormalizationRun


class NormalizationRunRepositoryPort(Protocol):
    async def request(
        self, *, id: str, scan_id: str, project_id: str, requested_at: datetime
    ) -> None:
        """Records that normalization is owed for this scan, idempotently.

        `project_id` is the dedup scope this module cannot reach any other way —
        `get_succeeded_by_scan_id` returns `ScanResult` rows that carry none, and
        the sweep's `WHERE` clause rules out a read port back into `scanning`
        (ADR-0019 decision 7). `RunScanUseCase` already holds `scan.project_id`,
        so passing it costs the caller nothing and keeps the method primitives-
        only, leaving decision 1's boundary exactly where it was.

        **Takes primitives, not a `NormalizationRun`, deliberately.** The caller
        is `scanning`'s `RunScanUseCase`, which may not import this module's
        domain (rule 3, enforced by the `cross-module-scanning` contract). Keeping
        the entity on this side of the boundary is what lets `scanning` write the
        row at all — it learns that normalization is owed, not how this module
        models it.

        This write happens inside the *same transaction* as the `ScanResult`
        rows, which is what removes the Postgres-commit-plus-Redis-enqueue dual
        write: the row is the outbox, and the enqueue is only a latency
        optimization on top of it (ADR-0017 decision 2).

        **A row already existing is the normal, correct outcome of a retry, not
        an error**, so this returns nothing and reports no row count — both
        outcomes mean the same thing. Implementations use
        `ON CONFLICT DO NOTHING` and must never `DO UPDATE`: overwriting would
        reset a running or completed row back to pending and re-normalize a scan
        that was already normalized.
        """
        ...

    async def get_by_scan_id(self, scan_id: str) -> NormalizationRun | None: ...
