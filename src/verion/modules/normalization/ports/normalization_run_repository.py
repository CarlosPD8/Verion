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

    async def claim(self, *, scan_id: str, now: datetime) -> NormalizationRun | None:
        """Take ownership of this scan's run, or report there is nothing to take.

        Returns the `RUNNING` run on success and `None` when the row is missing or
        already `COMPLETED` — the job's "nothing to do here" signal, and the exact
        counterpart of `RunScanUseCase`'s `if scan.status == ScanStatus.COMPLETED:
        return`. It is expressed here rather than in the use case because two
        workers can reach it at once: the sweep re-enqueues, arq retries, and both
        must resolve to one claimant.

        **`PENDING`, `RUNNING` and `FAILED` are all claimable**, so this is not
        only a first-claim. A `FAILED` row has to be re-claimable or arq's retry is
        defeated at the first thing it touches; a `RUNNING` row has to be, or a job
        killed mid-flight could never be recovered by the sweep. `COMPLETED` alone
        stops it.

        Implementations must serialize concurrent claims — the transition
        `NormalizationRun.start` computes is read-modify-write, and two workers
        reading the same `PENDING` row would both believe they claimed it. Unlike
        `FindingRepositoryPort.upsert`, where ADR-0020 decision 2 rejected
        read-modify-write outright, a row lock is available here and carries no
        `IntegrityError` risk: this row always already exists (ADR-0017 decision
        3's invariant), so there is no insert to collide.
        """
        ...

    async def update(self, run: NormalizationRun) -> None:
        """Persist a transitioned run. Identity is `id`; nothing else may change.

        Deliberately takes the entity where `request` takes primitives: that method
        is called by `scanning`, which may not import this module's domain (rule 3).
        This one is called only from inside `normalization`, so the entity — and
        therefore `__post_init__`'s invariants — is on the production write path.
        """
        ...

    async def get_stale(self, *, older_than: datetime, limit: int) -> list[NormalizationRun]:
        """Runs that are owed and are not visibly progressing — the sweep's input.

        **Selects on this table ALONE and must never read `Scan.status`.** ADR-0017
        decision 2 states that as an invariant rather than a query detail: a sweep
        filtering on `scan.status IN (COMPLETED, PARTIAL)` would violate ADR-016
        decision 2 by the back door — the job reads `get_succeeded_by_scan_id`
        correctly while the thing deciding *whether to run the job at all* sits
        downstream of a derived, human-facing summary. It does not need to join
        `ScanResult` either: by decision 3's invariant the row exists **iff**
        `ScanResult` rows were persisted, so the row's existence already carries
        what such a join would establish.

        Ordered oldest-requested-first, so a backlog drains in the order work was
        owed rather than in physical row order.
        """
        ...
