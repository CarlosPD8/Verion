from dataclasses import dataclass, replace
from datetime import datetime
from enum import StrEnum


class NormalizationRunStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass(frozen=True)
class NormalizationRun:
    """Pipeline progress for one Scan's normalization stage — one row per scan.

    Deliberately *not* members on `ScanStatus`: that enum is a derived,
    human-facing summary of per-tool scanner outcomes (ADR-016 decision 2), and
    growing it with pipeline stages would conflate two orthogonal axes that
    multiply out again at M5, M6 and M7.

    `failure_reason` belongs here and never on `Scan.failure_reason`, which
    keeps the disjoint meaning ADR-016 decision 2 gave it — a failure *before
    any tool ran*. A normalization failure is neither a scanner outcome nor a
    pre-tool failure, so overloading that field would make it mean two
    unrelated things depending on which stage wrote it.

    The status/`failure_reason` invariant below is enforced twice — here, and as
    a CHECK constraint on the table — the same defensive-constraint idiom
    `ScanResult` and `ck_scan_results_outcome_shape` already use. **As of M4.4 the
    timestamps are enforced the same way, in both places**, which is what M4.3's
    note here was holding open: they belong to transitions, and the transitions
    now exist (`start`/`complete`/`fail` below).

    **`COMPLETED` is the only terminal state, and that is load-bearing rather than
    lax.** `PENDING`, `RUNNING` and `FAILED` are all re-claimable. A `FAILED` row
    has to be, or arq's own retry is defeated at the first thing it touches: the
    job writes `FAILED` and re-raises for a transient failure, and the retry would
    then find a row it is not allowed to claim. The symmetry with
    `RunScanUseCase`'s `if scan.status == ScanStatus.COMPLETED: return` is
    deliberate — same rule, one stage over.

    `project_id` is the **dedup scope**, not decoration. Findings dedup within a
    project (`UNIQUE(project_id, dedup_hash)`), and `normalization` can reach a
    project through none of its other inputs: `get_succeeded_by_scan_id` returns
    `ScanResult` rows, which carry none. A read port back into `scanning` cannot
    serve it either, because decision 2 fixes the reconciliation sweep as
    selecting on this table alone and a read port cannot serve a `WHERE` clause.
    So the handoff row carries it. See ADR-0019 decision 7.

    See ADR-0017 decision 1 for why this record exists and who owns it.
    """

    id: str
    scan_id: str
    project_id: str
    status: NormalizationRunStatus
    requested_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    failure_reason: str | None

    def __post_init__(self) -> None:
        if self.status is NormalizationRunStatus.FAILED:
            if self.failure_reason is None:
                raise ValueError(
                    f"NormalizationRun for scan '{self.scan_id}' is FAILED but has no "
                    f"failure_reason"
                )
        elif self.failure_reason is not None:
            raise ValueError(
                f"NormalizationRun for scan '{self.scan_id}' is {self.status.upper()} but "
                f"carries a failure_reason"
            )

        # Stated per status rather than as a set of implications, deliberately:
        # an exhaustive table cannot leave a status unconstrained by omission,
        # which is how `RUNNING` would otherwise have kept accepting a
        # `finished_at`. Same exhaustive shape as the failure_reason guard above.
        expected_started = self.status is not NormalizationRunStatus.PENDING
        expected_finished = self.status in (
            NormalizationRunStatus.COMPLETED,
            NormalizationRunStatus.FAILED,
        )
        if (self.started_at is not None) is not expected_started:
            raise ValueError(
                f"NormalizationRun for scan '{self.scan_id}' is {self.status.upper()} but "
                f"started_at is {'set' if self.started_at is not None else 'None'} — only a "
                f"PENDING run has no start time"
            )
        if (self.finished_at is not None) is not expected_finished:
            raise ValueError(
                f"NormalizationRun for scan '{self.scan_id}' is {self.status.upper()} but "
                f"finished_at is {'set' if self.finished_at is not None else 'None'} — only "
                f"a COMPLETED or FAILED run has an end time"
            )
        if (
            self.started_at is not None
            and self.finished_at is not None
            and self.finished_at < self.started_at
        ):
            raise ValueError(
                f"NormalizationRun for scan '{self.scan_id}' finished at {self.finished_at}, "
                f"before it started at {self.started_at}"
            )

    @classmethod
    def requested(
        cls, *, id: str, scan_id: str, project_id: str, requested_at: datetime
    ) -> "NormalizationRun":
        """The only state the scan → normalize handoff produces.

        Called by this module's own adapter, never by `scanning`: the port
        `scanning` writes through takes primitives only, precisely because
        `RunScanUseCase` may not import another module's domain (rule 3). Every
        later transition is normalization's own, so this is the sole
        constructor the handoff needs.
        """
        return cls(
            id=id,
            scan_id=scan_id,
            project_id=project_id,
            status=NormalizationRunStatus.PENDING,
            requested_at=requested_at,
            started_at=None,
            finished_at=None,
            failure_reason=None,
        )

    def start(self, now: datetime) -> "NormalizationRun":
        """Claim this run. Legal from every state except COMPLETED.

        `started_at` is set on the FIRST claim only, mirroring
        `RunScanUseCase`'s `scan.started_at or self._clock.now()` — a retry must
        not overwrite the original start time.

        **Re-claiming a FAILED run clears `failure_reason`, and it has to**: a
        RUNNING row carrying one is rejected by `__post_init__` and by
        `ck_normalization_runs_failure_reason_shape`. So the reason for the
        previous attempt's failure does not survive into this attempt — which is
        correct (it describes an attempt that is over) and is also why a caller
        wanting failure history would need a second table rather than this field.
        """
        if self.status is NormalizationRunStatus.COMPLETED:
            raise ValueError(
                f"NormalizationRun for scan '{self.scan_id}' is already COMPLETED and cannot "
                f"be started again — completed is the only terminal state"
            )
        return replace(
            self,
            status=NormalizationRunStatus.RUNNING,
            started_at=self.started_at or now,
            finished_at=None,
            failure_reason=None,
        )

    def complete(self, now: datetime) -> "NormalizationRun":
        """Normalization finished. Legal only from RUNNING.

        Reached for a PARTIAL scan and for a scan whose every tool failed alike:
        this status is about NORMALIZATION, never about the scan. Zero findings
        from zero succeeded results is a completed run, not a failed one
        (ADR-0017 decision 3).
        """
        self._require_running("completed")
        return replace(self, status=NormalizationRunStatus.COMPLETED, finished_at=now)

    def fail(self, now: datetime, reason: str) -> "NormalizationRun":
        """Normalization failed. Legal only from RUNNING.

        `reason` must be non-empty — a FAILED row with no reason is rejected by
        `__post_init__`, and an empty string would satisfy the `IS NOT NULL` CHECK
        while telling a reader nothing.
        """
        self._require_running("failed")
        if not reason:
            raise ValueError(
                f"NormalizationRun for scan '{self.scan_id}' cannot be failed with an empty "
                f"reason — record what went wrong, the same way native_severity records what "
                f"a tool actually said"
            )
        return replace(
            self,
            status=NormalizationRunStatus.FAILED,
            finished_at=now,
            failure_reason=reason,
        )

    def _require_running(self, target: str) -> None:
        if self.status is not NormalizationRunStatus.RUNNING:
            raise ValueError(
                f"NormalizationRun for scan '{self.scan_id}' is {self.status.upper()} and "
                f"cannot go straight to {target} — a run is claimed before it produces an "
                f"outcome, so every terminal transition comes from RUNNING"
            )
