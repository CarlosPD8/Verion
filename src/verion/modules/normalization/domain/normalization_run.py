from dataclasses import dataclass
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
    `ScanResult` and `ck_scan_results_outcome_shape` already use. The timestamps
    deliberately are not, in either place: `started_at`/`finished_at` belong to
    transitions M4.4 writes, and pinning them now would constrain a state
    machine this issue does not implement.

    See ADR-0017 decision 1 for why this record exists and who owns it.
    """

    id: str
    scan_id: str
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

    @classmethod
    def requested(cls, *, id: str, scan_id: str, requested_at: datetime) -> "NormalizationRun":
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
            status=NormalizationRunStatus.PENDING,
            requested_at=requested_at,
            started_at=None,
            finished_at=None,
            failure_reason=None,
        )
