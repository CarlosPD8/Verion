from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class ScanStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    # Some enabled tools succeeded and some failed (ADR-016 decision 2).
    # PRODUCT_SPEC.md §12 requires surviving "ZAP times out but Semgrep
    # succeeds" without corrupting state; a blanket FAILED here would discard
    # the succeeding scanner's output, which is that corruption.
    PARTIAL = "partial"
    FAILED = "failed"


@dataclass(frozen=True)
class Scan:
    """`status` and `failure_reason` are a *summary* of the scan, derived from
    the per-tool outcomes on ScanResult once every scanner has returned. They
    are not the source of truth for what is safe to normalize — M4 asks
    `ScanResultRepositoryPort.get_succeeded_by_scan_id` instead, so a
    human-facing summary field can never become a pipeline's input (ADR-016
    decision 2).

    `failure_reason` keeps exactly the meaning M3.3 gave it and is not
    overloaded by PARTIAL: it records a failure that happened *before any tool
    ran* — no connected repo, no GitHub connection, an unsupported provider, a
    failed checkout — in which case no ScanResult rows exist at all. On
    PARTIAL it stays None, and the per-tool failure_reason fields carry the
    detail.
    """

    id: str
    project_id: str
    status: ScanStatus
    triggered_by: str
    started_at: datetime | None
    finished_at: datetime | None
    failure_reason: str | None
