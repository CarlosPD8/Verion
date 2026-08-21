from dataclasses import dataclass
from enum import StrEnum


class ScanResultStatus(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"


@dataclass(frozen=True)
class ScanResult:
    """One tool's outcome within a scan. A tool that *failed* still gets a row:
    that is what distinguishes "this tool was attempted and failed" from "this
    tool was never enabled", a distinction M4 cannot otherwise make, and it is
    what keeps the (scan_id, tool) upsert idempotent across retries.

    `raw_output` is nullable rather than `""` on failure, deliberately: `""`
    conflates "ran and produced nothing" with "produced nothing because it
    failed", and M4 would have to guess which. The invariant below is enforced
    twice — here, and as a CHECK constraint on the table — so that every row
    `get_succeeded_by_scan_id` returns is guaranteed to carry output, and M4's
    per-scanner mappers can take `str` rather than `str | None`. See ADR-016
    decision 2.

    Prefer the `succeeded`/`failed` constructors over the raw initializer: they
    make the two valid shapes unbuildable-wrongly rather than merely checked.
    """

    id: str
    scan_id: str
    tool: str
    status: ScanResultStatus
    raw_output: str | None
    failure_reason: str | None

    def __post_init__(self) -> None:
        if self.status is ScanResultStatus.SUCCEEDED:
            if self.raw_output is None:
                raise ValueError(
                    f"ScanResult for tool '{self.tool}' is SUCCEEDED but has no raw_output"
                )
            if self.failure_reason is not None:
                raise ValueError(
                    f"ScanResult for tool '{self.tool}' is SUCCEEDED but carries a failure_reason"
                )
        else:
            if self.raw_output is not None:
                raise ValueError(
                    f"ScanResult for tool '{self.tool}' is FAILED but carries raw_output"
                )
            if self.failure_reason is None:
                raise ValueError(
                    f"ScanResult for tool '{self.tool}' is FAILED but has no failure_reason"
                )

    @classmethod
    def succeeded(cls, *, id: str, scan_id: str, tool: str, raw_output: str) -> "ScanResult":
        return cls(
            id=id,
            scan_id=scan_id,
            tool=tool,
            status=ScanResultStatus.SUCCEEDED,
            raw_output=raw_output,
            failure_reason=None,
        )

    @classmethod
    def failed(cls, *, id: str, scan_id: str, tool: str, failure_reason: str) -> "ScanResult":
        return cls(
            id=id,
            scan_id=scan_id,
            tool=tool,
            status=ScanResultStatus.FAILED,
            raw_output=None,
            failure_reason=failure_reason,
        )
