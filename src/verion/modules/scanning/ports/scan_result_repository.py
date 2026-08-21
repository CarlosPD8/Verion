from typing import Protocol

from verion.modules.scanning.domain.scan_result import ScanResult


class ScanResultRepositoryPort(Protocol):
    async def upsert(self, scan_result: ScanResult) -> None:
        """Inserts, or replaces the existing row for the same (scan_id, tool)
        so a redelivered/retried job never produces a duplicate row.

        Replaces status/raw_output/failure_reason together, not raw_output
        alone: a retry that turns a previously-succeeding tool into a failing
        one must not leave the old output behind under a FAILED status.
        """
        ...

    async def get_by_scan_id(self, scan_id: str) -> list[ScanResult]: ...

    async def get_succeeded_by_scan_id(self, scan_id: str) -> list[ScanResult]:
        """Only the results that are safe to consume — this is M4's entry point.

        M4 must be able to tell exactly which raw results it can trust, and it
        answers that by asking this rather than by reading Scan.status (a
        derived, human-facing summary) or by filtering get_by_scan_id by hand.
        Every result returned here is guaranteed to carry non-null raw_output,
        by ScanResult's own invariant and by the table's CHECK constraint —
        which is what lets a normalizer take `str`, not `str | None`.
        """
        ...
