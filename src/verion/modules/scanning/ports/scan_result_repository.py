from typing import Protocol

from verion.modules.scanning.domain.scan_result import ScanResult


class ScanResultRepositoryPort(Protocol):
    async def upsert(self, scan_result: ScanResult) -> None:
        """Inserts, or replaces the existing row for the same (scan_id, tool)
        so a redelivered/retried job never produces a duplicate row."""
        ...

    async def get_by_scan_id(self, scan_id: str) -> list[ScanResult]: ...
