from typing import Protocol

from verion.modules.scanning.domain.raw_scan_result import RawScanResult


class ScannerPort(Protocol):
    async def run(self, repo_path: str) -> RawScanResult:
        """Runs the tool against a local, already-checked-out repo path."""
        ...
