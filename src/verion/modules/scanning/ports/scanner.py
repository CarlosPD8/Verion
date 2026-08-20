from typing import Protocol

from verion.modules.scanning.domain.raw_scan_result import RawScanResult


class ScannerPort(Protocol):
    async def run(self, target: str) -> RawScanResult:
        """Runs the tool and returns its raw output.

        `target` means different things per adapter — a local, already-
        checked-out filesystem path for repo-based scanners (SemgrepAdapter,
        TrivyAdapter), or a live target URL for a scanner that attacks a
        running application (ZapAdapter). Each adapter documents which one
        it expects.
        """
        ...
