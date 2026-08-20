from dataclasses import dataclass


@dataclass(frozen=True)
class ScanResult:
    id: str
    scan_id: str
    tool: str
    raw_output: str
