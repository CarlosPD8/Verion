from dataclasses import dataclass


@dataclass(frozen=True)
class RawScanResult:
    tool: str
    raw_output: str
