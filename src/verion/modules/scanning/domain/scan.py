from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class ScanStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass(frozen=True)
class Scan:
    id: str
    project_id: str
    status: ScanStatus
    triggered_by: str
    started_at: datetime | None
    finished_at: datetime | None
