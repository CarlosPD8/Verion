from typing import Protocol


class JobQueuePort(Protocol):
    async def enqueue_scan(self, scan_id: str) -> None: ...
