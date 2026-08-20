from typing import Protocol

from verion.modules.scanning.domain.scan import Scan


class ScanRepositoryPort(Protocol):
    async def add(self, scan: Scan) -> None: ...

    async def get_by_id(self, scan_id: str) -> Scan | None: ...

    async def update(self, scan: Scan) -> None: ...
