from typing import Protocol

from verion.modules.projects.domain.scanner_config import ScannerConfig


class ScannerConfigRepositoryPort(Protocol):
    async def get_by_project_id(self, project_id: str) -> ScannerConfig | None:
        """None means "never configured", which is not "nothing enabled" — an
        empty `enabled_tools` is the latter. `scanning`'s
        `domain/scanner_dispatch.py::resolve_enabled_tools` is the single place
        that distinguishes them and supplies the default for the former."""
        ...

    async def upsert(self, config: ScannerConfig) -> None:
        """Inserts, or replaces the existing row for the same project_id.

        Upsert rather than add/update, because there is exactly one row per
        project and a caller updating configuration should not have to know
        whether the project has ever been configured before.
        """
        ...
