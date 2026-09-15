from typing import Protocol

from verion.modules.projects.domain.route_map_record import RouteMapRecord


class RouteMapRepositoryPort(Protocol):
    """Persist and read a project's `RouteMapRecord`. One row per project. M5.6 commit 4.

    `projects`' own persistence port, written by `BuildSecurityContextFromGitHubUseCase`. It is
    not what `correlation` reads: that is `RouteMapPort`, which returns only the `RouteMap`
    and answers for a project with no record.
    """

    async def get_by_project_id(self, project_id: str) -> RouteMapRecord | None: ...

    async def upsert(self, record: RouteMapRecord) -> None: ...
