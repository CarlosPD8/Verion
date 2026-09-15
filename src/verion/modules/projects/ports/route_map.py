from typing import Protocol

from verion.modules.projects.domain.route_extraction import RouteMap


class RouteMapPort(Protocol):
    """A project's route map, for `correlation` to derive a source location's route path.

    ADR-0029 decisions 1 and 4. `correlation` never names `RouteMap`: it takes the value by
    inference off this return annotation — the `NormalizeScanUseCase` idiom ADR-0023's
    Decision rests on — and calls `RouteMap.paths_serving` on it, so the span-containment
    rule stays in `projects` (rule 3).

    **Populated since M5.6 commit 4**, at Security Context build time
    (`BuildSecurityContextFromGitHubUseCase`). A project with no stored map reads as
    `RouteMap.not_read(UnreadTree.NOT_BUILT)`, which is empty, so `paths_serving` derives
    nothing for it, and it stays distinguishable from a built map with no routes.
    *(Until commit 4 this port's only adapter was `EmptyRouteMapReader`, and production
    derived no route path at all.)*

    **The map is effectively written once per project** — see `RouteMapRecord` and **G55**.

    **Whatever tree the map came from is not the tree a scanner read** — ADR-0029 decision 3,
    **G52**. A caller must not present a route derived from this map as a fact about the
    scanned revision.

    Async by rule 7: the adapter reads storage.
    """

    async def route_map_for(self, *, project_id: str) -> RouteMap: ...
