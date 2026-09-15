from typing import Protocol

from verion.modules.projects.domain.route_extraction import RouteMap


class RouteMapPort(Protocol):
    """A project's route map, for `correlation` to derive a source location's route path.

    ADR-0029 decisions 1 and 4. `correlation` never names `RouteMap`: it takes the value by
    inference off this return annotation — the `NormalizeScanUseCase` idiom ADR-0023's
    Decision rests on — and calls `RouteMap.paths_serving` on it, so the span-containment
    rule stays in `projects` (rule 3).

    **Production returns an EMPTY map until M5.6 commit 4.** Commit 3 ships this port, its
    consumer and the gate in front of it; commit 4 populates the map at Security Context
    build time and replaces the placeholder adapter. Between the two, production derives no
    route path for any finding, so no derived SAST↔DAST group exists outside the unit suite.
    ADR-0029's 2026-09-15 amendment records the decision and **G27** stays assigned to
    commit 4 on that ground.

    **Whatever tree the map came from is not the tree a scanner read** — ADR-0029 decision 3,
    **G52**. A caller must not present a route derived from this map as a fact about the
    scanned revision.

    Async by rule 7: the populated adapter reads storage.
    """

    async def route_map_for(self, *, project_id: str) -> RouteMap: ...
