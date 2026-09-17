from verion.modules.correlation.application.match_key_builder import build_match_key
from verion.modules.correlation.domain.exceptions import ProjectAccessDenied
from verion.modules.correlation.domain.matching import MatchGroup, group_by_match_key

# `normalization`'s PORT, never its domain or adapters — the legality ADR-0023's
# Decision rests on, and the reason `cross-module-correlation` sets
# allow_indirect_imports. The port's signatures name `Finding`; this module never
# does, and takes the type by inference at the call site below.
from verion.modules.normalization.ports.finding_repository import FindingRepositoryPort

# `projects`' PORT, and note WHICH port: ProjectAccessPort, not
# ProjectMembershipRepositoryPort. The second is contract-legal too and is the wrong
# one — it is a persistence port, so reading it would mean this module knowing that
# authorization means "a membership row exists", which is `projects`' domain knowledge
# crossing a boundary through a repository, and one copy of an authorization rule per
# consuming module. This port hands over the verdict instead. ADR-0022 decision 2, and
# the same choice ListProjectFindingsUseCase made for the same reason.
from verion.modules.projects.ports.project_access import ProjectAccessPort

# Two more of `projects`' PORTS (M5.6 commit 3), and the same choice again: verdict and value,
# never the persistence ports behind them. `ServingDeclarationPort` crosses a bool, so the
# in-force rule stays `projects`' (ADR-0028 decision 4). `RouteMapPort` crosses a map whose
# type this module never names, and whose containment query is a method on that map, so the
# span rule stays `projects`' too (ADR-0029 decision 1).
from verion.modules.projects.ports.route_map import RouteMapPort
from verion.modules.projects.ports.serving_declaration import ServingDeclarationPort


class CorrelateFindingsUseCase:
    """Group a project's findings into candidate Risks.

    **Per-project, not per-scan** — M5.8's criterion (a), decided in ADR-0023's
    2026-08-26 amendment before any matching code existed, on four grounds: it is the
    scope `Finding` itself has (durable and project-scoped by ADR-0019 decision 1), the
    scope M5.1's measured grouping has, the one whose alternative costs M9.1's four
    acceptance criteria rather than a `WHERE` clause, and the only one a completeness
    envelope exists for today. So M9.1's criteria stay out of this issue.

    **The inherited exposure, in the words the existing code already uses rather than
    discovered later:** this groups findings that may have been fixed three scans ago,
    because resolution detection is M9.1's. `ListProjectFindingsUseCase` carries the same
    exposure and already documents it — it "exposes when a finding was last seen and never
    whether it is still present". Correlation inherits that sentence unchanged rather than
    adding to it.

    **What this use case deliberately does NOT do about completeness, and why — because a
    silent omission and a decision look identical afterwards.** `ListProjectFindingsUseCase`
    carries `latest_run` and `unfinished_runs` because a project whose last three scans
    failed to normalize returns a short list otherwise indistinguishable from a clean
    project (G15). The exposure here is real and is one layer worse — a Risk is only as
    complete as the findings it correlated, so an unrecovered normalization can make a Risk
    look fully evidenced while a constituent finding was never produced. It is still not
    answered here: this returns groups, not a response, and there is no envelope for the
    admission to live in. Assembling one would mean deciding what a *Risk listing* admits,
    which is **M5.2**'s — G15's own post-M4 note names it as the second consumer that has
    to decide that. The two ports are callable from this layer, so M5.2 inherits the
    ability and not a rewrite.

    Does not persist and does not decide resolution (M9.1). **Nothing persists a candidate Risk**
    — ADR-0025 decision 1 makes it a projection, and decision 2 puts the first forced write at
    M8.1, the first issue with a value that cannot be recomputed and must stay attached to a
    Risk when its membership changes (ADR-0025's 2026-09-17 amendment; M7.2's stored Brief is
    an earlier value that cannot be recomputed, and writes no Risk). *(This line named M5.2 as the
    issue that would persist, until that issue decided not to.)*
    """

    def __init__(
        self,
        project_access: ProjectAccessPort,
        findings: FindingRepositoryPort,
        serving: ServingDeclarationPort,
        route_maps: RouteMapPort,
    ) -> None:
        self._project_access = project_access
        self._findings = findings
        self._serving = serving
        self._route_maps = route_maps

    async def execute(self, *, project_id: str, user_id: str) -> list[MatchGroup]:
        """Authorize first, then read, then gate the derivation. Both orders are properties.

        The access check is the first statement, before any repository is touched — the
        gate placement ADR-0013 established for the SSRF validators and for the same
        reason: a check that runs after a read is a check a refactor can move without
        anything failing. A fake repository that raises when touched pins it.

        Reads `get_by_project_id` rather than `list_for_project`, and the difference is
        the point rather than an accident of which method was to hand: correlation wants
        every finding in the project, unfiltered and unpaged, while the listing carries
        M4.5's display policy — a severity rank order, a filter vocabulary and a page
        bound, none of which correlation should inherit. It also does not require the
        sighting invariant, so nothing here depends on the read path's join.

        **The derivation gate — M5.6's acceptance criterion, moved there from M5.5 by
        ADR-0028 decision 0: a derived SAST↔DAST group is not produced when the project's
        serving declaration is absent or out of force.** The route map is not even READ in
        that case — the derivation is not attempted, rather than produced and discarded — so
        an undeclared project spends no tree read, and a route map that raises when touched
        pins the order. The ZAP path re-key in `build_match_key` is NOT behind this gate: it
        is a property of the key, not of whether comparing two tools is founded.

        **What a group this gate admits means, and it is narrower than it looks** (ADR-0029
        decision 3, ADR-0028 decision 2). It means: a person declared that the scanned URL
        serves the connected repository and branch, and none of those three values has been
        edited since; and the route path exists in the route map's tree, with the finding's
        line inside that route's span there. It does **not** mean the deployment runs the
        code Semgrep read — the declaration voids on reconfiguration and never on drift,
        **G47** — and it does **not** mean the tree Semgrep scanned defined this route,
        because the map is derived from a tree no scanner read, **G52**. It never means the
        two findings are about one system. Acceptance is that a group is WITHHELD without a
        declaration, not that an admitted group is true.

        *(Until M5.6 commit 4 production's route map was empty, so this gate opened onto
        nothing outside the unit suite. Since commit 4 the map is stored at Security Context
        build and read through `PostgresRouteMapReader`, so the gate opens onto a real map in
        production; `tests/integration/test_derived_group_end_to_end.py` is the evidence. See
        `RouteMapPort`.)*
        """
        if not await self._project_access.may_read_project(project_id=project_id, user_id=user_id):
            # One message for both "no such project" and "not a member". The port cannot
            # tell them apart and neither should this — see ProjectAccessDenied.
            raise ProjectAccessDenied(f"No readable project with id '{project_id}'")

        findings = await self._findings.get_by_project_id(project_id)

        paths_serving = None
        if await self._serving.url_serves_scanned_tree(project_id=project_id):
            route_map = await self._route_maps.route_map_for(project_id=project_id)
            # The bound method, typed by inference off the port's return annotation and
            # checked against `PathsServing` at this assignment's use below.
            paths_serving = route_map.paths_serving

        return group_by_match_key(
            [
                (
                    finding.id,
                    build_match_key(
                        project_id=finding.project_id,
                        package=finding.location.package,
                        url=finding.location.url,
                        file_path=finding.location.file_path,
                        start_line=finding.location.start_line,
                        paths_serving=paths_serving,
                    ),
                )
                for finding in findings
            ]
        )
