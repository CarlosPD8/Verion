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

    Does not persist (M5.2) and does not decide resolution (M9.1).
    """

    def __init__(self, project_access: ProjectAccessPort, findings: FindingRepositoryPort) -> None:
        self._project_access = project_access
        self._findings = findings

    async def execute(self, *, project_id: str, user_id: str) -> list[MatchGroup]:
        """Authorize first, then read. The order is the security property.

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
        """
        if not await self._project_access.may_read_project(project_id=project_id, user_id=user_id):
            # One message for both "no such project" and "not a member". The port cannot
            # tell them apart and neither should this — see ProjectAccessDenied.
            raise ProjectAccessDenied(f"No readable project with id '{project_id}'")

        findings = await self._findings.get_by_project_id(project_id)
        return group_by_match_key(
            [
                (
                    finding.id,
                    build_match_key(
                        project_id=finding.project_id,
                        package=finding.location.package,
                        url=finding.location.url,
                    ),
                )
                for finding in findings
            ]
        )
