# `correlation`'s PORT, never its `application/` or `domain/`. The port is what ADR-0005
# decision 2 published so this module would not have to import another module's use case —
# the hole rule 3 forbids in words and no contract catches in CI (**G35**). The annotation
# names `MatchGroup`; this module never does, and takes the type by inference below.
from verion.modules.correlation.ports.candidate_risk import CandidateRiskPort

# `normalization`'s PORT, for the same reason and by the same mechanism. A `MatchGroup`
# carries `finding_ids` and no severity, so scoring cannot see a `Finding.severity` without
# reading findings here. That second read is **G61**.
from verion.modules.normalization.ports.finding_repository import FindingRepositoryPort
from verion.modules.risk_engine.domain.exceptions import MemberFindingMissing
from verion.modules.risk_engine.domain.scoring import ScoredSurface, SurfaceMember, score_surface


class ComputeRiskUseCase:
    """Score a project's candidate Risks. FR-7's decision layer (M6.2, ADR-0005).

    **Consumes two ports and names neither module's types.** Both return values are taken by
    inference off the port annotations — the pattern `allow_indirect_imports = true` permits
    and `CorrelateFindingsUseCase` already uses for `Finding`. This is what keeps
    `cross-module-risk-engine` satisfied while still reading another module's data.

    **Writes nothing.** ADR-0005 decision 3, with ADR-0025 decisions 1 and 2 behind it: a
    score is derived from stored inputs exactly as the grouping is, so there is no `risks`
    table, no upsert, and **G37**'s protected-column obligation stays latent. M8.1 is the
    first issue forced to persist a Risk, because a dismissal is the first value about one
    that cannot be recomputed and must stay attached to it when its membership changes (the
    wording of ADR-0025's 2026-09-17 amendment: M7.2's stored Brief narrative is an earlier
    value that cannot be recomputed, and it does not follow the Risk). **M6.3 could have
    written a row and declined to** (ADR-0030), and M7.2 writes a Brief row but no Risk row
    (ADR-0033), so G37 is unmoved and M8.1 remains the forced one.

    **Returns `correlation`'s group order, NOT a priority order.** Ranking is
    `ListScoredRisksUseCase`'s, above this one, and sorting here would pre-empt it —
    `test_risks_routes.py` pins that the M5.2 listing carries no priority order, and
    `test_the_order_is_correlations_group_order_and_not_a_priority_order` pins that this use
    case does not acquire one now that a route above it does have one.

    Authorization is the port's: `candidate_risks` refuses before reading anything and
    raises `CandidateRiskAccessDenied`, which this module deliberately does not catch — it
    has nothing to add, and M6.3's route is where a denial becomes a 404.
    """

    def __init__(self, candidate_risks: CandidateRiskPort, findings: FindingRepositoryPort) -> None:
        self._candidate_risks = candidate_risks
        self._findings = findings

    async def execute(self, *, project_id: str, user_id: str) -> list[ScoredSurface]:
        """Group, read, score. One pass, nothing persisted.

        **The findings read is the project's whole set, deliberately** — `get_by_project_id`
        rather than `list_for_project`, for the reason `CorrelateFindingsUseCase` gives: the
        listing carries M4.5's display policy (a severity order, a filter vocabulary, a page
        bound) and scoring should inherit none of it. It is also the read that makes a scored
        request read the project's findings **twice**, once inside correlation and once here
        (**G61**), priced by arithmetic over ADR-0025's measurements and measured by nothing
        until M6.3.

        **No helper takes a group or a finding as a parameter, and that is structural rather
        than stylistic.** `mypy --strict` requires an annotation on every parameter, so any
        extracted helper would have to NAME `MatchGroup` or `Finding` — the exact import
        `cross-module-risk-engine` forbids. Inference only survives where the values stay
        local, so the loop stays inline.
        """
        groups = await self._candidate_risks.candidate_risks(project_id=project_id, user_id=user_id)
        findings = await self._findings.get_by_project_id(project_id)
        by_id = {finding.id: finding for finding in findings}

        scored: list[ScoredSurface] = []
        for group in groups:
            members: list[SurfaceMember] = []
            # Zipped, because `member_confidence` is positionally aligned to `finding_ids`
            # (ADR-0037 decision 5) and reading them apart is how an alignment bug becomes a
            # mislabelled member. `strict=True` so a group that ever lost the invariant
            # raises here rather than scoring a short surface, which is the same preference
            # `MemberFindingMissing` below encodes.
            for finding_id, confidence in zip(
                group.finding_ids, group.member_confidence, strict=True
            ):
                finding = by_id.get(finding_id)
                if finding is None:
                    # The two reads disagreed. Scoring a short surface would return a
                    # confident bucket computed from incomplete members — see the exception.
                    raise MemberFindingMissing(
                        f"Finding '{finding_id}' is in a candidate Risk but not in the "
                        f"findings read for project '{project_id}'"
                    )
                members.append(
                    SurfaceMember(
                        finding_id=finding.id,
                        source=finding.source,
                        severity=finding.severity,
                        confidence=confidence,
                    )
                )

            scored.append(
                score_surface(
                    project_id=group.key.project_id,
                    package=group.key.package,
                    url=group.key.url,
                    members=members,
                )
            )

        return scored
