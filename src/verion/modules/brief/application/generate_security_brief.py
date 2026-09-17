from verion.modules.brief.domain.security_brief import SecurityBrief
from verion.modules.brief.ports.explanation_provider import ExplanationProviderPort
from verion.modules.brief.ports.security_brief_repository import SecurityBriefRepositoryPort

# `risk_engine`'s PORT, never its application or domain (rule 3, G35).
from verion.modules.risk_engine.ports.explainable_risk import ExplainableRiskPort
from verion.shared_kernel.ports import ClockPort, IdGeneratorPort


class GenerateSecurityBriefUseCase:
    """Narrate one current scored Risk and store the result. FR-8, M7.2, ADR-0033.

    **Order is a property, and each step's failure leaves nothing written:**

    1. **The port.** It authorizes before reading anything, then selects the surface by
       exact member set and fails closed on a changed set (ADR-0033 decision 1).
    2. **The narration.** A provider failure raises `ExplanationUnavailable` before anything
       is added. The route's session would roll that back anyway, which is exactly why a unit
       test pins the order: an integration test cannot see an `add` that the rollback undid.
    3. **The write**, append-only (ADR-0033 decision 3).

    **Authorization is member-level, inherited through the port** (ADR-0033 decision 7). It
    coincides with owner-gating only because nothing in `src/` creates a non-owner membership
    (**G75**).

    **Synchronous**, and billed per call. The request's session stays open across the
    provider call, and nothing bounds repeats (**G73**). Generation does not refuse while
    normalization is unfinished, because a failed run counts and is never retried, so that
    refusal would be permanent (ADR-0033 decision 5, **G76**).
    """

    def __init__(
        self,
        explainable_risks: ExplainableRiskPort,
        explanations: ExplanationProviderPort,
        briefs: SecurityBriefRepositoryPort,
        clock: ClockPort,
        ids: IdGeneratorPort,
    ) -> None:
        self._explainable_risks = explainable_risks
        self._explanations = explanations
        self._briefs = briefs
        self._clock = clock
        self._ids = ids

    async def execute(
        self, *, project_id: str, user_id: str, finding_ids: tuple[str, ...]
    ) -> SecurityBrief:
        risk = await self._explainable_risks.explainable_risk(
            project_id=project_id, user_id=user_id, finding_ids=finding_ids
        )
        explanation = await self._explanations.explain(decision=risk.decision)
        brief = SecurityBrief(
            id=self._ids.new_id(),
            project_id=project_id,
            # The ENGINE's members, never the request's: what was scored is what is stored.
            finding_ids=risk.finding_ids,
            decision=risk.decision,
            explanation=explanation,
            generated_at=self._clock.now(),
        )
        await self._briefs.add(brief)
        return brief
