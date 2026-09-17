from typing import Protocol

from verion.modules.brief.domain.brief_member import BriefMember
from verion.modules.brief.domain.explanation import Explanation

# `risk_engine`'s PORT module, never its domain. `ExplainableDecision` is declared there
# precisely so this parameter can be annotated without naming `RiskReasoning`, which
# `cross-module-brief` forbids (ADR-0032 decision 1).
from verion.modules.risk_engine.ports.explainable_decision import ExplainableDecision


class ExplanationProviderPort(Protocol):
    """Writes a Brief's two narratives. `brief`'s outbound port to an LLM (M7.1, M7.3).

    **Two methods, and the separation between them is the point** (ADR-0034 decision 3).
    `explain` sees the decided priority and nothing scanned; `describe` sees scanned member
    facts and no decision. So the narrative of a priority is written from a prompt holding zero
    attacker-controlled bytes, and rule 6 holds by construction rather than by the model obeying.

    **Neither decides anything.** Nothing returned here can move a Risk between buckets (rule 6,
    ADR-0004). Provider-agnostic as a port; the one adapter shipped is OpenAI's.
    """

    async def explain(self, *, decision: ExplainableDecision) -> Explanation:
        """Narrate why `decision`'s priority is what it is.

        Raises `ExplanationUnavailable` on any provider failure, and nothing else — no
        transport library's exception escapes an adapter.
        """
        ...

    async def describe(self, *, members: tuple[BriefMember, ...], member_count: int) -> Explanation:
        """Narrate what the scanners reported on a surface, from its members' typed fields.

        `members` are already sanitized and capped (`BriefMember`); `member_count` is the
        surface's full size, which may exceed `len(members)`. Raises `ExplanationUnavailable` on
        any provider failure, and nothing else.
        """
        ...
