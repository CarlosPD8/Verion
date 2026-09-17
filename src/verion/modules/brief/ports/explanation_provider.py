from typing import Protocol

from verion.modules.brief.domain.explanation import Explanation

# `risk_engine`'s PORT module, never its domain. `ExplainableDecision` is declared there
# precisely so this parameter can be annotated without naming `RiskReasoning`, which
# `cross-module-brief` forbids (ADR-0032 decision 1).
from verion.modules.risk_engine.ports.explainable_decision import ExplainableDecision


class ExplanationProviderPort(Protocol):
    """Turns a decided priority into prose. `brief`'s outbound port to an LLM (M7.1).

    **It narrates; it never decides.** The input is a decision the Risk Engine already made
    and the output is text, so nothing returned here can move a Risk between buckets
    (rule 6, ADR-0004). Provider-agnostic as a port; the one adapter shipped is OpenAI's.
    """

    async def explain(self, *, decision: ExplainableDecision) -> Explanation:
        """Narrate `decision`.

        Raises `ExplanationUnavailable` on any provider failure, and nothing else — no
        transport library's exception escapes an adapter.
        """
        ...
