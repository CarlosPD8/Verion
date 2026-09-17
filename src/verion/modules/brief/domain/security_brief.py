from dataclasses import dataclass
from datetime import datetime

from verion.modules.brief.domain.explanation import Explanation

# `risk_engine`'s PUBLISHED carrier. **This is the first import of another module from any
# `domain/` package in the tree** (ADR-0033 decision 2). It is legal: rule 3 permits a
# published port, and the carrier is two frozen dataclasses with no framework in them. No
# contract sees this edge — `layers-brief` relates layers inside `brief` only, and
# `cross-module-brief` does not forbid `.ports` — so it is registered as **G77**.
from verion.modules.risk_engine.ports.explainable_decision import ExplainableDecision


@dataclass(frozen=True, kw_only=True)
class SecurityBrief:
    """A narrative of one scored decision, with what it narrated and what it was about. FR-8.

    **The Brief's identity is its own `id`, never derived from the Risk.** A candidate Risk has
    no identifier (ADR-0025 decision 1). `finding_ids` is the Risk's member set held as DATA:
    FR-9's link, and what a client joins on against `/scored-risks`. No route resolves a Risk
    by it (ADR-0033 decision 1).

    **`decision`, `explanation` and `what_happened` are held whole, not copied field by field.**
    The live score can move for an unchanged member set, so what was narrated has to be stored
    to stay re-derivable (rule 5) and checkable against its narrative (rule 6). A copy would
    store without any field the carrier later gains, which is G33's narrowing at a storage
    boundary.

    Three of FR-8's six parts: *why it matters* is `explanation.text`, *evidence sources* is
    `finding_ids`, and *what happened* is `what_happened.text` (ADR-0034). **Two narrations, each
    with its own producer**: `explanation` was written from the decision alone, and
    `what_happened` from the members' typed titles and locations alone, by separate calls.

    **`what_happened` is `None` only for a Brief written before M7.3.** Generation never writes
    `None`. **Deliberately absent**, each with a test asserting the field set: `risk_id`,
    `recommended_action` and `estimated_effort` (**G74**), and `confidence` (**G63**).
    """

    id: str
    project_id: str
    finding_ids: tuple[str, ...]
    decision: ExplainableDecision
    explanation: Explanation
    what_happened: Explanation | None
    generated_at: datetime
