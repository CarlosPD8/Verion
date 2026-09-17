"""The Explanation Layer's prompt: what the model is told, and exactly what it is shown.

Pure — no I/O — so the wording is unit-tested without a provider (ADR-0032 decision 4).

**What reaches the model is Verion-computed and nothing else**: a bucket name, integers,
the fixed strings `scoring.py` declares, and severity labels from `shared_kernel`. No
finding id, no package, no URL, no finding text — so nothing from a scanned repository
leaves Verion through this prompt, and prompt-injection-via-scanned-content (M7.3) has no
entry point here. That property belongs to `ExplainableDecision`'s field set, which a test
pins; this module only has to avoid rendering the ids it does carry.

**G62 is carried, not restated.** Rule 3 below tells the model to describe a signal only in
its definition's terms, and `CORROBORATION_DEFINITION` — declared beside the function that
computes the signal — is what says the signal is not agreement. Instructions are not
guarantees: whether a real model obeys them is verified by nothing in CI (**G62**, **G65**).
"""

from verion.modules.risk_engine.ports.explainable_decision import (
    ExplainableDecision,
    ExplainableSignal,
)
from verion.shared_kernel.severity import Severity

# Bumped whenever DEVELOPER_INSTRUCTIONS or the rendered facts change, so a persisted
# narrative can be traced to the wording that produced it.
PROMPT_VERSION = "m7.1-1"

DEVELOPER_INSTRUCTIONS = """\
You explain a security prioritization that Verion has already decided. The decision is final.

Rules:
1. State the priority exactly as given. Do not recommend, imply or speculate about a \
different priority, and do not call the item more or less urgent than its priority.
2. Explain the priority only as the sum of the three signals given and the thresholds \
given. Add no other reason.
3. Describe each signal only in the terms of its definition, and go no further than the \
definition does.
4. A surface is a package or a route path; you are not told which. You are not told what \
the vulnerability is, what code, package or URL is affected, how to fix it, how much effort \
a fix takes, or how confident anyone is. Do not state or guess any of these.
5. Include no identifiers. Write plain prose, at most four sentences, with no headings or \
lists."""


def _severity_label(rank: int) -> str | None:
    labels = [severity.value for severity in Severity if severity.rank == rank and rank > 0]
    return labels[0] if labels else None


def _signal_line(signal: ExplainableSignal, *, detail: str | None) -> str:
    head = f"{signal.name} = {signal.value}"
    if detail:
        head = f"{head} ({detail})"
    lines = [f"{head}. Definition: {signal.definition}"]
    if signal.note:
        lines.append(f"  Note: {signal.note}")
    return "\n".join(lines)


def render_facts(decision: ExplainableDecision) -> str:
    """The user message: the decision and its working, one fact per line.

    `produced_by` is rendered only as a COUNT, and only for corroboration, where the
    representatives are one per distinct scanner — so the count is the number of scanners.
    The ids themselves are never rendered: meaningless to a reader, and rule 5 of the
    instructions forbids repeating them.
    """
    corroboration = decision.corroboration
    corroboration_detail = (
        f"from {len(corroboration.produced_by)} distinct scanners"
        if corroboration.value > 0
        else None
    )
    return "\n".join(
        [
            f"Priority: {decision.priority} (score {decision.priority_score})",
            (
                f"Thresholds: fix_now at {decision.fix_now_at} or more; plan at "
                f"{decision.plan_at} or more; monitor below {decision.plan_at}."
            ),
            _signal_line(decision.severity, detail=_severity_label(decision.severity.value)),
            _signal_line(decision.exposure, detail=None),
            _signal_line(corroboration, detail=corroboration_detail),
        ]
    )


def build_messages(decision: ExplainableDecision) -> list[dict[str, str]]:
    """Chat Completions `messages`: the instructions as `developer`, the facts as `user`.

    `developer` rather than `system`: openai-python's `ChatCompletionDeveloperMessageParam`
    documents that "with o1 models and newer, `developer` messages replace the previous
    `system` messages", and OpenAI's text guide ranks `developer` ahead of `user`. Whether
    `gpt-5-mini` itself accepts the role is stated on no model page and is verified only by
    a real call, which nothing in CI makes (ADR-0032).
    """
    return [
        {"role": "developer", "content": DEVELOPER_INSTRUCTIONS},
        {"role": "user", "content": render_facts(decision)},
    ]
