# ADR-004: LLM explanation layer strictly downstream of risk scoring

## Status

Accepted

## Context

Verion generates a natural-language Security Brief for each scored Risk, and an LLM is the natural tool for turning structured data into readable prose. But ADR-003 establishes that priority must stay traceable to explicit, inspectable signals — if the LLM had any influence over the `fix_now`/`plan`/`monitor` decision itself, that guarantee would be void the moment the model's behavior wasn't fully predictable, which is inherent to LLM outputs. There's also a security dimension specific to this product: scanned source code and finding content is untrusted input (it comes from the repositories being scanned, not from Verion's own trusted data), so any point where that content reaches an LLM prompt is a potential prompt-injection surface.

## Decision

The Risk Engine computes priority, confidence, and `RiskReasoning` entirely before the LLM is ever invoked, and persists that result. The LLM's only job, via `ExplanationProviderPort`, is to narrate an already-finalized `RiskReasoning` into readable prose for the Security Brief — it receives the structured scoring result as input and produces text as output; it has no path to alter the priority that was already decided and stored. See `ARCHITECTURE.md` §8 for the full scan → correlation → risk → brief sequence, which shows the LLM call happening strictly after risk persistence. `ROADMAP.md` M7.3 additionally requires sanitizing/constraining what scanned content gets interpolated into the LLM prompt, since that content is untrusted.

## Consequences

This keeps ADR-003's explainability guarantee intact end-to-end: no matter what the LLM produces, the priority a developer sees was decided by the deterministic Risk Engine, not by the model. It also bounds the blast radius of a successful prompt injection via scanned content — worst case, the narrative text is compromised or nonsensical, but the model has no mechanism to change which Risk gets flagged `fix_now`. It gives a stable contract for testing: the Explanation Layer can be tested with a fake/deterministic adapter for CI stability (a real LLM call is a separate, small integration test), without needing to also verify scoring behavior at the same time.

It also means the Security Brief's narrative quality is fundamentally limited by the quality of the `RiskReasoning` it's given — the LLM cannot compensate for a thin or unclear reasoning record by inferring additional context, because giving it license to do that would reopen the boundary this ADR exists to hold. And it forecloses certain future UX ideas (e.g., letting a user ask the LLM "what if this exposure changed?" and get an updated priority in response) unless that flow is explicitly redesigned to re-run the Risk Engine rather than let the LLM answer directly.

## Alternatives considered

**Let the LLM weigh in on priority directly** (e.g., pass it the raw findings and signals and let it produce both the priority and the explanation together). Rejected: this is faster to build for a demo, but it reopens exactly the black-box problem ADR-003 closes — priority would no longer be traceable to explicit inputs — and combines the untrusted-content/prompt-injection risk with the ability to influence a security-relevant decision, which is a materially worse risk profile than injection only being able to affect narrative text.

**Have the LLM produce a suggested priority that a human or the Risk Engine can override.** Rejected as unnecessary complexity for the MVP: it still requires building the override/reconciliation logic, and doesn't remove the core objection — the LLM's suggestion would itself be an unexplainable input sitting next to the Risk Engine's explainable one, which is confusing for the exact audience (developers who want to trust the "why") this product is built for.
