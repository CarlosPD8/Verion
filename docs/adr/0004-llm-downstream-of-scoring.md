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

## Amendments

- **2026-09-16 (M6.2): two clauses of the Decision are qualified by what M6.2 shipped. Neither is struck, and the boundary this ADR exists to hold is untouched.**
  - *"The Risk Engine computes priority, confidence, and `RiskReasoning` entirely before the LLM is ever invoked, **and persists that result**."* — **M6.2 persists nothing.** ADR-0005 decision 3 scores per request from stored inputs, so there is no `risks` table and no row to write (ADR-0025 decisions 1 and 2); M6.3's write stays optional and M8.1 is the first issue forced into one. What this ADR requires is that priority be **decided** before the LLM runs, and it is. Persistence was the mechanism assumed in 2026, not the guarantee.
  - *"See `ARCHITECTURE.md` §8 … which shows the LLM call happening strictly after risk **persistence**."* — that diagram read `Risk->>DB: persist priority + reasoning` until this commit, which described no code; **the same commit replaces that line** with the findings read M6.2 actually performs. The **ordering** the diagram illustrates holds and is unchanged; the persistence step within it is gone, because there is none to draw.
  - Recorded here because M7.1 reads this ADR before building against it: a scored Risk carries **no `confidence`** (**G63**), so one of the three values this Decision names is absent at the boundary. Rule 6 forbids the Explanation Layer from supplying one itself, which makes this a missing input rather than something M7.1 can route around.

## Alternatives considered

**Let the LLM weigh in on priority directly** (e.g., pass it the raw findings and signals and let it produce both the priority and the explanation together). Rejected: this is faster to build for a demo, but it reopens exactly the black-box problem ADR-003 closes — priority would no longer be traceable to explicit inputs — and combines the untrusted-content/prompt-injection risk with the ability to influence a security-relevant decision, which is a materially worse risk profile than injection only being able to affect narrative text.

**Have the LLM produce a suggested priority that a human or the Risk Engine can override.** Rejected as unnecessary complexity for the MVP: it still requires building the override/reconciliation logic, and doesn't remove the core objection — the LLM's suggestion would itself be an unexplainable input sitting next to the Risk Engine's explainable one, which is confusing for the exact audience (developers who want to trust the "why") this product is built for.
