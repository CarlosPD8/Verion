# ADR-003: Explainable risk scoring over black-box ML

## Status

Accepted

## Context

Verion's core pitch is turning a wall of scanner findings into a small number of prioritized, explainable decisions — "from security findings to security decisions." `PRODUCT_SPEC.md` §7 states this as a non-functional requirement in explicit terms: "every score, correlation, and recommendation must be traceable to explicit inputs. No opaque 'AI magic number.'" A trained ML model scoring risk severity/priority would likely be feasible to build and could plausibly outperform a hand-specified formula on raw predictive accuracy — but a developer looking at a `fix_now` label has no way to ask a trained model "why," short of post-hoc explainability techniques that are themselves approximations, not ground truth. That directly undermines the product's differentiator: developers are supposed to trust and act on Verion's prioritization, and trust requires the "why" to be answerable in plain terms.

## Decision

Risk scoring in the MVP is a documented, inspectable function of explicit signals — severity, exposure, reachability (where available), asset sensitivity, and environment — that produces a priority bucket (`fix_now` / `plan` / `monitor`), a confidence value, and a `RiskReasoning` record capturing which signals drove the result. No trained model or hidden-weight scoring is used anywhere in the risk-scoring path. The exact formula and weights are to be documented in `docs/adr/0005-risk-scoring-model.md` when that work happens (`ROADMAP.md` M6.1) — this ADR establishes the constraint that formula must satisfy, not the formula itself.

## Consequences

This makes every priority decision auditable: a developer (or Verion's own team) can point at a `fix_now` label and trace it back to the exact signals that produced it, which is what `PRODUCT_SPEC.md`'s explainability requirement demands. It also makes the Risk Engine fully unit-testable with deterministic inputs and expected outputs — no model training, no non-determinism, no dataset to curate and maintain.

It caps the sophistication of the scoring in the near term: a hand-specified function of explicit signals will not capture subtle interactions between signals the way a trained model could, and improving accuracy means deliberately reworking the formula rather than retraining on more data. It also puts pressure on signal quality — an explainable formula is only as good as the signals feeding it (exposure, reachability, etc.), and gaps there show up directly as scoring gaps rather than being absorbed by a model's ability to find patterns in noisy data.

## Amendments

- **2026-09-16 (M6.1): the Decision's five-signal list is narrowed by measurement, and the constraint it exists to state is untouched.** ADR-0005 ships the function this ADR deferred, and it does not use three of the five signals named above.
  - **What was claimed:** scoring is a function of *"severity, exposure, reachability (where available), asset sensitivity, and environment"*.
  - **What ships:** `severity_signal`, an `exposure_signal`, and a `corroboration_signal` this ADR did not name. **`reachability_signal`, `asset_sensitivity_signal` and `environment_signal` have no source anywhere in `src/`** and are declined for M6 rather than invented — inventing one would be the untraceable input rule 5 forbids, which is this ADR's own subject.
  - **`exposure` ships in a weaker form than this ADR meant**, and the difference is stated rather than absorbed: FR-7's exposure is the project's statement about the asset, which exists only as `SecurityContext.exposure_tags` (free text, behind a persistence port, unreadable after a second detect — `ROADMAP.md` **G55**). ADR-0005 substitutes a fact already in the data: a surface carrying a DAST member was reached over the network by a scanner.
  - **Nothing here is reversed.** The constraint — an inspectable function of explicit signals, a bucket, a confidence, a `RiskReasoning`, no trained model — is what ADR-0005 satisfies, and the signals above remain the target rather than becoming wrong. What this amendment records is that the list was written before any of its inputs had a source, and three of them still do not.

## Alternatives considered

**A trained ML model** (e.g. gradient-boosted trees or a small neural net trained on labeled finding/outcome data) for priority scoring. Rejected: even with post-hoc explainability tooling (SHAP, LIME, etc.), the explanation is an approximation of what the model actually did, not a direct account of it — that gap is exactly what `PRODUCT_SPEC.md` §7 rules out. It would also require a labeled training dataset that doesn't exist yet and can't be assembled within the MVP timeline.

**A hybrid: explainable scoring with an ML-based confidence adjustment.** Rejected for MVP as unnecessary complexity — introduces the same black-box-explainability problem for the confidence dimension specifically, for a benefit (better-calibrated confidence) that hasn't been shown to matter yet at this stage.
