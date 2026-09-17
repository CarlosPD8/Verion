from dataclasses import dataclass


@dataclass(frozen=True, kw_only=True)
class ExplainableSignal:
    """One scored term as another module may see it: `Signal`'s fields, plus its meaning.

    **Declared in `ports/` so a consumer can NAME it.** `cross-module-brief` forbids
    `verion.modules.risk_engine.domain`, where `Signal` lives, and `ExplanationProviderPort`
    must annotate its parameter — the inference that lets `ComputeRiskUseCase` take
    `MatchGroup` off a port's RETURN annotation does not exist for a parameter. The shape is
    `CandidateRiskAccessDenied`'s in `correlation/ports/`: declared where the consumer is
    allowed to name it, constructed inside the owning module (ADR-0032 decision 1).

    **A full copy of `Signal`, never a narrowed one.** `name`, `value`, `produced_by` and
    `note` carry `Signal`'s own annotations, and `tests/unit/test_explainable_decision.py`
    derives that from `dataclasses.fields(Signal)` rather than from a hand-written list —
    the no-narrowing constraint **G33** records, applied to this copy.

    **`definition` is the one addition**, and the reason it exists: `Signal.note` is `None`
    whenever a signal fires, so without it a firing `corroboration_signal` would reach a
    narrator carrying a bare `1` and nothing saying what that number does not mean (**G62**).
    Its text is `scoring.py`'s, so `risk_engine` stays the only owner of that meaning.
    """

    name: str
    value: int
    produced_by: tuple[str, ...]
    note: str | None
    definition: str


@dataclass(frozen=True, kw_only=True)
class ExplainableDecision:
    """A scored Risk's decided priority and its working — everything a narrator may see.

    **Frozen**, because between "decided" and "narrated" nothing may change it: rule 6
    enforced by the type rather than by a convention (ADR-0004).

    **The bucket, the score and the thresholds are here, not only the reasoning.**
    `RiskReasoning` carries the three signals and nothing else, so a narrator given only it
    could not name the bucket without summing and bucketing itself — which is the LLM
    deciding a priority. All four are Verion-computed and already public on
    `/scored-risks` (ADR-0030 decision 3). `priority` is `Priority`'s value as `str`,
    because a consumer may not name that enum.

    **What is deliberately absent, and is the boundary this issue ends at:** `project_id`,
    `package`, `url` and `finding_ids`. `package` and `url` are scanned content — a Trivy
    `PkgName`, a ZAP path or a route derived from scanned source — and scanned content in a
    prompt is M7.3's scope. A test asserts this field set EQUALS its enumeration, so adding
    one of them fails rather than widening the boundary silently (ADR-0032 decision 2).

    **Stored whole by `brief` since M7.2** (ADR-0033 decision 2). A change to this type's
    fields, or to `ExplainableSignal`'s, fails `brief`'s pinned v1 test, and must bump the
    stored version and keep a reader for existing rows.
    """

    priority: str
    priority_score: int
    fix_now_at: int
    plan_at: int
    severity: ExplainableSignal
    exposure: ExplainableSignal
    corroboration: ExplainableSignal
