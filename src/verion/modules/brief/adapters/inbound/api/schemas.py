from datetime import datetime

from pydantic import BaseModel, Field, field_validator


class GenerateSecurityBriefRequest(BaseModel):
    """Which current Risk to narrate: its exact member set, as `/scored-risks` lists it.

    **A selector, never an address** (ADR-0033 decision 1). It is resolved by exact set equality,
    and a set that no longer matches a surface is refused. ~~It is resolved once, in this
    request~~ *(struck 2026-09-21, M8.6 commit 3: the resolution moved to the worker, ADR-0038
    decision 1. The request stores this set and answers 202; a set that no longer names a surface
    now reaches the poll as `surface_changed` rather than this request as a 404. **This site is
    not on ADR-0038's owed list** — it was found by grepping the struck claim rather than at the
    sites the ADR named.)*

    **Duplicates are refused rather than collapsed**, so the set a client sends is the set that
    is compared. **No maximum length**: nothing bounds a surface's member count, and request
    size limits are M10.2's.
    """

    finding_ids: list[str] = Field(min_length=1)

    @field_validator("finding_ids")
    @classmethod
    def _no_duplicates(cls, finding_ids: list[str]) -> list[str]:
        if len(set(finding_ids)) != len(finding_ids):
            raise ValueError("finding_ids must not repeat an id")
        return finding_ids


class BriefSignalResponse(BaseModel):
    """One narrated signal as the narrator saw it, `definition` included."""

    name: str
    value: int
    produced_by: list[str]
    note: str | None
    definition: str


class BriefReasoningResponse(BaseModel):
    severity: BriefSignalResponse
    exposure: BriefSignalResponse
    corroboration: BriefSignalResponse


class BriefThresholdsResponse(BaseModel):
    """The thresholds the narrated bucket was decided against, stored with the Brief.

    Not today's constants: a Brief is a record of what was narrated. That is what keeps its
    bucket re-derivable by hand after the scale changes (rule 5).
    """

    fix_now_at: int
    plan_at: int


class WhatHappenedResponse(BaseModel):
    """*What happened*, and the producer of that narration (M7.3, ADR-0034).

    A narration of the members' typed titles and locations, written by a separate call from the
    one behind `why_it_matters`, so it carries its own `model` and `prompt_version`. **Its text
    derives from scanned content**: the same fields `GET /projects/{project_id}/findings` already
    lists in bulk, never a finding's `raw_payload` (ADR-0034 decisions 1 and 6).
    """

    text: str
    model: str
    prompt_version: str


class ConfidenceResponse(BaseModel):
    """A Risk's grouping provenance, and what it means. M8.5, ADR-0037 decision 10.

    **The definition rides the response because NO PROMPT receives this value.** The three
    scored signals get their meaning to a reader through a narrator that was handed
    `ExplainableSignal.definition`; this value is handed to neither call, so the response is
    the only thing that can carry its meaning, and the field name alone would not.

    **One owner, two placements.** The text is `correlation`'s single `CONFIDENCE_DEFINITION`,
    forwarded verbatim. It sits on the ITEM here, because a Brief is one narrated record with
    no envelope, and on the ENVELOPE of `/scored-risks`, because there it would be a constant
    repeated once per item — ADR-0030 decision 3's reason for the thresholds. A test asserts
    the two placements are byte-identical, which is what makes "one owner" a claim.

    **`value` is one of `reported`, `inferred`, `ungrouped`**, all three named and defined in
    `definition` so the text and the vocabulary cannot drift apart.
    """

    value: str
    definition: str


class SecurityBriefResponse(BaseModel):
    """One stored Brief. FR-8's *why it matters*, *what happened* and *evidence sources*.

    **`finding_ids` is FR-9's link**: each id is reachable at
    `GET /projects/{project_id}/findings/{finding_id}/evidence`. It is also what a client joins
    on against `/scored-risks` to find a surface's current Brief, which is the first item with
    an equal set.

    **The decision is the one that was narrated**, which may no longer be the live one: a
    member's severity can be refreshed without the set changing. Compare `priority_score`
    **and `confidence`** against `/scored-risks` to see whether either moved.

    **`what_happened` is `null` only for a Brief generated before M7.3**, and is kept whole on
    the list as well (ADR-0034 decision 6). It is an object, not top-level fields beside
    `why_it_matters`, `model` and `prompt_version`, so that shipped keys were not renamed; those
    three remain the *why it matters* narration's.

    **`confidence` is `null` only for a Brief generated before M8.5** (ADR-0037), on
    `what_happened`'s terms: generation never writes one, and there is no backfill. It is the
    surface's grouping provenance as the engine computed it, and like `priority_score` above
    it is **the value that was stored, not today's** — compare it against `/scored-risks` to
    see whether a route-map rebuild has moved it (**G93**).

    **Deliberately absent**, each asserted by a test:
    `recommended_action` and `estimated_effort` (**G74**, both cut to V2); `risk_id`, because
    a Risk has no identifier (ADR-0025 decision 1); `project_id`, which is the path parameter
    (ADR-0022 decision 1); and a completeness envelope (ADR-0033 decision 4, **G76**).
    """

    id: str
    finding_ids: list[str]
    why_it_matters: str
    what_happened: WhatHappenedResponse | None
    confidence: ConfidenceResponse | None
    priority: str
    priority_score: int
    thresholds: BriefThresholdsResponse
    reasoning: BriefReasoningResponse
    model: str
    prompt_version: str
    generated_at: datetime


class ProjectSecurityBriefsResponse(BaseModel):
    """A page of a project's Briefs, newest first. No envelope (ADR-0033 decision 4)."""

    items: list[SecurityBriefResponse]
    total: int
    limit: int
    offset: int


class BriefGenerationAcceptedResponse(BaseModel):
    """`POST /projects/{project_id}/briefs`'s 202 body. M8.6, ADR-0038 decisions 1 and 8.

    **`ScanAcceptedResponse`'s shape, deliberately**: the id, because a caller cannot poll a
    generation it cannot address, and the status, which is always `pending` on this path. Rule
    10: never the domain `BriefGeneration`, whose `user_id` and `finding_ids` this route has no
    reason to echo back.

    **202 rather than 201** because the work is enqueued, not completed — and a 202 here means
    the row exists *and* the job is queued, which the after-commit enqueue is what guarantees.

    The key set is pinned by an equality assertion in `test_security_brief_routes.py`.
    """

    id: str
    status: str


class BriefGenerationResponse(BaseModel):
    """`GET /projects/{project_id}/brief-generations/{id}`. M8.6, ADR-0038 decision 8.

    **`failure_kind` is a closed vocabulary of three, chosen on what a client DOES** (decision
    6), not on how many ways generation can fail — five terminal failures map onto three
    actions: `surface_changed` (re-read `/scored-risks` and ask again), `provider_unavailable`
    (retry), `internal_error` (do not retry). Not one free-text field, which is `scans`' shape
    and removes the client's ability to choose; not five, which encodes distinctions no client
    acts on. The client is M8.3, two issues out.

    **No kind names an access denial.** A caller who may not read this generation gets a 404
    from this route's own verdict and never a body (**G17**).

    **`detail` is DERIVED from `failure_kind`, not stored.** A fixed sentence per kind, owned by
    the router. Two consequences, both deliberate: it carries no provider text by construction
    (rule 12), and it needs no column outside `ck_brief_generations_outcome_shape` — which would
    have been a correlation held by convention, the shape decision 7 refuses to copy from
    `scans`.

    `brief_id` is `null` until `succeeded`, and is how a client reaches the Brief on
    `GET …/briefs`. `failure_kind` and `detail` are `null` unless `failed`.

    **Deliberately absent**: `project_id` (the path parameter, ADR-0022 decision 1), `user_id`
    (the caller's own, and a step toward naming who may read a row), `finding_ids` (the caller
    sent them), and any timestamp — nothing reads one (ADR-0038 decision 11 declines the sweep
    that would).
    """

    id: str
    status: str
    failure_kind: str | None
    detail: str | None
    brief_id: str | None
