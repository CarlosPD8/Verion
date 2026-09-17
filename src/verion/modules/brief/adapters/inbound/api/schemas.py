from datetime import datetime

from pydantic import BaseModel, Field, field_validator


class GenerateSecurityBriefRequest(BaseModel):
    """Which current Risk to narrate: its exact member set, as `/scored-risks` lists it.

    **A selector, never an address** (ADR-0033 decision 1). It is resolved once, in this
    request, by exact set equality, and a set that no longer matches a surface is refused.

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


class SecurityBriefResponse(BaseModel):
    """One stored Brief. FR-8's *why it matters*, *what happened* and *evidence sources*.

    **`finding_ids` is FR-9's link**: each id is reachable at
    `GET /projects/{project_id}/findings/{finding_id}/evidence`. It is also what a client joins
    on against `/scored-risks` to find a surface's current Brief, which is the first item with
    an equal set.

    **The decision is the one that was narrated**, which may no longer be the live one: a
    member's severity can be refreshed without the set changing. Compare `priority_score`
    against `/scored-risks` to see whether it moved.

    **`what_happened` is `null` only for a Brief generated before M7.3**, and is kept whole on
    the list as well (ADR-0034 decision 6). It is an object, not top-level fields beside
    `why_it_matters`, `model` and `prompt_version`, so that shipped keys were not renamed; those
    three remain the *why it matters* narration's.

    **Deliberately absent**, each asserted by a test: `confidence` (**G63**);
    `recommended_action` and `estimated_effort` (**G74**); `risk_id`, because
    a Risk has no identifier (ADR-0025 decision 1); `project_id`, which is the path parameter
    (ADR-0022 decision 1); and a completeness envelope (ADR-0033 decision 4, **G76**).
    """

    id: str
    finding_ids: list[str]
    why_it_matters: str
    what_happened: WhatHappenedResponse | None
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
