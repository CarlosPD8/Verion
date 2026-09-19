from datetime import datetime

from pydantic import BaseModel, Field, field_validator

from verion.modules.history.domain.risk import MAX_REASON_CHARS, is_blank_reason


def _not_blank(reason: str) -> str:
    # The domain's definition of blank, so a 422 here and the domain's refusal never disagree.
    if is_blank_reason(reason):
        raise ValueError("reason must not be blank")
    return reason


class DismissRiskRequest(BaseModel):
    """Which current Risk to dismiss, by its exact member set, and why. ADR-0036.

    **A selector, never an address**: `finding_ids` is resolved once, in this request, against
    the scored projection, and a set that no longer matches a surface is refused. Duplicates are
    refused rather than collapsed, as `GenerateSecurityBriefRequest` does.

    **`reason` is required, non-blank, and at most 2,000 characters** (ADR-0036 decision 7), the
    first length bound on member-supplied input in this API (**G91**).
    """

    finding_ids: list[str] = Field(min_length=1)
    reason: str = Field(min_length=1, max_length=MAX_REASON_CHARS)

    @field_validator("finding_ids")
    @classmethod
    def _no_duplicates(cls, finding_ids: list[str]) -> list[str]:
        if len(set(finding_ids)) != len(finding_ids):
            raise ValueError("finding_ids must not repeat an id")
        return finding_ids

    @field_validator("reason")
    @classmethod
    def _reason_not_blank(cls, reason: str) -> str:
        return _not_blank(reason)


class UndoRiskDismissalRequest(BaseModel):
    """Why a dismissal is undone, optionally. Non-blank and at most 2,000 characters if given."""

    reason: str | None = Field(default=None, min_length=1, max_length=MAX_REASON_CHARS)

    @field_validator("reason")
    @classmethod
    def _reason_not_blank(cls, reason: str | None) -> str | None:
        return None if reason is None else _not_blank(reason)


class RiskDismissalResponse(BaseModel):
    """One dismissal record, with its latest event. Every item, and both write responses.

    **`id` is the record's, never a Risk's.** It addresses an immutable snapshot, which is what
    the undo route takes. A candidate Risk still has no identifier, and `/risks` and
    `/scored-risks` still carry none (ADR-0025 decision 1, ADR-0036 decision 1).

    **`finding_ids` is the snapshot**: the surface's members as the engine scored them when it
    was dismissed. A current surface is dismissed iff its members are a subset of an active
    snapshot, so a Risk a new finding joined is no longer dismissed, although this record still
    reads `dismissed` (ADR-0036 decision 2).

    **`state`, `reason`, `actor_user_id` and `occurred_at` are the latest event's.** While the
    record is dismissed, they say who dismissed it, why and when. Once undone, they describe the
    undo, and the dismissal stays in the log unreturned. `actor_user_id` is a user id, not a
    credential (rule 12). **Deliberately absent:** `project_id`, which is the path parameter.
    """

    id: str
    finding_ids: list[str]
    state: str
    reason: str | None
    actor_user_id: str
    occurred_at: datetime


class RiskAlreadyDismissedResponse(BaseModel):
    """The 409 body when an active snapshot already covers the surface (ADR-0036 decision 11).

    Names the record to undo, since a client that wants the surface undismissed needs its id.
    """

    covering_dismissal_id: str


class ProjectRiskDismissalsResponse(BaseModel):
    """A page of a project's dismissal records, newest dismissal first. No envelope: every
    record exists because a request wrote it."""

    items: list[RiskDismissalResponse]
    total: int
    limit: int
    offset: int
