from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class BriefGenerationStatus(StrEnum):
    """Where one Brief generation has got to. M8.6, ADR-0038 decision 5.

    **New to `brief`, and inherited from nowhere.** The module had no status vocabulary before
    this issue: `SecurityBrief`'s eight fields carry no state, because every stored Brief is a
    completed one. `scanning`'s `ScanStatus` is not reused — ADR-0016 decision 2 keeps it
    scanner-scoped, and a Brief has no per-tool outcome to summarise.

    The column behind it is a plain `String`, not a Postgres enum, on
    `security_briefs.confidence`'s ground: adding a value must not need a type migration. So the
    type is reconstructed on read, the same asymmetry ADR-0018 decision 2 notes for `Confidence`.
    """

    PENDING = "pending"
    """The row is written and the job is queued. What a 202 means.

    A row that stays here forever is the cost ADR-0038 decision 11 accepts: an enqueue lost after
    the commit is never re-driven, because this ADR declines `normalization`'s sweep (**G87**).
    """

    RUNNING = "running"
    """The job claimed the row. Written by `claim`, in its own transaction, before the work.

    Claimed separately for `normalize_scan`'s reason: in one transaction this state would be
    written and overwritten before anything could observe it.
    """

    SUCCEEDED = "succeeded"
    """`brief_id` is set and the Brief is readable on `GET …/briefs`."""

    FAILED = "failed"
    """`failure_kind` is set. Never retried — arq 0.28 retries only `Retry`, `RetryJob` and
    `CancelledError` (**G87**) — and the recovery is the user asking again (decision 11)."""


class BriefGenerationFailureKind(StrEnum):
    """Why a generation failed, in the terms of **what the client does about it**. Decision 6.

    Three values, and the number is argued rather than convenient: five terminal failures map
    onto exactly three distinct client actions, and the client is M8.3, two issues out.

    **Not one free-text field**, which is `scans`' bare `failure_reason` and removes the client's
    ability to choose. **Not five**, which would encode distinctions no client acts on.

    **`ExplainableRiskAccessDenied` is deliberately not a fourth value.** A denial is never named
    in a response body (**G17**): the poll authorizes on its own, so a caller whose access was
    revoked between enqueue and run gets 404 from the poll's own verdict, while the row still
    terminates under `SURFACE_CHANGED` so decision 7's CHECK holds and nothing sits `running`
    forever. That value is unobservable while the revocation stands, by construction.
    """

    SURFACE_CHANGED = "surface_changed"
    """`NoCurrentRisk`. **Re-read `/scored-risks` and ask again.**

    The member set no longer names a current Risk — findings joined or left it since the caller
    read the listing (ADR-0033 decision 1's fail-closed selection, reported later rather than in
    the request). Also where a revoked membership lands, for the reason above.
    """

    PROVIDER_UNAVAILABLE = "provider_unavailable"
    """`ExplanationUnavailable` and its subclass `WhatHappenedRejected`. **Retry.**

    One value for both, because to a client they are the same outcome: no usable narrative and
    nothing stored. The route made the same join at 502 (ADR-0034 decision 5).
    """

    INTERNAL_ERROR = "internal_error"
    """`ExplainableRiskInconsistent` and `BriefMemberMissing`. **Do not retry.**

    Both are broken server-side invariants that nothing a client does will clear.
    """


@dataclass(frozen=True, kw_only=True)
class BriefGeneration:
    """One request to generate a Brief, and what became of it. M8.6, ADR-0038.

    **`brief` gains a second entity and stops being one aggregate behind one port** (decision 2).
    Stated because it is a real change to the module's shape, and it is the price of the fork
    that leaves `security_briefs`, `SecurityBrief`, ADR-0033 decision 3 and both pinned field-set
    tests untouched.

    **It is the record, not arq's result** — which is why the job is registered `keep_result=0`
    (decision 10). The poll reads this row.

    **`user_id` is stored because the job re-authorizes with it** (decision 4). That is not a
    verdict inherited across the queue: `ExplainableRiskPort.explainable_risk` authorizes and
    selects in one call and cannot be split, so the id crosses the boundary under every design.
    What the storage buys is a **second, independent check in the worker**, which also catches a
    membership revoked between enqueue and run — something the scanning path has no answer for,
    since `StartScanUseCase` authorizes once and never again.

    **`finding_ids` is the caller's REQUESTED set**, not the engine's. The engine's members are
    what `SecurityBrief.finding_ids` stores, once a surface has been selected; before the job
    runs there is no surface, and the two differing is exactly the `SURFACE_CHANGED` outcome.

    **What this type deliberately does not carry: `started_at` and `finished_at`.** Neither has a
    consumer. Decision 8's response shape returns neither, and `normalization_runs` carries a
    start time only to serve **the sweep's staleness rule**, which decision 11 declines. Adding
    them would also put two nullable fields outside decision 7's CHECK, making a `succeeded` row
    with no finish time and a `pending` row with one both legal — *"a convention nothing
    enforces"*, which is the phrase decision 7 uses for what it refuses to copy from `scans`.
    """

    id: str
    project_id: str
    user_id: str
    finding_ids: tuple[str, ...]
    status: BriefGenerationStatus
    brief_id: str | None
    failure_kind: BriefGenerationFailureKind | None
    requested_at: datetime
