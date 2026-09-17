class BriefError(Exception):
    """Base for this module's own errors, on `risk_engine`'s `RiskEngineError` precedent."""


class ExplanationUnavailable(BriefError):
    """The Explanation Layer produced no usable narrative. The priority is unaffected.

    Raised for every provider failure alike — a transport error, a non-2xx status, a body
    that does not parse, a refusal, an empty answer, or a stop for any reason but
    completion. One type, because a caller's only decision is the same in every case: the
    decision stands and its narrative is missing (rule 6, ADR-0004).

    **Its message carries at most a status code or a `finish_reason`, and never a provider's
    response body.** OpenAI's 401 `error.message` echoes a key's first eight and last four
    characters (a user-pasted body, AutoGPT issue #1422; observed by M7.3's capture on
    2026-09-17), so a body forwarded
    here would be a credential in an exception (rule 12, **G71**'s second path). Adapters
    raise it `from None` for the same reason: a chained cause is part of the traceback a log
    prints.
    """


class WhatHappenedRejected(ExplanationUnavailable):
    """A *what happened* narrative failed output validation (ADR-0034 decision 5, M6).

    **A subclass of `ExplanationUnavailable`**, because to a caller it is the same outcome: no
    usable narrative, nothing stored, and the route's fixed 502. It is its own type so a test
    can tell a rejection from a provider failure.

    **Its message names the check that failed and never quotes the output**, which is model text
    written over scanned content.
    """


class BriefMemberMissing(BriefError):
    """A finding the engine scored into this Risk could not be read back. A broken invariant.

    Nothing in `src/` deletes a finding, and `get_by_id` is scoped to the project the engine
    scored, so this means the two reads disagreed. It is raised before any provider call, so
    nothing is billed and nothing is stored, and the route answers a fixed 500 (ADR-0034
    decision 2, ADR-0030 decision 5's shape).
    """


class SecurityBriefAccessDenied(BriefError):
    """The caller may not read this project's Briefs.

    Like the verdict beneath it (`ProjectAccessPort`), it does not distinguish "no such project"
    from "not a member", so a route answers 404 for both (ADR-0022 decision 2).
    """


class StoredBriefUnreadable(BriefError):
    """A stored Brief's `decision` has a shape this code does not read.

    Raised for a missing or unknown `version`, or a value that does not reconstruct. **It is
    never skipped past**: a list that silently omitted it would hide data loss behind a shorter
    page. So one unreadable row fails its project's whole list read, until the row is migrated
    or a reader for its version ships (ADR-0033 decision 9).

    The message carries a version number at most, never the stored content.
    """
