class BriefError(Exception):
    """Base for this module's own errors, on `risk_engine`'s `RiskEngineError` precedent."""


class ExplanationUnavailable(BriefError):
    """The Explanation Layer produced no usable narrative. The priority is unaffected.

    Raised for every provider failure alike — a transport error, a non-2xx status, a body
    that does not parse, a refusal, an empty answer, or a stop for any reason but
    completion. One type, because a caller's only decision is the same in every case: the
    decision stands and its narrative is missing (rule 6, ADR-0004).

    **Its message carries at most a status code or a `finish_reason`, and never a provider's
    response body.** OpenAI's 401 `error.message` has been reported echoing a key's prefix
    and last four characters (a user-pasted body, AutoGPT issue #1422), so a body forwarded
    here would be a credential in an exception (rule 12, **G71**'s second path). Adapters
    raise it `from None` for the same reason: a chained cause is part of the traceback a log
    prints.
    """
