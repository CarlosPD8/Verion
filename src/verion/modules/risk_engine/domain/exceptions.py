class RiskEngineError(Exception):
    """Base for this module's own errors. `correlation` declares its own for the same
    reason: an exception is part of a module's vocabulary, and catching another module's
    would be naming its `domain` (rule 3)."""


class MemberFindingMissing(RiskEngineError):
    """A group named a finding id that the findings read did not return.

    **Raised rather than scored around, because the alternative is a wrong number that
    looks right.** Scoring reads the project's findings in a SEPARATE call from the one
    that produced the groups (**G61**), and the two are not in one transaction, so a
    finding could in principle disappear between them. Dropping the member silently would
    lower `severity_signal` or clear `corroboration_signal` and still return a confident
    bucket — an untraceable score, which is the one thing rule 5 forbids.

    Nothing deletes a finding today (G11 records that six tables depend on another module's
    rows never being deleted), so this is expected to be unreachable in production.
    It is a guard against the reads disagreeing, not a handled flow.
    """
