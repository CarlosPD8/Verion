from typing import Protocol

from verion.modules.normalization.domain.finding import Finding, FindingSighting


class FindingRepositoryPort(Protocol):
    """Persistence for the identity model ADR-0019 decided.

    Every read here is **by a key**. A filtered or paginated listing is not
    missing by oversight: it would encode a staleness rule, an ordering and a
    filter vocabulary that are M4.5's to choose, which is the same line ADR-0017
    decision 2 drew between shipping `get_by_scan_id` and deferring the sweep
    query. The key-based reads ship now because without them the write path
    could only be verified by asserting on the adapter's own ORM model, which is
    testing the adapter with the adapter.
    """

    async def upsert(self, finding: Finding) -> Finding:
        """Insert this finding, or fold it into the stored one, and return the result.

        **`merge_observation` is the executable spec for what this does**, and
        implementations must not re-invent the policy in an `ON CONFLICT DO
        UPDATE` clause. The two agree because that function's refresh set is
        *total except the two surrogate ids*: it keeps `existing.id` and
        `existing.evidence.id` and takes every other value from the observation.
        See ADR-0020 — including the condition under which that equivalence
        stops holding.

        **Returns the resolved `Finding`, and the return type is load-bearing.**
        Identity is the hash and `id` is a surrogate, so only this upsert settles
        which id wins (ADR-0019 decision 1). `NormalizeScanUseCase` cannot
        construct a `FindingSighting` without it, and since M4.4 it does exactly
        that: `finding_id=stored.id`, never the observation's own. That is why
        this returns a value where
        `NormalizationRunRepositoryPort.request` returns `None`: there, both
        outcomes of the conflict mean the same thing to the caller and no caller
        branches; here the caller's next write depends on the answer.
        """
        ...

    async def record_sighting(self, sighting: FindingSighting) -> None:
        """Record that this scan observed this finding. Idempotent.

        **`match_count` is the complete per-scan total, never an increment**, and
        this method overwrites it rather than adding to it. That is the contract,
        not an implementation detail:

        - Overwriting is the only *idempotent* option, and idempotency is the
          requirement — `ARCHITECTURE.md` §9 says re-normalizing a scan refreshes
          rows rather than adding them, and an arq retry re-running every enabled
          scanner is guaranteed rather than hypothetical (ADR-016 decision 1).
        - Summing would therefore double-count on every retry, silently.
        - `ON CONFLICT DO NOTHING` would leave a stale count and never refresh
          `observed_at`. ADR-0017's reason for choosing it there does not
          transfer: that row carries a state machine `DO UPDATE` would reset, and
          a sighting has none.

        So a caller that computes the total in more than one pass over a scan
        must **aggregate before calling**, not call twice. `collapse_by_identity`
        produces the total in one pass, which is what makes `NormalizeScanUseCase`
        satisfy this — it maps every succeeded tool's output into ONE list and
        collapses that, rather than batching per tool;
        per-tool batching is also safe by construction, since `source` is a
        `dedup_hash` input and no `(finding_id, scan_id)` can span two tools.
        Chunking *within* one tool's output is the case that would break it.
        """
        ...

    async def get_by_project_id(self, project_id: str) -> list[Finding]: ...

    async def get_sightings_by_finding_id(self, finding_id: str) -> list[FindingSighting]: ...
