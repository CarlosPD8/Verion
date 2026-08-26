from datetime import datetime

from pydantic import BaseModel


class MatchKeyResponse(BaseModel):
    """The signal fields a Risk's findings share. Dedicated schema, never `MatchKey` (rule 10).

    `project_id` is omitted because it is the path parameter, the same reason `FindingResponse`
    omits it. Which fields the key carries, and why these and not others, is ADR-0023's
    2026-08-26 amendment section 3.
    """

    package: str | None
    url: str | None


class RiskResponse(BaseModel):
    """One candidate Risk: what its findings share, and which findings they are.

    The three declared fields are the whole schema (rule 10). `finding_ids` are handles into
    `GET /projects/{id}/findings/{fid}/evidence`, which is FR-9's link followed rather than
    inlined; `match` is the key the grouping is on.

    **A candidate Risk has no `id`** — ADR-0025 decision 1 records why, and why a derived one
    would be worse than none at all.

    Everything else this response is held to is the numbered list in ADR-0025 decision 5, each
    item pinned by a test in `tests/integration/test_risks_routes.py`. Two earlier drafts of
    this docstring summarised that list as a sentence about which fields are absent, and both
    were false; the summary is not attempted again.
    """

    match: MatchKeyResponse
    finding_ids: list[str]
    finding_count: int


class NormalizationRunResponse(BaseModel):
    """The pipeline state behind a Risk listing.

    The same six fields `normalization`'s own route returns, and `failure_reason` is safe here
    for the reason it is safe there — it was enforced at the write. Returning fewer would be
    two routes answering one question differently. ADR-0025 decision 4.

    **This field is the one place a `dedup_hash` can leave this route**, because
    `NormalizeScanUseCase` writes skipped groups' hashes into it deliberately. So `RiskResponse`'s
    "no `dedup_hash`" is a claim about a Risk's fields and not about every byte of the body —
    the same precision `normalization`'s own schema draws, and both halves are pinned by tests
    rather than left to the docstrings.
    """

    scan_id: str
    status: str
    requested_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    failure_reason: str | None


class NormalizationStateResponse(BaseModel):
    """Whether this Risk listing can be trusted to be complete.

    `unfinished_runs` is the load-bearing half, for the reason ADR-0022 decision 3 gives. The
    second-order exposure a Risk adds — a Risk looking fully evidenced while a constituent
    finding was never produced (G15) — is deliberately carried by no field; ADR-0025 decision 4
    says why a count of it would fabricate rather than report.
    """

    latest_run: NormalizationRunResponse | None
    unfinished_runs: int


class ProjectRisksResponse(BaseModel):
    """A page of a project's candidate Risks.

    `total` is the project's whole group count and is exact rather than a second statement's
    answer. Items are ordered by `_group_order`, which is total and deterministic — and is
    **not** a priority order; nothing here is scored (ADR-0025 decision 5).
    """

    items: list[RiskResponse]
    total: int
    limit: int
    offset: int
    normalization: NormalizationStateResponse
