from datetime import datetime

from pydantic import BaseModel


class MatchKeyResponse(BaseModel):
    """The signal fields a Risk's findings share. Dedicated schema (rule 10).

    **`risk_engine`'s own, never `correlation`'s** — `cross-module-risk-engine` forbids that
    module's `adapters`. The same two fields the M5.2 route returns, which is what makes this
    response a superset of that one rather than a differently-shaped answer (**G66**).

    `project_id` is omitted because it is the path parameter, the same reason
    `FindingResponse` and `RiskResponse` omit it.
    """

    package: str | None
    url: str | None


class SignalResponse(BaseModel):
    """One scored term: its value, and **the member that produced it**.

    `produced_by` is what makes rule 5 hold rather than being asserted: a reader given
    `severity 4` cannot check it without being told which member was the `HIGH` one. The ids
    are `Finding` ids — handles into `GET /projects/{id}/findings/{fid}/evidence`, FR-9's link
    followed rather than inlined, and the same ids the item's `finding_ids` already carries,
    so this adds no new exposure.

    `note` says why a signal contributed nothing, and it is load-bearing rather than
    decorative: `Severity.UNKNOWN`'s rank is 0 and the no-member fallback is also 0, so the
    score is identical either way and only this field distinguishes "no member stated a
    severity" from a member that stated the lowest one.
    """

    name: str
    value: int
    produced_by: list[str]
    note: str | None


class RiskReasoningResponse(BaseModel):
    """The three signals behind a bucket. FR-7's traceability, ADR-0003's constraint.

    **Carries no `confidence`, and since M8.5 that is a PLACEMENT rather than an absence.**
    A scored Risk has one — see `ScoredRiskResponse.confidence` — and it sits on the ITEM,
    not here, because this type is the three signals that SUM to the score and the confidence
    is summed into nothing (ADR-0037 decision 7). A field here would read as a fourth term.
    *(Until M8.5 this paragraph recorded the absence itself, under **G63**: ADR-0005 deferred
    the scale and M6.2 emitted none, so FR-7's second output was unmet by shipped code at the
    surface a user sees. FR-7's OUTPUT half is now met; its INPUT half — a per-finding
    confidence — is still declined, and **G94** carries it.)*

    Carries no `explanation_text` either — prose is M7.1's, and the LLM narrates a reasoning
    already decided (rule 6, ADR-0004).
    """

    severity: SignalResponse
    exposure: SignalResponse
    corroboration: SignalResponse


class ScoredRiskResponse(BaseModel):
    """One scored Risk: what was scored, the number, the bucket, and the working.

    Dedicated schema, never `ScoredSurface` (rule 10). **The field list below is ADR-0030
    decision 3's enumeration and it is BINDING**: `test_scored_risks_routes.py` asserts this
    response's key set EQUALS it exactly, so an extra field and a missing field are both red.
    The absence assertions in that file constrain what must not appear and say nothing about
    what must, and **G66**'s claim that this response is a strict superset of `RiskResponse`
    holds only while `match` and `finding_count` are actually here.

    **A scored Risk scores a SURFACE, not a vulnerability** — ADR-0005 decision 0.
    `match.package`/`match.url` are the key's fields, so an item means "everything wrong with
    that package or route path". It is emphatically **not** "these findings describe the same
    vulnerability": membership is produced by the route map, and no available field separates
    a substantive cross-tool member from a coincidental one (**G62**). No text derived from
    this may say that two tools agree.

    **The top bucket is closed to every dependency finding, however severe.** `fix_now` has
    exactly one reachable decomposition — a route-path surface carrying both a SAST and a
    DAST member, with at least one `HIGH` member, which may come from either tool — so a
    `CRITICAL` package CVE tops out at `plan`. **G64** holds the derivation, and an
    integration test pins the consequence at this surface so that this paragraph is a claim
    rather than a comment.

    **No `id`**: a candidate Risk is a projection with no identity (ADR-0025 decision 1), and
    scoring adds a number to it without adding a row.

    **`confidence` is the surface's GROUPING PROVENANCE** (M8.5, ADR-0037): `reported` when
    every member was placed here by a field its own scanner reported, `inferred` when at
    least one was placed by Verion's route map, `ungrouped` when there was no signal to group
    on. It says nothing about whether a finding is real and nothing about whether the tools
    agree, and **it is not part of the score** — `priority_score` is the same three signals it
    has always been. Its meaning travels on the ENVELOPE as `confidence_definition`, once per
    response, because it is a constant: the same reason the thresholds sit there
    (ADR-0030 decision 3).
    """

    match: MatchKeyResponse
    finding_ids: list[str]
    finding_count: int
    priority_score: int
    priority: str
    reasoning: RiskReasoningResponse
    confidence: str


class ThresholdsResponse(BaseModel):
    """The bucket boundaries, so a reader can re-derive the BUCKET and not only the sum.

    ADR-0030 decision 3. `RiskReasoningResponse` makes the sum re-derivable by hand — each
    signal's value and its producer — but re-deriving which bucket that sum lands in needs
    these two numbers, and ADR-0005 decision 1 claims a bucket is re-derivable by hand. That
    claim is false at the surface without them.

    Populated by name from `FIX_NOW_AT` and `PLAN_AT` in `risk_engine/domain/scoring.py`,
    which is the one place they are declared, and a test asserts these values **are** those
    constants rather than literals — so the field cannot drift from the function it
    describes.

    On the envelope rather than on each item, because per item they would be a constant
    repeated once per surface — the speculative shape ADR-0016 decision 3 and ADR-0021 both
    refused. `monitor` has no constant: it is every score below `plan_at`.
    """

    fix_now_at: int
    plan_at: int


class NormalizationRunResponse(BaseModel):
    """The pipeline state behind a scored Risk listing.

    The same six fields `normalization`'s own route returns, and `failure_reason` is safe
    here for the reason it is safe there — it was enforced at the write, in M4.4, and
    `test_normalize_scan.py` is what keeps that honest. Returning fewer would be two routes
    answering one question differently, which is **G17**'s shape one level down (ADR-0025
    decision 4, inherited by ADR-0030 decision 4).

    **This field is the one place a `dedup_hash` can leave this route**, because
    `NormalizeScanUseCase` writes skipped groups' hashes into it deliberately. So
    `ScoredRiskResponse`'s "no `dedup_hash`" is a claim about a Risk's fields and not about
    every byte of the body — the same precision the two sibling routes draw, and both halves
    are pinned by tests rather than left to the docstrings.
    """

    scan_id: str
    status: str
    requested_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    failure_reason: str | None


class NormalizationStateResponse(BaseModel):
    """Whether this scored listing can be trusted to be complete.

    `unfinished_runs` is the load-bearing half, for ADR-0022 decision 3's reason. **The
    exposure is worse here than on either sibling route, which is why the envelope is carried
    rather than dropped:** a Risk is only as complete as the findings it correlated, so an
    unrecovered normalization can make this endpoint present a confident *priority order*
    built on findings that were never produced.

    The second-order exposure a Risk adds — looking fully evidenced while a constituent
    finding was never produced (G15) — is deliberately carried by no field; ADR-0025
    decision 4 says why a count of it would fabricate rather than report.
    """

    latest_run: NormalizationRunResponse | None
    unfinished_runs: int


class ScoredProjectRisksResponse(BaseModel):
    """A ranked page of a project's scored Risks.

    `total` is the project's whole scored-surface count and is exact rather than a second
    statement's answer. **Items ARE in priority order** — `priority_score` descending, tie-broken
    by `correlation`'s own group order so that within one bucket this route and
    `GET /projects/{id}/risks` agree. ~~That is the single difference between the two routes~~,
    and it is named in neither URL (**G66**). *(Struck M8.5: since ADR-0037 an item also
    carries `confidence` and this envelope carries `confidence_definition`, and `/risks`
    carries neither — so the order is no longer the only difference. It is still named in
    neither URL, and the superset relation is wider than it was.)*

    **`confidence_definition` is on the envelope and not on each item**, because it is one
    constant per response — ADR-0030 decision 3's own reason for putting the thresholds here,
    and `SignalResponse` on this route carries no `definition` either. A Brief carries the
    same text on its item, having no envelope to put it on, and a test asserts the two are
    byte-identical from `correlation`'s single declaration.
    """

    items: list[ScoredRiskResponse]
    total: int
    limit: int
    offset: int
    thresholds: ThresholdsResponse
    confidence_definition: str
    normalization: NormalizationStateResponse
