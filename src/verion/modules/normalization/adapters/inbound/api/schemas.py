from datetime import datetime

from pydantic import BaseModel


class LocationResponse(BaseModel):
    """Dedicated response schema, never the domain Location directly (rule 10)."""

    file_path: str | None
    start_line: int | None
    end_line: int | None
    package: str | None
    installed_version: str | None
    url: str | None
    http_method: str | None
    parameter: str | None


class EvidenceMetadataResponse(BaseModel):
    """What a LISTING says about a finding's evidence — everything except the payload.

    **The omission is the schema's reason for existing** (rule 10, rule 12).
    `raw_payload` is a verbatim copy of a scanned source element; returning one
    per item would make every listing a bulk source-code export. It is reachable
    one finding at a time at `/findings/{finding_id}/evidence`, which is FR-9's
    "link back to the tool output" followed rather than inlined.

    `payload_chars` is here so a client can tell a 300-byte Semgrep result from a
    10 KB Trivy advisory before deciding to fetch it. `id` and `finding_id` are
    omitted: they are surrogate keys of a 1:1 row that nothing addresses by them.
    """

    scan_id: str
    source_tool: str
    captured_at: datetime
    payload_chars: int


class FindingResponse(BaseModel):
    """Dedicated response schema, never the domain Finding directly (rule 10).

    **`dedup_hash` is deliberately absent — as a FIELD, which is the precise
    claim and was not always how this was worded.** It is internal identity
    carrying a version prefix, and a *field* invites a client to key on it, which
    would turn a `v2:` bump — already a re-normalization (ADR-0019 decision 6) —
    into a breaking API change on top of one. `id` is the addressable handle.

    The precision matters because hashes **do** reach this API by one other route,
    and an unqualified "never exposed" would have been false: when
    `collapse_by_identity` rejects a group, `NormalizeScanUseCase` records the
    skipped groups' `dedup_hash` values in `NormalizationRun.failure_reason`, and
    `NormalizationRunResponse` returns that. That is deliberate and is not the
    hazard above — nobody keys an API client on a substring of a human-readable
    diagnostic, and the identifier is the whole point of that message: it is how a
    person finds which groups were dropped. See `NormalizationRunResponse` and
    ADR-0022 decision 1.

    `project_id` is absent too: it is the path parameter, so repeating it on every
    item is noise.

    **`rule_id` and `location.file_path` are present, and they are the two fields
    G9 and G10 name.** Both entries record "M4.5 returns an absolute worker
    filesystem path in a response body" as a consequence of Semgrep's invocation.
    M4.4 closed that with `cwd=target` and `--no-rewrite-rule-ids`; a route test
    asserts neither field is an absolute path in a real-pipeline response, which
    is that consequence checked on the side it would have shown.

    The sighting fields are derived per request, never stored — ADR-0019 decision
    1 forbids the columns and states that both are `max()` over sightings.
    `last_seen_at` says WHEN a finding was last observed and never whether it is
    resolved; see `ListProjectFindingsUseCase`.
    """

    id: str
    source: str
    rule_id: str
    severity: str
    native_severity: str
    title: str
    cwe: str | None
    owasp_category: str | None
    cvss: float | None
    location: LocationResponse
    evidence: EvidenceMetadataResponse
    first_seen_at: datetime
    last_seen_at: datetime
    last_seen_scan_id: str
    sighting_count: int
    latest_match_count: int


class NormalizationRunResponse(BaseModel):
    """The pipeline state behind a findings list.

    `failure_reason` is returned, and that is safe by design rather than by luck:
    `NormalizeScanUseCase` persists the exception TYPE only on the transient
    branch — because SQLAlchemy's `StatementError.__str__` renders
    `[parameters: ...]`, which for the finding upsert means `title` and
    `raw_payload` — and only a count plus `dedup_hash` values on the skip branch.
    Both comments there name this endpoint as the reason, and the assertion that
    keeps the transient branch honest is `test_normalize_scan.py`'s, shipped with
    that branch in M4.4 rather than here.

    **So this field is the one place a `dedup_hash` can leave the system**, and
    `FindingResponse`'s "deliberately absent" is a claim about fields, not about
    every byte of every response. Deliberate: the identifier is what makes the
    message actionable, and a hash inside a bounded free-text diagnostic is not
    the API-versioning coupling a `dedup_hash` *field* would create.
    `test_findings_routes.py` covers this path explicitly, because a test that
    only ever seeds a healthy project would assert "never exposed" while never
    visiting the branch that exposes it.
    """

    scan_id: str
    status: str
    requested_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    failure_reason: str | None


class NormalizationStateResponse(BaseModel):
    """Whether this findings list can be trusted to be complete.

    **`unfinished_runs` is the field that does the work.** A project whose most
    recent scan normalized cleanly while three earlier ones failed reports
    `completed` in `latest_run` and looks healthy, while three scans' findings
    were never produced. Without this count, a list shortened by a normalization
    failure is indistinguishable from a clean project — which is G15's own
    description of the gap this narrows.

    It narrows it rather than closing it: a transient failure that exhausts arq's
    retries is still never re-enqueued, because the sweep excludes `failed`. What
    ships here is the visibility half.
    """

    latest_run: NormalizationRunResponse | None
    unfinished_runs: int


class ProjectFindingsResponse(BaseModel):
    """A page of findings, plus what it says about its own completeness.

    `total` is the count matching the same filters, not the project's whole
    population. It comes from a second statement, so under Postgres's default READ
    COMMITTED a normalization committing between the two can leave it disagreeing
    with `items` by a row — the same class of inconsistency offset paging already
    carries, bounded the same way (writes arrive per scan, not continuously).
    """

    items: list[FindingResponse]
    total: int
    limit: int
    offset: int
    normalization: NormalizationStateResponse


class EvidenceResponse(BaseModel):
    """One finding's verbatim tool output. **The rule-12 surface of this module.**

    `raw_payload` is a copy of a single element of a scanner's report — for
    Semgrep that includes `extra.lines`, the matched source line. See
    `GetFindingEvidenceUseCase` for why this is a route of its own and for G7,
    which records that a `SEMGREP_APP_TOKEN` arms it with no code change.

    **`raw_payload` is an opaque string. Do not parse it unless
    `payload_truncated` is false.** It is never re-serialized on the way out,
    because re-serializing would mutate the verbatim copy ADR-0018 decision 6
    requires; where the character cap fired it is a prefix that is no longer valid
    JSON. The whole element is always recoverable from `ScanResult.raw_output`,
    keyed by the `scan_id` here.
    """

    finding_id: str
    scan_id: str
    source_tool: str
    captured_at: datetime
    raw_payload: str
    payload_truncated: bool
