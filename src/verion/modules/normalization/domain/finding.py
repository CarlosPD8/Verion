from collections.abc import Sequence
from dataclasses import dataclass, replace
from datetime import datetime

from verion.modules.normalization.domain.dedup import compute_dedup_hash
from verion.shared_kernel.scanner_tools import ScannerTool
from verion.shared_kernel.severity import Severity

# A single tool element can be pathological — a ZAP alert with thousands of
# instances, or a Trivy vulnerability with an unusually long description. Bounded
# so one finding can't bloat a row, and (once M4.5 surfaces it) a response. Same
# reasoning and same shape as RunScanUseCase._MAX_FAILURE_REASON_CHARS, with a
# larger budget because this payload is the evidence FR-9 requires, not an error
# message.
MAX_RAW_PAYLOAD_CHARS = 20_000

# The attributes merge_observation refreshes from a later observation. Every one
# derives from the RULE or the ADVISORY rather than from the individual match, so
# two findings sharing a dedup_hash inside one scan cannot disagree on any of
# them — which is what lets collapse_by_identity and merge_observation divide the
# work over disjoint field sets instead of competing. See ADR-0019.
_RULE_LEVEL_ATTRIBUTES = (
    "severity",
    "native_severity",
    "title",
    "cwe",
    "owasp_category",
    "cvss",
)


@dataclass(frozen=True)
class Location:
    """Where a finding is, across three tools that mean different things by it.

    Semgrep locates a finding in a file at a line range; Trivy locates it in a
    package pinned by a manifest, with no line; ZAP locates it at a URL, method
    and parameter. Every field is nullable and each tool populates the subset it
    actually knows.

    **Deliberately one flat shape rather than a tagged union of three.** A union
    would force every downstream reader to branch on which tool produced the
    finding — `if isinstance(loc, SemgrepLocation)` — which is per-tool knowledge
    living downstream of `normalization`, the exact leak CLAUDE.md forbids. Flat
    nullable fields let M5 ask "do these two findings share a file_path?" without
    knowing, or caring, which tools they came from. That question is the whole
    point of correlation.

    **An all-None Location is allowed, and there is deliberately no guard against
    it.** An earlier draft raised when nothing was set, on the reasoning that a
    finding must be locatable somewhere. A ZAP site-level alert with an empty
    `instances` list disproved it — that alert is real output, and the guard
    turned it into an exception raised in the middle of mapping, which would take
    down normalization for every *other* finding in the same scan. That is the
    partial-failure corruption `PRODUCT_SPEC.md` §12 forbids, arriving by way of
    a validation rule. An empty Location is unhelpful but honest: it says the
    tool did not tell us where, which is the same contract every nullable field
    on `Finding` already has.

    **Five of these eight fields carry identity and three do not** —
    `start_line`, `end_line` and `installed_version` are excluded from
    `dedup_hash` and refresh on every sighting. `compute_dedup_hash`'s signature
    is where that split is stated; it is recorded here too because a reader
    adding a field to this class needs to decide which kind it is.
    """

    file_path: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    package: str | None = None
    installed_version: str | None = None
    url: str | None = None
    http_method: str | None = None
    parameter: str | None = None


@dataclass(frozen=True)
class Evidence:
    """The tool's own words for one finding, kept verbatim (FR-9).

    `raw_payload` is a **copy of the single source element** — one entry of
    Semgrep's `results[]`, one of Trivy's `Vulnerabilities[]`, one of ZAP's
    `alerts[]` narrowed to a single instance — not a reference into
    `ScanResult.raw_output`. A reference would dangle by design here:
    `RunScanUseCase` upserts on `(scan_id, tool)` and a retry re-runs every
    enabled scanner (ADR-016 decision 1), so that blob can be replaced by a later
    attempt's output, or nulled entirely if the retry's run of that tool fails.
    An index into it breaks silently, and silently is the worst way for evidence
    to break.

    It is also what keeps per-tool structure *out* of the common schema: anything
    a mapper could not normalize is still here, addressable by whoever needs it,
    without `correlation` or `risk_engine` learning a tool's field names.

    **`scan_id` is the payload's provenance, and it is why `Finding` can drop the
    field entirely.** A `Finding` now outlives the scan that first produced it,
    so "which scan produced the evidence you are showing me?" stopped being
    answerable from the finding. Evidence holds the *latest* observation's
    payload (see `merge_observation`), and this records which scan that was.
    """

    id: str
    finding_id: str
    scan_id: str
    raw_payload: str
    source_tool: ScannerTool
    captured_at: datetime

    def __post_init__(self) -> None:
        if len(self.raw_payload) > MAX_RAW_PAYLOAD_CHARS:
            raise ValueError(
                f"Evidence raw_payload for finding '{self.finding_id}' is "
                f"{len(self.raw_payload)} chars, over the {MAX_RAW_PAYLOAD_CHARS} limit — "
                f"mappers must truncate before constructing Evidence"
            )


@dataclass(frozen=True)
class Finding:
    """One normalized security finding, from any scanner.

    Everything downstream of `normalization` speaks this schema and only this
    schema. The per-scanner mappers in `domain/mappers/` are the only code in the
    project that knows what a Semgrep result or a ZAP alert looks like.

    **A `Finding` is durable and project-scoped, not scan-scoped** — the decision
    G5 named and ADR-0019 records. It is identified by `dedup_hash`, and each
    scan that observes it records a `FindingSighting`. That is what makes FR-5's
    "deduplication across repeated scans" expressible at all: with a single
    `scan_id` either the same underlying finding got a fresh row per scan (so
    nothing deduped) or the first row was kept with a stale `scan_id` (so nothing
    recorded it was seen again), and M9.1 could not tell "still present" from
    "last seen three scans ago".

    Note what is deliberately *absent*: no `last_seen_at`, no `last_seen_scan_id`.
    Both are `max()` over the sightings, and denormalizing them here would put a
    derived summary that can silently go stale into M9.1's path — the failure
    ADR-016 decision 2 legislated against for `Scan.status`, arriving one table
    over.

    **A field with no source is `None`, never `""` and never a guess.** The three
    tools populate different subsets — Trivy alone supplies CVSS, only Semgrep
    can supply an OWASP category, and it does so only when the rule declares it.
    A mapper that invented a value would be feeding the Risk Engine an input
    nothing can trace, which is rule 5 violated one layer upstream of where
    anyone would look for it. Same reasoning ADR-016 decision 2 used to make
    `ScanResult.raw_output` nullable rather than `""`.

    `severity` is the normalized scale; `native_severity` is what the tool
    literally said, so the collapse of three scales into one stays lossy for
    ordering without being lossy for provenance (FR-9). See ADR-0018.

    `rule_id` is the tool's own stable identifier for *what fired* — Semgrep's
    `check_id`, Trivy's `VulnerabilityID`, ZAP's `alertRef`. It exists because
    the common schema had nowhere to put it: `title` melts the identifier
    together with advisory-mutable prose (`"CVE-2019-11324: python-urllib3:
    Certification mishandle…"`), so hashing `title` would re-key every Trivy
    finding the first time an advisory's wording changed. It earns its place
    beyond identity too — M5 groups by rule across scans, M6 explains by it, M8
    filters on it, and none of them can get it out of `title`.

    **What the mappers' `"(unidentified)"` fallback does and does not buy**, said
    plainly because the obvious reading is wrong: it makes the absence *visible*
    rather than empty, and it does **not** remove the collision it looks like it
    prevents. Two findings whose tool named no rule, at the same location, hash
    identically — a shared constant merges exactly as `""` would. That merge is
    the under-count side of ADR-0019's principle and is acceptable. **What the
    *use case* does when two such findings then disagree on a rule-level attribute
    — so `collapse_by_identity` raises — was decided in M4.4** (ADR-0021 decision
    5): `NormalizeScanUseCase` calls that function once per identity group, so the
    raise drops one group instead of aborting a whole scan's normalization, and
    the run is marked `failed` carrying the count and the hashes so the drop is
    recorded rather than silent. Latent rather than live, and measured: all 30
    elements across the six committed fixtures carry their tool's identifier, so
    nothing captured reaches this fallback at all.

    `confidence` is still absent and still M6.1's to add or decline: only ZAP
    supplies it, as an opaque numeric code whose vocabulary mixes degrees with
    states, and `RiskReasoning`'s five signals do not include it (ADR-0018).
    """

    id: str
    project_id: str
    source: ScannerTool
    rule_id: str
    severity: Severity
    native_severity: str
    title: str
    location: Location
    evidence: Evidence
    cwe: str | None = None
    owasp_category: str | None = None
    cvss: float | None = None

    @property
    def dedup_hash(self) -> str:
        """This finding's identity — derived, never assigned.

        A property rather than a constructor field so it cannot drift from the
        fields it is over and cannot be forged by a caller, which is also why
        there is no `__post_init__` guard for it: there is nothing to check.
        M4.3 persists it as a column because the unique index
        `(project_id, dedup_hash)` needs one; that column is a materialization of
        this property, not a second source of truth.
        """
        return compute_dedup_hash(
            source=self.source,
            rule_id=self.rule_id,
            file_path=self.location.file_path,
            package=self.location.package,
            url=self.location.url,
            http_method=self.location.http_method,
            parameter=self.location.parameter,
        )

    def __post_init__(self) -> None:
        if self.evidence.finding_id != self.id:
            raise ValueError(
                f"Evidence '{self.evidence.id}' is attached to finding '{self.id}' but "
                f"carries finding_id '{self.evidence.finding_id}'"
            )
        if self.evidence.source_tool is not self.source:
            raise ValueError(
                f"Finding '{self.id}' came from '{self.source}' but its evidence records "
                f"'{self.evidence.source_tool}'"
            )
        if not self.native_severity:
            raise ValueError(
                f"Finding '{self.id}' has an empty native_severity — a mapper must record "
                f"what the tool actually said, even when it said something unrecognised"
            )
        if not self.rule_id:
            raise ValueError(
                f"Finding '{self.id}' has an empty rule_id — a mapper must record the tool's "
                f"identifier, or a labelled fallback when the tool gave none, the same way "
                f"native_severity does. An empty one is a mapper bug, not a tool's silence"
            )


@dataclass(frozen=True)
class FindingSighting:
    """One scan's observation of one `Finding`.

    Composite natural key `(finding_id, scan_id)` and no surrogate id, following
    `ProjectMembership`: there is nothing to address a sighting by other than the
    pair it joins.

    **Absence is the point.** "Not sighted in scan N" is the absence of a row,
    and "scan N was never normalized" is `normalization_runs` — which by ADR-0017
    decision 3 exists iff `ScanResult` rows were persisted. The two records
    compose into the distinction M9.1 needs, with no third state and nothing to
    keep in sync.

    `match_count` is how many source elements collapsed into this identity in
    this scan. It exists because `dedup_hash` deliberately excludes line numbers,
    so two matches of one Semgrep rule in one file become one `Finding` — an
    under-count that would otherwise be invisible. Two matches is a different
    signal from one, which M5 and M6 will want.

    Written by the normalization use case (M4.4), never by a mapper: a mapper
    cannot know a finding's resolved `id`, since identity is the hash and `id` is
    a surrogate that only the repository's upsert settles.
    """

    finding_id: str
    scan_id: str
    observed_at: datetime
    match_count: int = 1

    def __post_init__(self) -> None:
        if self.match_count < 1:
            raise ValueError(
                f"FindingSighting for finding '{self.finding_id}' in scan '{self.scan_id}' "
                f"has match_count {self.match_count} — a sighting means the finding was "
                f"observed at least once"
            )


def merge_observation(existing: Finding, observed: Finding) -> Finding:
    """Fold a later scan's observation into the stored `Finding`.

    Across scans. `collapse_by_identity` is the within-a-scan counterpart, and
    the two divide the work over **disjoint field sets** rather than competing —
    see that function's docstring.

    Frozen: `id`, `project_id`, and everything `dedup_hash` is over. Refreshed:
    the rule-level attributes, the whole `Location` (so `start_line` and
    `installed_version` track the current state of the code), and the evidence.

    **The evidence refresh is latest-wins, unconditionally, and that has a cost
    worth naming rather than implying.** A later scan can observe the same
    finding with a *poorer* payload — a Trivy entry caught mid-advisory-update
    with a shorter description — and the richer earlier one is replaced. It is
    still the right default: FR-9 asks for the tool output that produced *this*
    assessment, not the best output ever seen, so a Brief citing text the current
    scan did not produce would be a traceability defect dressed as generosity.
    Preferring the older payload would also require deciding which is "richer",
    which means either a size heuristic or per-tool field comparison — the leak
    the common schema exists to prevent. `ScanResult.raw_output` remains the
    floor: every past scan's full output is still on disk, keyed by scan.
    M9.2's before/after evidence view is the trigger for revisiting this.

    A mismatched hash raises rather than degrading. Unlike an unrecognised
    severity string — upstream data from a tool that can change in any release —
    this can only mean a caller merged two different findings, which is a
    programming error and should fail where it happens (ADR-0018 decision 1's
    raise-versus-degrade line).
    """
    if existing.dedup_hash != observed.dedup_hash:
        raise ValueError(
            f"Cannot merge finding '{observed.id}' into '{existing.id}': their dedup_hash "
            f"values differ ({observed.dedup_hash} vs {existing.dedup_hash}), so they are "
            f"not the same finding"
        )
    if existing.project_id != observed.project_id:
        raise ValueError(
            f"Cannot merge finding '{observed.id}' from project "
            f"'{observed.project_id}' into '{existing.id}' from project "
            f"'{existing.project_id}' — findings dedup within a project, never across"
        )
    return replace(
        observed,
        id=existing.id,
        evidence=replace(
            observed.evidence,
            id=existing.evidence.id,
            finding_id=existing.id,
        ),
    )


def _representative_key(finding: Finding) -> tuple[bool, int, bool, int, bool, str, str]:
    """A total order over the fields `dedup_hash` excludes.

    Total, so the representative of a collapsed group never depends on the order
    the mapper happened to emit its findings in. "Lowest start_line" alone would
    have left Trivy and ZAP groups — where every line field is `None` — falling
    back to list order, which is precisely the mistake ZAP's own `instances[0]`
    is the record of: those instances arrive in crawl order, not sorted.

    `None` sorts first (`False < True`). `raw_payload` is a last-resort tiebreak:
    two members with an identical key are indistinguishable by construction.
    """
    location = finding.location
    return (
        location.start_line is not None,
        location.start_line or 0,
        location.end_line is not None,
        location.end_line or 0,
        location.installed_version is not None,
        location.installed_version or "",
        finding.evidence.raw_payload,
    )


def collapse_by_identity(findings: Sequence[Finding]) -> list[tuple[Finding, int]]:
    """Collapse one scan's findings that share an identity, with their counts.

    Within a scan. `merge_observation` is the across-scans counterpart.

    Returns `(representative, match_count)` pairs, ordered by `dedup_hash` so the
    result is deterministic regardless of input order.

    **The two functions cannot disagree, and the reason is structural.** Every
    attribute `merge_observation` refreshes derives from the rule or the advisory
    rather than from the individual match — Semgrep's severity and metadata are
    per-rule, Trivy's severity, CVSS, title and CweIDs are per-advisory, ZAP's
    riskcode and cweid are per-alert — and a shared `dedup_hash` already pins
    `source` and `rule_id`. So the fields that can differ inside a group are
    exactly the ones the hash excludes for positional reasons, and the
    representative choice never competes with the merge's precedence.

    That is asserted rather than assumed, because "two matches of one rule carry
    the same severity" is the kind of "should" that stops being true without
    anything noticing. A disagreement means a mapper derived a rule-level
    attribute from a match-level field — a programming error, so it raises.
    """
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.dedup_hash, []).append(finding)

    collapsed: list[tuple[Finding, int]] = []
    for dedup_hash in sorted(grouped):
        group = grouped[dedup_hash]
        representative = min(group, key=_representative_key)
        # `dedup_hash` excludes the project deliberately — scope is the UNIQUE
        # constraint, not a hash input — so grouping by it alone would merge
        # across projects if a caller ever mixed them. Inert today (one scan is
        # one project), and guarded anyway so this function enforces the same
        # boundary merge_observation does; a matched pair where only one half
        # checks the scope is a pair that will be relied on for both.
        for other in group:
            if other.project_id != representative.project_id:
                raise ValueError(
                    f"Findings sharing dedup_hash '{dedup_hash}' span projects "
                    f"'{representative.project_id}' and '{other.project_id}' — findings "
                    f"dedup within a project, never across"
                )
        for attribute in _RULE_LEVEL_ATTRIBUTES:
            expected = getattr(representative, attribute)
            for other in group:
                if getattr(other, attribute) != expected:
                    raise ValueError(
                        f"Findings sharing dedup_hash '{dedup_hash}' disagree on "
                        f"'{attribute}' ({expected!r} vs {getattr(other, attribute)!r}) — "
                        f"that attribute is rule-level, so a mapper has derived it from a "
                        f"match-level field"
                    )
        collapsed.append((representative, len(group)))
    return collapsed
