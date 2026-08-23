from dataclasses import dataclass
from datetime import datetime

from verion.shared_kernel.scanner_tools import ScannerTool
from verion.shared_kernel.severity import Severity

# A single tool element can be pathological — a ZAP alert with thousands of
# instances, or a Trivy vulnerability with an unusually long description. Bounded
# so one finding can't bloat a row, and (once M4.5 surfaces it) a response. Same
# reasoning and same shape as RunScanUseCase._MAX_FAILURE_REASON_CHARS, with a
# larger budget because this payload is the evidence FR-9 requires, not an error
# message.
MAX_RAW_PAYLOAD_CHARS = 20_000


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
    `alerts[]` — not a reference into `ScanResult.raw_output`. A reference would
    dangle by design here: `RunScanUseCase` upserts on `(scan_id, tool)` and a
    retry re-runs every enabled scanner (ADR-016 decision 1), so that blob can be
    replaced by a later attempt's output, or nulled entirely if the retry's run
    of that tool fails. An index into it breaks silently, and silently is the
    worst way for evidence to break.

    It is also what keeps per-tool structure *out* of the common schema: anything
    a mapper could not normalize is still here, addressable by whoever needs it,
    without `correlation` or `risk_engine` learning a tool's field names.
    """

    id: str
    finding_id: str
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

    Two fields `ARCHITECTURE.md` §4 once listed are deliberately absent, each
    because the issue that can decide it properly is not this one:
    `confidence` (M6.1 — only ZAP supplies it, as an opaque numeric code, and its
    vocabulary mixes degrees with states) and `dedup_hash` (M4.2 — computing one
    here would mean inventing the identity rule that issue exists to decide).
    """

    id: str
    scan_id: str
    source: ScannerTool
    severity: Severity
    native_severity: str
    title: str
    location: Location
    evidence: Evidence
    cwe: str | None = None
    owasp_category: str | None = None
    cvss: float | None = None

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
