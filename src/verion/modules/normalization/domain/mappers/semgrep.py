import json
from typing import Any

from verion.modules.normalization.domain.cwe import canonical_cwe
from verion.modules.normalization.domain.finding import (
    MAX_RAW_PAYLOAD_CHARS,
    Evidence,
    Finding,
    Location,
)
from verion.shared_kernel.ports import ClockPort, IdGeneratorPort
from verion.shared_kernel.scanner_tools import ScannerTool
from verion.shared_kernel.severity import Severity

# Semgrep's three levels stretched across the normalized five. ERROR is Semgrep's
# *maximum*, so it maps to HIGH rather than CRITICAL: Trivy choosing HIGH means it
# had CRITICAL available and declined it, while Semgrep never had the option.
# Reserving CRITICAL for tools that can express it keeps that distinction real
# instead of inflating every SAST finding to the top of the scale. What is lost —
# relative position within each tool's own scale — is recorded in ADR-0018 and is
# why `source` stays a scoring input for M6.
_SEVERITY: dict[str, Severity] = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.INFO,
}


def _first(value: Any) -> Any:
    """Semgrep metadata fields are sometimes a list, sometimes a bare string."""
    if isinstance(value, list):
        return value[0] if value else None
    return value


def map_semgrep_output(
    *,
    project_id: str,
    scan_id: str,
    raw_output: str,
    id_generator: IdGeneratorPort,
    clock: ClockPort,
) -> list[Finding]:
    """Maps one Semgrep `--json` document to Findings. Pure: no I/O, no adapters.

    `raw_output` is `str`, not `str | None`, because every row
    `get_succeeded_by_scan_id` returns carries non-null output — guaranteed by
    `ck_scan_results_outcome_shape`, not by convention (ADR-016 decision 2).

    `project_id` is the dedup scope: findings dedupe within a project and never
    across one (`ARCHITECTURE.md` §4, ADR-0019). `scan_id` no longer lands on the
    `Finding` — it survives only as `Evidence.scan_id`, the provenance of the
    retained payload, because a `Finding` now outlives the scan that produced it.
    Neither this function nor its callers create `FindingSighting` rows: a mapper
    cannot know a finding's resolved `id`, so that is M4.4's job.

    **Two fields this deployment can never populate from Semgrep**, verified
    against real captured output rather than assumed: `extra.fingerprint` and
    `extra.lines` are both the literal string `"requires login"` for anonymous
    Semgrep OSS, and this project sets no `SEMGREP_APP_TOKEN` anywhere. So
    `lines` carries no source code, and `fingerprint` is unusable as an identity
    input — which also removes the only discriminator that would have let two
    matches of one rule in one file stay distinct without putting line numbers
    into `dedup_hash` (G7, ADR-0019).

    **`path` and `check_id` are both `dedup_hash` inputs, and both were unstable
    in production until M4.4 (G9, G10 — now closed).** Semgrep renders each of
    them relative to the process's working directory, and `SemgrepAdapter` used to
    pass an absolute `tempfile.mkdtemp` target from its own CWD — so `path`
    carried a different prefix on every scan and `check_id` a different one on
    every install. Both fixes are in the adapter and neither is here: it runs with
    `cwd=<checkout>`, passes `.`, and adds `--no-rewrite-rule-ids`.

    That division is the reason this mapper needed no change for either. `path`
    and `check_id` are copied verbatim, exactly as `native_severity` is: what the
    tool said is what gets recorded, and making an identity input *stable* is a
    question about how the tool is invoked, never about how its output is read.
    Normalizing `check_id` here was the obvious-looking alternative and is ruled
    out in G10 on ADR-0019 decision 3's own principle — stripping to the last
    dotted segment collapses registry namespaces, fabricating merges rather than
    under-counting.
    """
    document = json.loads(raw_output)
    findings: list[Finding] = []

    for result in document.get("results") or []:
        native_severity = str(result.get("extra", {}).get("severity", ""))
        metadata = result.get("extra", {}).get("metadata") or {}
        start = result.get("start") or {}
        end = result.get("end") or {}

        finding_id = id_generator.new_id()
        payload = json.dumps(result, sort_keys=True)
        check_id = str(result.get("check_id") or "")
        findings.append(
            Finding(
                id=finding_id,
                project_id=project_id,
                source=ScannerTool.SEMGREP,
                # Semgrep's own stable identifier for what fired, copied
                # verbatim. It is genuinely stable as of M4.4 — until then it
                # embedded the `--config` path rendered relative to the worker's
                # CWD, so moving `rulesets/default.yml`, redeploying to a
                # different install path, or changing a container WORKDIR each
                # re-keyed every Semgrep finding (G10). Closed in the adapter with
                # `--no-rewrite-rule-ids`, not here — see this function's
                # docstring for why the fix cannot be a mapper transform.
                rule_id=check_id or "(unidentified)",
                # An unrecognised level degrades to UNKNOWN rather than raising.
                # A severity string is upstream data from a tool that can add a
                # level in any release; an unknown *tool name* raises and fails
                # the scan (ADR-016 decision 2) because that is deployment
                # configuration this project controls. See ADR-0018.
                severity=_SEVERITY.get(native_severity.upper(), Severity.UNKNOWN),
                native_severity=native_severity or "(absent)",
                title=check_id or "(unnamed semgrep rule)",
                location=Location(
                    file_path=str(result.get("path")) if result.get("path") else None,
                    start_line=start.get("line"),
                    end_line=end.get("line"),
                ),
                evidence=Evidence(
                    id=id_generator.new_id(),
                    finding_id=finding_id,
                    scan_id=scan_id,
                    raw_payload=payload[:MAX_RAW_PAYLOAD_CHARS],
                    source_tool=ScannerTool.SEMGREP,
                    captured_at=clock.now(),
                ),
                # Both come from rule-author metadata. The ruleset this project
                # pins declares none, so both are None in production today —
                # tracked as G6, not worked around here by inventing a value.
                cwe=canonical_cwe(_first(metadata.get("cwe"))),
                owasp_category=(
                    str(_first(metadata.get("owasp")))
                    if _first(metadata.get("owasp")) is not None
                    else None
                ),
                # Semgrep emits no CVSS at all.
                cvss=None,
            )
        )

    return findings
