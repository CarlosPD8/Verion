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

# The only tool with a level above HIGH, and the only one that emits UNKNOWN
# literally. UNKNOWN is carried through rather than folded into LOW or MEDIUM:
# collapsing it would have this mapper invent a Risk Engine input, which rule 5
# exists to prevent. See ADR-0018.
_SEVERITY: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.UNKNOWN,
}

# NVD first, then these, then any remaining vendor. Trivy keys CVSS by vendor and
# they disagree; picking deterministically matters because M6 compares the number
# across findings, and "whichever vendor happened to be first in the dict" is not
# a comparison anyone could trace back (rule 5).
_CVSS_VENDOR_PREFERENCE = ("nvd", "redhat", "ghsa")


def _v3_score(cvss: dict[str, Any] | None) -> float | None:
    """The CVSS v3 base score, preferring NVD.

    **v3 only, never v2.** Trivy supplies both for older CVEs, and they are
    different scales — a v2 6.8 and a v3 6.8 do not mean the same thing. Mixing
    them in one float would make M6's severity_signal compare incomparable
    numbers, which is a rule-5 violation dressed up as arithmetic. A CVE with
    only a v2 score yields None, which correctly means "no comparable score",
    not "no severity" — Severity is mapped separately and is unaffected.
    """
    if not cvss:
        return None
    ordered = [v for v in _CVSS_VENDOR_PREFERENCE if v in cvss]
    ordered += sorted(v for v in cvss if v not in _CVSS_VENDOR_PREFERENCE)
    for vendor in ordered:
        score = (cvss.get(vendor) or {}).get("V3Score")
        if isinstance(score, int | float):
            return float(score)
    return None


def map_trivy_output(
    *,
    scan_id: str,
    raw_output: str,
    id_generator: IdGeneratorPort,
    clock: ClockPort,
) -> list[Finding]:
    """Maps one `trivy fs --format json` document to Findings. Pure: no I/O.

    Note `Vulnerabilities` is genuinely absent *or* explicitly `null` on a result
    with no findings — `test_trivy_adapter.py` already works around the same
    thing with `r.get("Vulnerabilities") or []`, and this mapper does likewise.
    """
    document = json.loads(raw_output)
    findings: list[Finding] = []

    for result in document.get("Results") or []:
        target = result.get("Target")
        for vulnerability in result.get("Vulnerabilities") or []:
            native_severity = str(vulnerability.get("Severity", ""))
            finding_id = id_generator.new_id()
            payload = json.dumps(vulnerability, sort_keys=True)

            vulnerability_id = vulnerability.get("VulnerabilityID") or "(unidentified)"
            title = vulnerability.get("Title")
            findings.append(
                Finding(
                    id=finding_id,
                    scan_id=scan_id,
                    source=ScannerTool.TRIVY,
                    severity=_SEVERITY.get(native_severity.upper(), Severity.UNKNOWN),
                    native_severity=native_severity or "(absent)",
                    # The CVE id leads: it is what a developer searches for, and
                    # Title is absent on some advisories.
                    title=f"{vulnerability_id}: {title}" if title else str(vulnerability_id),
                    location=Location(
                        file_path=str(target) if target else None,
                        package=(
                            str(vulnerability.get("PkgName"))
                            if vulnerability.get("PkgName")
                            else None
                        ),
                        installed_version=(
                            str(vulnerability.get("InstalledVersion"))
                            if vulnerability.get("InstalledVersion")
                            else None
                        ),
                    ),
                    evidence=Evidence(
                        id=id_generator.new_id(),
                        finding_id=finding_id,
                        raw_payload=payload[:MAX_RAW_PAYLOAD_CHARS],
                        source_tool=ScannerTool.TRIVY,
                        captured_at=clock.now(),
                    ),
                    # Measured across the real fixture: every one of the 12
                    # vulnerabilities carries exactly one CweIDs entry, which is
                    # what settled `cwe` as a single value rather than a tuple
                    # (ADR-0018). The full list stays in raw_payload regardless.
                    cwe=canonical_cwe(next(iter(vulnerability.get("CweIDs") or []), None)),
                    # Trivy has no OWASP category concept.
                    owasp_category=None,
                    cvss=_v3_score(vulnerability.get("CVSS")),
                )
            )

    return findings
