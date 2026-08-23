import json

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

# ZAP's traditional-json report has NO severity field. The risk level is the
# numeric `riskcode`; the word form exists only inside `riskdesc`, as
# "Risk (Confidence)" — e.g. "Medium (High)". Mapping from riskcode rather than
# parsing that string is deliberate: riskdesc's format is a display convention
# that could change, while riskcode is the enumerated value.
_SEVERITY: dict[str, Severity] = {
    "3": Severity.HIGH,
    "2": Severity.MEDIUM,
    "1": Severity.LOW,
    "0": Severity.INFO,
}

# The word ZAP itself uses for each riskcode, recorded so native_severity carries
# something a human recognises rather than the digit. Kept in sync with the map
# above by the unit tests, which assert both against real captured output.
_NATIVE: dict[str, str] = {
    "3": "High",
    "2": "Medium",
    "1": "Low",
    "0": "Informational",
}


def map_zap_output(
    *,
    scan_id: str,
    raw_output: str,
    id_generator: IdGeneratorPort,
    clock: ClockPort,
) -> list[Finding]:
    """Maps one ZAP traditional-json report to Findings. Pure: no I/O.

    **One Finding per alert, not per instance**, and the choice is deliberate
    rather than convenient. ZAP groups by rule: an alert has one riskcode, one
    cweid and one solution, while `instances[]` lists every URL the rule fired
    on. Those instances are *occurrences* — precisely the sighting concept G5
    says the model is missing — so splitting them into separate Findings here
    would pre-empt the identity decision M4.2 owns. The first instance supplies
    the location; every instance stays verbatim in `raw_payload`, so nothing is
    lost and M4.2 can revisit this with the full data in front of it.

    `confidence` is not mapped, because `Finding` carries no confidence field.
    In this report it is an opaque numeric code (`"2"`, `"3"`) whose vocabulary
    mixes degrees with states — see ADR-0018 and M6.1.
    """
    document = json.loads(raw_output)
    findings: list[Finding] = []

    for site in document.get("site") or []:
        for alert in site.get("alerts") or []:
            riskcode = str(alert.get("riskcode", ""))
            instances = alert.get("instances") or []
            first = instances[0] if instances else {}

            finding_id = id_generator.new_id()
            payload = json.dumps(alert, sort_keys=True)
            findings.append(
                Finding(
                    id=finding_id,
                    scan_id=scan_id,
                    source=ScannerTool.ZAP,
                    severity=_SEVERITY.get(riskcode, Severity.UNKNOWN),
                    native_severity=_NATIVE.get(riskcode)
                    or f"(unrecognised riskcode {riskcode!r})",
                    title=str(alert.get("name") or alert.get("alert") or "(unnamed zap alert)"),
                    location=Location(
                        # Falls back to the site itself when an alert carries no
                        # instances. That is not a guessed value: ZAP nests the
                        # alert under that site in its own document, so the site
                        # *is* the alert's location — it is simply less precise
                        # than a per-instance URL.
                        url=str(first.get("uri") or site.get("@name") or "") or None,
                        http_method=str(first.get("method")) if first.get("method") else None,
                        # Empty string is ZAP's "not parameter-specific", which
                        # is the same thing as absent for our purposes.
                        parameter=str(first.get("param")) if first.get("param") else None,
                    ),
                    evidence=Evidence(
                        id=id_generator.new_id(),
                        finding_id=finding_id,
                        raw_payload=payload[:MAX_RAW_PAYLOAD_CHARS],
                        source_tool=ScannerTool.ZAP,
                        captured_at=clock.now(),
                    ),
                    # A bare number, and `-1`/`0` mean "none known" rather than
                    # naming a real weakness — canonical_cwe handles both.
                    cwe=canonical_cwe(alert.get("cweid")),
                    # ZAP's traditional-json report carries no OWASP category and
                    # no CVSS. `wascid` is a different taxonomy and is not one.
                    owasp_category=None,
                    cvss=None,
                )
            )

    return findings
