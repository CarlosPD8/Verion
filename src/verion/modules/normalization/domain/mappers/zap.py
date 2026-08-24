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
    project_id: str,
    scan_id: str,
    raw_output: str,
    id_generator: IdGeneratorPort,
    clock: ClockPort,
) -> list[Finding]:
    """Maps one ZAP traditional-json report to Findings. Pure: no I/O.

    **One Finding per (alert, instance)**, which is the question M4.1 deliberately
    left open and ADR-0019 decides. ZAP groups by rule: an alert has one riskcode,
    one cweid and one solution, while `instances[]` lists every URL the rule fired
    on. Three things decided it:

    - Alert-level identity cannot include the URL. The location would be
      `instances[0]`, and that is not deterministic — in the captured fixture the
      CSP alert's four instances carry ids 6, 5, 1, 0, so they arrive in crawl
      order rather than sorted.
      The same finding's displayed URL would flip between scans, and identity
      would have to fall back to the site while `Location` still showed a URI that
      was not part of it.
    - Per-instance makes resolution granular: fixing the missing header on `/`
      but not on `/robots.txt` becomes one resolved and one still present. At
      alert level that transition is invisible — an under-report of a half-fixed
      alert as unchanged, which is a false claim about security state rather than
      a lost count.
    - Instances are per-URL; sightings are per-scan. They are orthogonal, so this
      neither pre-empts nor duplicates the sighting model.

    An alert with **no instances at all** still produces exactly one Finding,
    located at the site it is nested under. That is real output — a site-level
    alert — and the fallback is not a guess: ZAP's own nesting is its statement of
    where the alert applies.

    `raw_payload` is the alert with `instances` narrowed to this finding's one
    instance. ADR-0018 decision 6 is clarified rather than amended by that: the
    principle — a verbatim copy of the source element, never a reference into a
    replaceable blob — is unchanged, and what changes is what counts as the source
    element, which for a per-instance finding is the alert-plus-instance pair.
    Nothing is invented, only projected; the instances are partitioned across the
    findings so none is dropped; and the whole alert stays verbatim in
    `ScanResult.raw_output` regardless.

    `confidence` is not mapped, because `Finding` carries no confidence field.
    In this report it is an opaque numeric code (`"2"`, `"3"`) whose vocabulary
    mixes degrees with states — see ADR-0018 and M6.1.
    """
    document = json.loads(raw_output)
    findings: list[Finding] = []

    for site in document.get("site") or []:
        for alert in site.get("alerts") or []:
            instances = alert.get("instances") or []
            # `[None]` rather than `[]`, so the site-level alert takes the same
            # code path as every other one instead of needing its own branch.
            for instance in instances or [None]:
                findings.append(
                    _map_alert_instance(
                        project_id=project_id,
                        scan_id=scan_id,
                        site=site,
                        alert=alert,
                        instance=instance,
                        id_generator=id_generator,
                        clock=clock,
                    )
                )

    return findings


def _map_alert_instance(
    *,
    project_id: str,
    scan_id: str,
    site: dict[str, Any],
    alert: dict[str, Any],
    instance: dict[str, Any] | None,
    id_generator: IdGeneratorPort,
    clock: ClockPort,
) -> Finding:
    riskcode = str(alert.get("riskcode", ""))
    located_at = instance or {}

    finding_id = id_generator.new_id()
    payload = json.dumps(
        {**alert, "instances": [instance] if instance is not None else []},
        sort_keys=True,
    )
    return Finding(
        id=finding_id,
        project_id=project_id,
        source=ScannerTool.ZAP,
        # `alertRef` before `pluginid`: it is the finer of the two, naming a
        # sub-alert of one plugin (`10036-2` under plugin `10036`), and those
        # sub-alerts are genuinely different findings.
        rule_id=str(alert.get("alertRef") or alert.get("pluginid") or "") or "(unidentified)",
        severity=_SEVERITY.get(riskcode, Severity.UNKNOWN),
        native_severity=_NATIVE.get(riskcode) or f"(unrecognised riskcode {riskcode!r})",
        title=str(alert.get("name") or alert.get("alert") or "(unnamed zap alert)"),
        location=Location(
            url=str(located_at.get("uri") or site.get("@name") or "") or None,
            http_method=str(located_at.get("method")) if located_at.get("method") else None,
            # Empty string is ZAP's "not parameter-specific", which is the same
            # thing as absent for our purposes.
            parameter=str(located_at.get("param")) if located_at.get("param") else None,
        ),
        evidence=Evidence(
            id=id_generator.new_id(),
            finding_id=finding_id,
            scan_id=scan_id,
            raw_payload=payload[:MAX_RAW_PAYLOAD_CHARS],
            source_tool=ScannerTool.ZAP,
            captured_at=clock.now(),
        ),
        # A bare number, and `-1`/`0` mean "none known" rather than naming a real
        # weakness — canonical_cwe handles both.
        cwe=canonical_cwe(alert.get("cweid")),
        # ZAP's traditional-json report carries no OWASP category and no CVSS.
        # `wascid` is a different taxonomy and is not one.
        owasp_category=None,
        cvss=None,
    )
