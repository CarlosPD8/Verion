import json
from pathlib import Path

import pytest

from verion.modules.scanning.adapters.outbound.scanners.trivy_adapter import TrivyAdapter
from verion.modules.scanning.domain.exceptions import ScannerExecutionFailed

_FIXTURES_DIR = Path(__file__).parent / "fixtures"
_TARGET_DIR = _FIXTURES_DIR / "trivy_target"

# urllib3 1.24.1, disclosed 2019 — long-established, still reported by a
# current Trivy DB (verified directly against real `trivy fs` output, not
# assumed from memory), alongside several other CVEs for the same pin. Unlike
# SemgrepAdapter's fixture, no copy-out-of-tests/ workaround is needed here:
# Trivy has no default ignore rule for a "test"/"tests" path segment (also
# verified directly), so the checked-in fixture is scanned in place.
_EXPECTED_CVE = "CVE-2019-11324"

# CI warms Trivy's vulnerability-DB cache once before the test suite runs
# (see ci.yml) — every call here passes skip_db_update=True so assertions
# never depend on live network access or on which CVEs are newly published
# on a given run. See ADR-0012.


async def test_returns_raw_json_with_the_expected_vulnerability():
    adapter = TrivyAdapter(skip_db_update=True)
    result = await adapter.run(str(_TARGET_DIR))

    assert result.tool == "trivy"
    body = json.loads(result.raw_output)
    vulnerabilities = [
        vuln
        for r in body["Results"]
        for vuln in r.get("Vulnerabilities") or []
        if vuln["PkgName"] == "urllib3"
    ]
    assert any(vuln["VulnerabilityID"] == _EXPECTED_CVE for vuln in vulnerabilities)


async def test_raises_on_nonexistent_target_path():
    adapter = TrivyAdapter(skip_db_update=True)
    with pytest.raises(ScannerExecutionFailed):
        await adapter.run(str(_FIXTURES_DIR / "does-not-exist"))
