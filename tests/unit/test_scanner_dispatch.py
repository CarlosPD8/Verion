from verion.modules.scanning.domain.scan import ScanStatus
from verion.modules.scanning.domain.scan_result import ScanResult
from verion.modules.scanning.domain.scanner_dispatch import (
    DEFAULT_ENABLED_TOOLS,
    derive_scan_status,
    resolve_enabled_tools,
)
from verion.shared_kernel.scanner_tools import ScannerTool


def _succeeded(tool: str) -> ScanResult:
    return ScanResult.succeeded(id=f"r-{tool}", scan_id="s1", tool=tool, raw_output="{}")


def _failed(tool: str) -> ScanResult:
    return ScanResult.failed(id=f"r-{tool}", scan_id="s1", tool=tool, failure_reason="boom")


def test_unconfigured_gets_the_default():
    assert resolve_enabled_tools(None) == DEFAULT_ENABLED_TOOLS


def test_the_default_excludes_zap():
    """Not incidental: ZAP needs a target URL only a user can supply, so it
    cannot be defaulted on. Semgrep and Trivy take no user-supplied target and
    therefore carry no SSRF surface."""
    assert ScannerTool.ZAP not in DEFAULT_ENABLED_TOOLS
    assert set(DEFAULT_ENABLED_TOOLS) == {ScannerTool.SEMGREP, ScannerTool.TRIVY}


def test_configured_to_run_nothing_is_not_the_default():
    """The distinction a truthiness check would lose: an empty tuple is an
    explicit choice, `None` is the absence of one."""
    assert resolve_enabled_tools(()) == ()


def test_an_explicit_selection_is_returned_as_given():
    assert resolve_enabled_tools([ScannerTool.ZAP]) == (ScannerTool.ZAP,)


def test_all_succeeded_is_completed():
    assert derive_scan_status([_succeeded("semgrep"), _succeeded("trivy")]) is ScanStatus.COMPLETED


def test_a_mix_is_partial():
    assert derive_scan_status([_succeeded("semgrep"), _failed("zap")]) is ScanStatus.PARTIAL


def test_all_failed_is_failed():
    assert derive_scan_status([_failed("semgrep"), _failed("zap")]) is ScanStatus.FAILED


def test_a_single_success_among_many_failures_is_still_partial():
    """The asymmetry that matters for §12: one surviving scanner is enough to
    keep this off FAILED, because FAILED is what would invite a caller to
    discard the whole scan."""
    results = [_succeeded("semgrep"), _failed("trivy"), _failed("zap")]

    assert derive_scan_status(results) is ScanStatus.PARTIAL


def test_no_results_is_failed():
    assert derive_scan_status([]) is ScanStatus.FAILED
