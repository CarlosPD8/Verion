import pytest

from verion.modules.scanning.domain.scan_result import ScanResult, ScanResultStatus


def test_succeeded_carries_output_and_no_reason():
    result = ScanResult.succeeded(id="r1", scan_id="s1", tool="semgrep", raw_output="{}")

    assert result.status is ScanResultStatus.SUCCEEDED
    assert result.raw_output == "{}"
    assert result.failure_reason is None


def test_failed_carries_a_reason_and_no_output():
    result = ScanResult.failed(id="r1", scan_id="s1", tool="zap", failure_reason="timed out")

    assert result.status is ScanResultStatus.FAILED
    assert result.raw_output is None
    assert result.failure_reason == "timed out"


# The four ways to build a row M4 could not interpret. Each is rejected in the
# domain and again by the table's CHECK constraint — the invariant is what lets
# get_succeeded_by_scan_id promise non-null raw_output, so it is worth pinning
# from both directions rather than only testing the two valid shapes above.


def test_succeeded_without_output_is_rejected():
    with pytest.raises(ValueError, match="SUCCEEDED but has no raw_output"):
        ScanResult(
            id="r1",
            scan_id="s1",
            tool="semgrep",
            status=ScanResultStatus.SUCCEEDED,
            raw_output=None,
            failure_reason=None,
        )


def test_succeeded_with_a_failure_reason_is_rejected():
    with pytest.raises(ValueError, match="SUCCEEDED but carries a failure_reason"):
        ScanResult(
            id="r1",
            scan_id="s1",
            tool="semgrep",
            status=ScanResultStatus.SUCCEEDED,
            raw_output="{}",
            failure_reason="timed out",
        )


def test_failed_with_output_is_rejected():
    with pytest.raises(ValueError, match="FAILED but carries raw_output"):
        ScanResult(
            id="r1",
            scan_id="s1",
            tool="zap",
            status=ScanResultStatus.FAILED,
            raw_output="{}",
            failure_reason="timed out",
        )


def test_failed_without_a_reason_is_rejected():
    with pytest.raises(ValueError, match="FAILED but has no failure_reason"):
        ScanResult(
            id="r1",
            scan_id="s1",
            tool="zap",
            status=ScanResultStatus.FAILED,
            raw_output=None,
            failure_reason=None,
        )


def test_an_empty_string_is_a_valid_success_output():
    """ "" is a real, if unusual, scanner output — it is only meaningless as a
    stand-in for failure, which is why raw_output is nullable instead."""
    result = ScanResult.succeeded(id="r1", scan_id="s1", tool="semgrep", raw_output="")

    assert result.status is ScanResultStatus.SUCCEEDED
    assert result.raw_output == ""
