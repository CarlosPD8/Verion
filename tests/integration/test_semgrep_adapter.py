import json
import shutil
import tempfile
from pathlib import Path

import pytest

from verion.modules.scanning.adapters.outbound.scanners.semgrep_adapter import SemgrepAdapter
from verion.modules.scanning.domain.exceptions import ScannerExecutionFailed

_FIXTURES_DIR = Path(__file__).parent / "fixtures"
_TARGET_DIR = _FIXTURES_DIR / "semgrep_target"
_RULESET = _FIXTURES_DIR / "semgrep_rules" / "basic.yml"

# A pinned local ruleset, not --config auto/p/*: those fetch from Semgrep's
# cloud registry over the network, which would make this test flaky/slow and
# dependent on registry availability for no benefit — see M3.2's plan.


def _copy_target_outside_of_any_test_directory() -> str:
    # Semgrep's own default ignore rules exclude any path with a "test"/
    # "tests" segment (see https://semgrep.dev/docs/ignoring-files-folders-code/
    # #understand-semgrep-defaults) — since our checked-in fixture lives under
    # tests/integration/fixtures/, scanning it in place gets silently skipped
    # ("0 files scanned") rather than actually exercising the rule. Copying it
    # to a fresh temp dir with no "test" segment in its path (verified: this
    # is an exact-segment match, not a substring match) reproduces what
    # SemgrepAdapter really does in production — scan a cloned repo's own
    # working tree, never a path under this project's own tests/ folder.
    target = tempfile.mkdtemp(prefix="semgrep-fixture-")
    shutil.copytree(_TARGET_DIR, target, dirs_exist_ok=True)
    return target


async def test_returns_raw_json_with_the_expected_finding():
    adapter = SemgrepAdapter(config=str(_RULESET))
    target = _copy_target_outside_of_any_test_directory()
    try:
        result = await adapter.run(target)
    finally:
        shutil.rmtree(target, ignore_errors=True)

    assert result.tool == "semgrep"
    body = json.loads(result.raw_output)
    assert body["results"]
    assert body["results"][0]["check_id"].endswith("dangerous-eval")


async def test_raises_on_invalid_config():
    adapter = SemgrepAdapter(config=str(_FIXTURES_DIR / "does-not-exist.yml"))
    target = _copy_target_outside_of_any_test_directory()
    try:
        with pytest.raises(ScannerExecutionFailed):
            await adapter.run(target)
    finally:
        shutil.rmtree(target, ignore_errors=True)
