import json
import shutil
import tempfile
from pathlib import Path

import pytest

from verion.modules.scanning.adapters.outbound.scanners.semgrep_adapter import SemgrepAdapter
from verion.modules.scanning.domain.exceptions import ScannerExecutionFailed

_FIXTURES_DIR = Path(__file__).parent / "fixtures"
_TARGET_DIR = _FIXTURES_DIR / "semgrep_target"
# The same ruleset the worker uses in production (Settings.semgrep_ruleset,
# M3.3) — not a test-only copy, so what's tested is what actually runs. See
# that file's own comment for why it's a small pinned ruleset, not
# --config auto/p/*.
_RULESET = (
    Path(__file__).parents[2]
    / "src"
    / "verion"
    / "modules"
    / "scanning"
    / "adapters"
    / "outbound"
    / "scanners"
    / "rulesets"
    / "default.yml"
)


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
    # Equality, not endswith(). `check_id` is a dedup_hash input (ADR-0019
    # decision 3) and the old assertion passed for every one of the three
    # CWD-dependent dotted forms G10 measured, so it could not have caught the
    # defect it looks like it covers. This is what pins "no filesystem path
    # reaches rule_id" — the disclosure half of G9 and G10.
    assert body["results"][0]["check_id"] == "dangerous-eval"
    # The G9 half: repo-relative, not the scan's unique absolute mkdtemp prefix.
    assert body["results"][0]["path"] == "vulnerable.py"


async def test_rule_id_and_path_do_not_depend_on_the_worker_s_working_directory(
    monkeypatch, tmp_path
):
    """The invariant G10 names, which no committed fixture can observe.

    `check_id` and `path` are both `dedup_hash` inputs, and Semgrep renders both
    relative to the process CWD by default — so before this issue their values
    differed between a developer's machine, CI and a container, and every stored
    Semgrep finding would re-key on a redeploy. A fixture records one machine's
    CWD, so it cannot see this; only invoking the real adapter from two different
    CWDs can.

    Asserting the two runs are EQUAL rather than asserting a literal is the point:
    it is a statement about the adapter's invocation being CWD-independent, and it
    fails for any future `--config`/`cwd` change that reintroduces the coupling,
    whatever value that change produces.
    """
    adapter = SemgrepAdapter(config=str(_RULESET))
    target = _copy_target_outside_of_any_test_directory()
    try:
        monkeypatch.chdir(tmp_path)
        from_tmp = json.loads((await adapter.run(target)).raw_output)
        monkeypatch.chdir(Path(__file__).parents[2])
        from_repo_root = json.loads((await adapter.run(target)).raw_output)
    finally:
        shutil.rmtree(target, ignore_errors=True)

    assert from_tmp["results"] and from_repo_root["results"]
    assert from_tmp["results"][0]["check_id"] == from_repo_root["results"][0]["check_id"]
    assert from_tmp["results"][0]["path"] == from_repo_root["results"][0]["path"]


async def test_raises_on_invalid_config():
    adapter = SemgrepAdapter(config=str(_FIXTURES_DIR / "does-not-exist.yml"))
    target = _copy_target_outside_of_any_test_directory()
    try:
        with pytest.raises(ScannerExecutionFailed):
            await adapter.run(target)
    finally:
        shutil.rmtree(target, ignore_errors=True)
