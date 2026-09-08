"""The active scan finds the `eval()` sink, demonstrated live. M5.9, resolving G24 and G29.

**Runtime, per CLAUDE.md's rule that any test over 30s justifies itself in its docstring.**
The module-scoped fixture below clones the target, resolves its pinned closure under Python
3.11, serves it, runs one real active ZAP scan against it and tears it down — **70.45s measured
on this machine**, of which the scan is most (the committed capture's README records 65.5s
around `ZapAdapter.run()` alone). pytest attributes fixture setup to the *first* test that
uses it, so `--durations` names one of the three below and the other two read as instant; the
cost is the fixture's and is shared by all three. It is not divisible: the three assertions are
three properties of **one** run, and giving each its own scan would triple the runtime to prove
nothing extra.

**Why three tests and not one.** G29's failure mode is a green result — a target that never
boots produces passive header alerts only, which is byte-for-byte what a correct scan of a
healthy target with no vulnerability produces. A single merged assertion would give one
identical red for a boot failure, a crawl failure and a genuine absence, which is the merging
ADR-0027 decision 6 forbids. Split three ways, each failure carries its own test id and its own
message, and the boot failure is the one that reports first.

**This test writes no fixture** — only the target's own stdout, to a `tmp_path_factory` file it
reads back into a failure message. ADR-0027 decision 3: a test that generates its own fixture
makes the fixture a function of the last run. The committed capture under
`tests/integration/fixtures/active_scan/` is a separate artifact from a separate hand-run, and
nothing here reads or replaces it.

**It runs unconditionally — no marker, no `skipif`, the first in this suite either way.** A skip
is itself a false negative that reads as green, which is exactly what this test exists to detect;
making the detector silently skippable is the one place this repo should not introduce its first
skip. What that costs — an intentionally vulnerable app on `0.0.0.0:8080` and ~70s on every
`uv run pytest`, on developer machines as well as the ephemeral runner ADR-0027 reasoned about —
is **G45**, which also records the exit condition for revisiting it.
"""

import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
import pytest_asyncio

from verion.modules.scanning.adapters.outbound.dns.system_dns_resolver import SystemDnsResolver
from verion.modules.scanning.adapters.outbound.scanners.zap_adapter import ZapAdapter
from verion.modules.scanning.adapters.outbound.vcs.git_repo_checkout import GitRepoCheckout
from verion.modules.scanning.domain.scan_options import ScanOptions

_ROOT = Path(__file__).resolve().parents[2]

# The capture driver is imported rather than copied, and the reason is narrower than reuse.
# `_REPO_URL`, `_PINNED_SHA`, `_TARGET_URL` and `_LIVENESS_MARKER` moving in one file and not
# the other would leave the committed capture and this test describing DIFFERENT TREES, with
# both green. Importing makes that impossible instead of unlikely. It also puts THIS DRIVER
# under CI — `seed_findings_benchmark.py`'s docstring names "Nothing in CI executes it" as its
# own weakness, and that stops being true of this one (`scripts/` as a directory has been in CI
# since check_claims.py) — and it takes `stop_target`'s POSIX branch on every ubuntu run, which
# is why that function's docstring and the capture's provenance README are dated in this commit
# rather than left saying it has never run.
sys.path.insert(0, str(_ROOT / "scripts"))

from capture_active_scan import (  # noqa: E402 — the sys.path line above is its precondition
    _ENV_ALLOWLIST,
    _ENV_DENY_PATTERN,
    _LIVENESS_MARKER,
    _PINNED_SHA,
    _REPO_URL,
    _TARGET_URL,
    CaptureAborted,
    _uv_serve_argv,
    port_is_closed,
    stop_target,
    wait_for_liveness,
)

# What the driver's allowlist does not carry, because it has only ever run on Windows: it names
# `SystemRoot`, `COMSPEC`, `LOCALAPPDATA` and friends, and on the ubuntu-latest runner it yields
# little more than PATH. `HOME` is the load-bearing addition — uv keeps its cache and its
# managed Python 3.11 under it. Extending here rather than widening the driver keeps the tool
# that produced the committed artifacts unchanged.
#
# **What this envelope protects and what it does not, because adding HOME back looks like a
# weakening and is not.** It protects secrets held in ENVIRONMENT VARIABLES, which is a measured
# threat and not a hypothetical one: commit 1 measured a live CLAUDE_CODE_MESSAGING_TOKEN in the
# capture shell, and the CI job carries DATABASE_URL and REDIS_URL. It has never protected the
# FILESYSTEM — with `HOME` unset, `os.path.expanduser` falls back to
# `pwd.getpwuid(os.getuid()).pw_dir`, so a payload through the `eval()` sink reaches `~/.ssh`
# either way.
_EXTRA_ENV_NAMES = (
    "HOME",
    "XDG_CACHE_HOME",
    "UV_CACHE_DIR",
    "UV_PYTHON_INSTALL_DIR",
    "LANG",
    "LC_ALL",
    "TZ",
)

# ADR-0027 decision 5 sources the passive alert set to this file, so it is READ rather than
# transcribed. A pasted list of five refs is prose that cannot be checked against anything,
# which is the class G42 is the record of. The cost is a coupling G44 half-covers: its re-entry
# trigger DOES fire on "any re-capture of either corpus", but what it says to re-derive is the
# two captures, not this test's control set — and a passive re-capture changes what this test's
# third assertion can detect.
_PASSIVE_REPORT = _ROOT / "tests" / "fixtures" / "scanners" / "zap_scan.json"

_VULNERABLE_PATH = "/calculate"
_VULNERABLE_PARAM = "expr"


@dataclass(frozen=True)
class _ActiveScanRun:
    """One run's observations. Nothing here is asserted — the three tests below own that."""

    liveness_ok: bool
    liveness_detail: str
    report: dict[str, Any] | None


def _target_env() -> dict[str, str]:
    """Built from an allowlist, never filtered down from `os.environ`.

    The deny pattern is the driver's own, re-run here rather than restated: the platform-specific
    part of this envelope is additive, and the safety-critical statement stays in one place.
    """
    names = (*_ENV_ALLOWLIST, *_EXTRA_ENV_NAMES)
    env = {name: os.environ[name] for name in names if name in os.environ}
    leaked = sorted(name for name in env if _ENV_DENY_PATTERN.search(name))
    assert not leaked, (
        f"the target's environment would carry {leaked}, and its /calculate?expr= is a working "
        "RCE sink. Remove the name from the allowlist rather than from the deny pattern."
    )
    return env


def _log_tail(log_path: Path, limit: int = 1500) -> str:
    """The target's own output, carried into the liveness failure message.

    Without it a boot failure reads as a bare timeout, and the thing worth seeing — G29's
    `ModuleNotFoundError: No module named 'urllib3.packages.six.moves'` — is in a temp file
    nobody looks at. Reading a file the child still holds open can fail on some platforms; a
    missing tail must not replace the real failure with its own.
    """
    try:
        return log_path.read_text(encoding="utf-8", errors="replace")[-limit:]
    except OSError as exc:  # pragma: no cover - only on a platform that locks the handle
        return f"<unreadable: {exc}>"


def _crawled_uris(report: dict[str, Any]) -> set[str]:
    # ADR-0027 decision 6: the report carries no spider log, so the crawled set is the union of
    # the instance URIs. That works because the response-level passive alerts fire on every
    # page ZAP fetched.
    return {
        instance["uri"]
        for site in report.get("site", [])
        for alert in site.get("alerts", [])
        for instance in alert.get("instances", [])
        if instance.get("uri")
    }


def _is_the_vulnerable_endpoint(uri: str) -> bool:
    parsed = urlparse(uri)
    return parsed.path == _VULNERABLE_PATH and _VULNERABLE_PARAM in parse_qs(parsed.query)


def _passive_alert_refs() -> set[str]:
    passive = json.loads(_PASSIVE_REPORT.read_text(encoding="utf-8"))
    return {alert["alertRef"] for site in passive["site"] for alert in site["alerts"]}


def _require_report(run: _ActiveScanRun) -> dict[str, Any]:
    if run.report is None:
        pytest.fail(
            "no report: the scan never ran, because the liveness gate failed first. The "
            "assertion that OWNS that failure is "
            "test_the_target_booted_under_python_311_and_served_the_app, which reports above "
            f"this one. Gate detail: {run.liveness_detail}"
        )
    return run.report


@pytest_asyncio.fixture(scope="module")
async def active_scan_run(tmp_path_factory: pytest.TempPathFactory) -> _ActiveScanRun:
    checkout_port = GitRepoCheckout()
    local_path = await checkout_port.checkout(_REPO_URL, access_token=None)
    try:
        # ADR-0027 decision 2. `git clone --depth 1` cannot REQUEST a commit (G25) — the pinned
        # SHA is reached only because it is the default-branch tip — so this assertion is the
        # whole of what stands between the test and silently scanning a different tree. It runs
        # before anything is served, and it aborts the run rather than reddening one of the
        # three properties below, because it is not one of them.
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=local_path,
            capture_output=True,
            text=True,
            check=True,
            timeout=60,
        ).stdout.strip()
        if head != _PINNED_SHA:
            pytest.fail(
                f"verion-demo-target HEAD is {head}, not the pinned {_PINNED_SHA}. Nothing was "
                "served. Every committed capture, the semgrep line number this demonstration "
                "pairs with, and the target's own do-not-fix-the-eval contract are pinned to "
                "that SHA; re-clone fully and `git checkout` it, or use `git clone --revision`."
            )

        checkout = Path(local_path)
        log_path = tmp_path_factory.mktemp("verion-demo-target") / "app.log"
        handle = log_path.open("wb")
        try:
            process = subprocess.Popen(
                _uv_serve_argv(checkout, "python", "app.py"),
                cwd=str(checkout),
                stdout=handle,
                stderr=subprocess.STDOUT,
                env=_target_env(),
                # POSIX: puts `uv` and its Flask grandchild in one process group, which is what
                # makes `stop_target`'s killpg reach the process actually holding the port.
                start_new_session=sys.platform != "win32",
            )
            liveness_ok = False
            liveness_detail = ""
            report: dict[str, Any] | None = None
            try:
                try:
                    wait_for_liveness(process)
                    liveness_ok = True
                    liveness_detail = f"200, and the body carried {_LIVENESS_MARKER!r}"
                except CaptureAborted as exc:
                    liveness_detail = f"{exc} --- target's own output: {_log_tail(log_path)}"

                if liveness_ok:
                    # The shipped adapter, at its pinned `docker_image` default and its own
                    # `timeout_seconds`, with nothing overridden but ADR-013's test-only escape
                    # hatch — so this run and the committed capture are the same plan at the
                    # same digest.
                    adapter = ZapAdapter(
                        dns_resolver=SystemDnsResolver(), allow_private_targets=True
                    )
                    result = await adapter.run(_TARGET_URL, ScanOptions(active_scan_consented=True))
                    report = json.loads(result.raw_output)
            finally:
                stop_target(process)
        finally:
            handle.close()

        # A tree kill that missed is worse than a failed test: the first hand-run of the capture
        # driver left this app LAN-reachable after the script exited, and only this check saw it.
        assert port_is_closed(), (
            "something is STILL LISTENING after the target was killed. The intentionally "
            "vulnerable app is reachable and must be stopped by hand."
        )
        return _ActiveScanRun(
            liveness_ok=liveness_ok, liveness_detail=liveness_detail, report=report
        )
    finally:
        await checkout_port.cleanup(local_path)


async def test_the_target_booted_under_python_311_and_served_the_app(
    active_scan_run: _ActiveScanRun,
) -> None:
    """G29's gate, and it is stronger than "the request succeeded" on purpose.

    A port that accepts a connection proves nothing and a 200 proves only that something is
    serving. `1.24.1` is rendered into the index by the serving process from
    `urllib3.__version__`, and `urllib3 1.24.1` cannot be imported under 3.12 at all — so the
    marker in the body is the one observation that distinguishes a healthy target from the
    false negative this entry is about.
    """
    assert active_scan_run.liveness_ok, (
        "the target never served the app, so no scan of it means anything (G29): "
        f"{active_scan_run.liveness_detail}"
    )


async def test_the_scan_reached_the_vulnerable_endpoint(active_scan_run: _ActiveScanRun) -> None:
    """ADR-0027 decision 6's second gate, which the liveness gate does not cover.

    The target's `index.html` states its link is the only path from `/` to `/calculate`, so a
    healthy app whose link was never followed yields passive header alerts only — identical to a
    clean scan. This is the second door onto the same false negative, and it fails separately.
    """
    report = _require_report(active_scan_run)
    uris = _crawled_uris(report)
    reached = sorted(uri for uri in uris if _is_the_vulnerable_endpoint(uri))
    assert reached, (
        f"the scan never reached {_VULNERABLE_PATH} carrying {_VULNERABLE_PARAM!r}. The target "
        "was serving, so this is a crawl failure and not a boot failure, and it produces the "
        f"same header-alerts-only report a clean target would. Crawled: {sorted(uris)}"
    )


async def test_the_active_scan_found_what_the_passive_plan_does_not(
    active_scan_run: _ActiveScanRun,
) -> None:
    """G24: a DAST finding about the sink, which no passive plan can produce.

    Deliberately not pinned, per ADR-0027 decision 5: no alert id, risk code, confidence, CWE,
    name or count. Every one of those is prose from one hand-run under a plan this repository
    cannot re-execute, and freezing it here would transcribe an unreproducible run into a green
    check. What IS asserted is the property the milestone claims — an alert the passive corpus
    does not contain, on the vulnerable endpoint, attributed to the parameter. `param` is the
    narrow attribution; `nodeName` carries it more widely and is not what this reads.
    """
    report = _require_report(active_scan_run)
    passive_refs = _passive_alert_refs()
    new_alerts = [
        alert
        for site in report.get("site", [])
        for alert in site.get("alerts", [])
        if alert["alertRef"] not in passive_refs
    ]
    attributed = sorted(
        alert["alertRef"]
        for alert in new_alerts
        for instance in alert.get("instances", [])
        if urlparse(instance.get("uri", "")).path == _VULNERABLE_PATH
        and instance.get("param") == _VULNERABLE_PARAM
    )
    assert attributed, (
        "the active scan produced no alert that the passive plan does not, attributed to "
        f"{_VULNERABLE_PARAM!r} on {_VULNERABLE_PATH}. The target was serving, or this test "
        "would have reported no report at all. Whether the endpoint was reached is "
        "test_the_scan_reached_the_vulnerable_endpoint's to say, and this message does not "
        f"claim it: if that one is green, the finding itself is absent. Passive refs "
        f"{sorted(passive_refs)}; alerts this run added "
        f"{sorted({a['alertRef'] for a in new_alerts})}."
    )
