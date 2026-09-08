"""Capture one active ZAP scan of `verion-demo-target`, redacted, for M5.9.

ADR-0024's *"What consent authorises"* table states each figure as the predicate that
produced it and then says none of them can be run here, because the probe's report, its
access log and its working tree were never committed. That is **G42**, whose re-entry
trigger is *"M5.9's committed active capture"*. This produces it.

**This script is versioned rather than kept as a scratch file**, on
`seed_findings_benchmark.py`'s precedent: *"A measurement recorded in an ADR with no way
to re-derive it is a number nobody can check."* Substitute ADR-0024 for ADR-012 and G42
for G4 and it is this situation exactly. The one-sentence resolution of the conflict with
`tests/fixtures/scanners/README.md`'s *"There is no script"*: that README argues a
committed script implies re-capturing is routine, which `seed_findings_benchmark.py`
disproves by existing, and it is right about **its own** subject — the passive corpus
depends on Trivy's vulnerability-DB state and is re-derivable by no script, while this
capture is pinned by SHA, by image digest and by code, and so is.

**The plan is never built here.** ADR-0027 decision 3 requires the capture to be driven
through the shipped `ZapAdapter` at its pinned `docker_image` default, on the plan
`_build_plan_yaml` and `_active_scan_jobs` build, because a capture from an ad-hoc plan is
what the 2026-08-25 probe already was. So this constructs the real adapter, overrides
nothing, and imports `_build_plan_yaml` only to *reproduce the plan text for the record* —
`ZapAdapter.run` deletes its temp directory in a `finally` on every path, so the plan and
the report are both gone by the time it returns and the report survives only as
`RawScanResult.raw_output`.

**Two things this deliberately does not do.** It does not retry, soften a gate, or widen a
timeout: every stop condition below aborts and reports, because a capture massaged into
succeeding is the artifact G29 and G42 exist to prevent. And it does not serve the target
from the working copy on this machine — it clones at the pinned SHA into a temp directory
and verifies `git rev-parse HEAD` before anything runs, which is ADR-0027 decision 2's
assertion exercised by hand.

**Safety.** The target is an intentionally vulnerable app whose `/calculate?expr=` is
remote code execution by design, and the scan reaches that sink. The subprocess is started
with an environment built from an allowlist rather than inherited, so no project variable
reaches a process with a live RCE sink; it binds `0.0.0.0:8080` and is reachable from the
local network for the duration, which this script measures and prints. **`stop_target` kills a
process tree because `terminate()` reaches only the `uv` wrapper and not the Flask grandchild
holding the port — ADR-0011 point 8 with a different intermediary.**

Run it from the repository root:

    uv run python scripts/capture_active_scan.py

Expect several minutes: the plan caps `activeScan` at 3 minutes and the adapter's own
`timeout_seconds` is 540.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import ipaddress
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from verion.modules.scanning.adapters.outbound.dns.system_dns_resolver import (  # noqa: E402
    SystemDnsResolver,
)
from verion.modules.scanning.adapters.outbound.scanners.zap_adapter import (  # noqa: E402
    ZapAdapter,
    _build_plan_yaml,
)
from verion.modules.scanning.domain.scan_options import ScanOptions  # noqa: E402

_REPO_URL = "https://github.com/CarlosPD8/verion-demo-target"

# The corpus is pinned to this commit and so is this capture. `git clone --depth 1`
# cannot REQUEST it (G25) — it is reached only because it is the default-branch tip, so
# the verification below is what makes a moved target a loud failure rather than a scan
# of a different tree.
_PINNED_SHA = "c68caa7aba8db8ae64da6dd2b4e1b8a05ecd1850"

# Fixed in the target's own `app.py` and deliberately not worked around: its README makes
# the port part of what a capture records, and the committed `zap_scan.json` records
# `@port 8080`. A capture served anywhere else does not describe the same run.
_PORT = 8080

# What ZAP is pointed at, from inside the container. `--add-host` maps it to the host
# gateway; the same hostname the passive corpus was captured against, so the two are
# comparable, and the same string the redaction below rewrites.
_TARGET_URL = f"http://host.docker.internal:{_PORT}/"

# What the liveness gate is pointed at, from this machine.
_LIVENESS_URL = f"http://127.0.0.1:{_PORT}/"

# ADR-0027 decision 6: the gate is not "a port accepts a connection" and not "something
# returned 200". `app.py`'s index renders `urllib3.__version__` from the serving process,
# and `urllib3 1.24.1` cannot be imported under 3.12 at all — so this string in the body
# is what distinguishes a healthy target from G29's false negative.
_LIVENESS_MARKER = "1.24.1"
_LIVENESS_TIMEOUT_SECONDS = 60.0

# Every environment variable the child is allowed to see, built up from nothing rather
# than filtered down from `os.environ`. A denylist gets a new hole every time this project
# adds a setting; this cannot.
_ENV_ALLOWLIST = (
    "SystemRoot",
    "windir",
    "SystemDrive",
    "PATH",
    "PATHEXT",
    "COMSPEC",
    "TEMP",
    "TMP",
    # uv resolves the target's closure into its own cache, which lives under these.
    "LOCALAPPDATA",
    "APPDATA",
    "USERPROFILE",
    "HOMEDRIVE",
    "HOMEPATH",
    "NUMBER_OF_PROCESSORS",
    "PROCESSOR_ARCHITECTURE",
)

# Asserted against the child's environment before the vulnerable app is started. Not a
# substitute for the allowlist above — a second, independent statement of the same
# property, so a future edit to the allowlist that lets one of these back in fails here
# rather than silently handing a secret to a process with an RCE sink.
_ENV_DENY_PATTERN = re.compile(
    r"DATABASE|REDIS|TOKEN|SECRET|PASSWORD|JWT|GITHUB|SEMGREP|AWS|AZURE|GOOGLE|OPENAI|ANTHROPIC",
    re.IGNORECASE,
)

_REDACTED_HOST = "target.example"
_REDACTED_CAPTURE_HOST = "<capture-host>"


class CaptureAborted(Exception):
    """A stop condition fired. The run is not a result and nothing is written."""


def _log(message: str) -> None:
    print(f"[capture] {message}", flush=True)


def _run_git(*args: str, cwd: str | None = None) -> str:
    completed = subprocess.run(  # noqa: S603 — argument list, never shell=True (ADR-0011)
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        env={"GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "Never", **_child_env()},
    )
    if completed.returncode != 0:
        raise CaptureAborted(f"git {' '.join(args)} failed: {completed.stderr.strip()}")
    return completed.stdout.strip()


def _child_env() -> dict[str, str]:
    env = {name: os.environ[name] for name in _ENV_ALLOWLIST if name in os.environ}
    leaked = sorted(name for name in env if _ENV_DENY_PATTERN.search(name))
    if leaked:
        raise CaptureAborted(f"allowlist admitted a denied variable: {leaked}")
    return env


# ---------------------------------------------------------------------------
# 1. Clone and assert the SHA
# ---------------------------------------------------------------------------


def clone_at_pinned_sha(into: Path) -> Path:
    checkout = into / "target"
    _log(f"cloning {_REPO_URL} --depth 1")
    _run_git("clone", "--depth", "1", _REPO_URL, str(checkout))
    head = _run_git("rev-parse", "HEAD", cwd=str(checkout))
    if head != _PINNED_SHA:
        raise CaptureAborted(
            f"target HEAD is {head}, not the pinned {_PINNED_SHA}. "
            "`--depth 1` cannot request a non-tip commit (G25); re-clone fully and "
            "`git checkout` the SHA, or use `git clone --revision` on git >= 2.49."
        )
    _log(f"HEAD verified: {head}")
    return checkout


# ---------------------------------------------------------------------------
# 2. Verify the resolved closure against requirements.txt
# ---------------------------------------------------------------------------

_CLOSURE_PROBE = (
    "import importlib.metadata as m, json;"
    "print(json.dumps(sorted((d.metadata['Name'], d.version) "
    "for d in m.distributions())))"
)


def _uv_serve_argv(checkout: Path, *tail: str) -> list[str]:
    # The command `tests/fixtures/scanners/README.md` records, verbatim in its shape:
    # the target's own pinned closure, read from the checkout, under Python 3.11.
    return [
        "uv",
        "run",
        "--no-project",
        "--python",
        "3.11",
        "--with-requirements",
        str(checkout / "requirements.txt"),
        *tail,
    ]


def verify_closure(checkout: Path) -> list[tuple[str, str]]:
    _log("resolving the target's closure under Python 3.11")
    completed = subprocess.run(  # noqa: S603 — argument list, never shell=True
        _uv_serve_argv(checkout, "python", "-c", _CLOSURE_PROBE),
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
        env=_child_env(),
    )
    if completed.returncode != 0:
        raise CaptureAborted(f"closure resolution failed: {completed.stderr.strip()}")
    resolved = [(name, version) for name, version in json.loads(completed.stdout)]

    pinned = {}
    for line in (checkout / "requirements.txt").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            name, _, version = line.partition("==")
            pinned[name.lower()] = version

    resolved_map = {name.lower(): version for name, version in resolved}
    missing = sorted(n for n in pinned if n not in resolved_map)
    mismatched = sorted(
        f"{n} pinned {pinned[n]} resolved {resolved_map[n]}"
        for n in pinned
        if n in resolved_map and resolved_map[n] != pinned[n]
    )
    extra = sorted(n for n in resolved_map if n not in pinned)
    if missing or mismatched:
        raise CaptureAborted(f"closure differs from requirements.txt: {missing} {mismatched}")
    _log(f"closure matches requirements.txt ({len(pinned)} pins); extras: {extra or 'none'}")
    return resolved


# ---------------------------------------------------------------------------
# 3-4. Serve, and the liveness gate
# ---------------------------------------------------------------------------


def start_target(checkout: Path, log_path: Path) -> subprocess.Popen[bytes]:
    _log(f"serving the target on 0.0.0.0:{_PORT} (LAN-reachable until it is killed)")
    handle = log_path.open("wb")
    return subprocess.Popen(  # noqa: S603 — argument list, never shell=True
        _uv_serve_argv(checkout, "python", "app.py"),
        cwd=str(checkout),
        stdout=handle,
        stderr=subprocess.STDOUT,
        env=_child_env(),
        # POSIX only: puts `uv` and its Flask grandchild in their own process group, which
        # is what makes `stop_target`'s killpg reach the process actually holding the port.
        start_new_session=sys.platform != "win32",
    )


def wait_for_liveness(process: subprocess.Popen[bytes]) -> float:
    deadline = time.monotonic() + _LIVENESS_TIMEOUT_SECONDS
    last_error = "no attempt completed"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise CaptureAborted(
                f"the target exited with code {process.returncode} before it served anything"
            )
        try:
            with urllib.request.urlopen(_LIVENESS_URL, timeout=5) as response:  # noqa: S310
                body = response.read().decode("utf-8", errors="replace")
            if response.status == 200 and _LIVENESS_MARKER in body:
                elapsed = _LIVENESS_TIMEOUT_SECONDS - (deadline - time.monotonic())
                _log(f"liveness gate green in {elapsed:.1f}s (body carries {_LIVENESS_MARKER})")
                return elapsed
            last_error = f"status {response.status}, marker present: {_LIVENESS_MARKER in body}"
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            last_error = repr(exc)
        time.sleep(0.5)
    raise CaptureAborted(
        f"liveness gate never went green in {_LIVENESS_TIMEOUT_SECONDS}s: {last_error}. "
        "A target that never served is G29's false negative; nothing is captured."
    )


def stop_target(process: subprocess.Popen[bytes]) -> None:
    """Kill the whole tree, not the process this script spawned.

    **Measured, not anticipated: `terminate()` alone leaves the target serving.** The
    documented invocation is `uv run … python app.py`, so the child here is `uv` and the
    Flask server is its GRANDchild; terminating the wrapper orphans a process still bound
    to `0.0.0.0:8080`. The first capture run ended with the intentionally vulnerable app
    still LAN-reachable and only `port_is_closed()` noticed. An intentionally vulnerable
    app outliving the scan that needed it is the one failure this script must not have, so
    the tree kill is the primary control and the port check below is the verification.

    **The Windows branch is the exercised one; the POSIX branch has never run.** Both kill a
    tree, by the mechanism each platform offers, but only the first has been observed doing
    it. Said here rather than left for a reader to assume symmetry.
    """
    if process.poll() is None:
        if sys.platform == "win32":
            subprocess.run(  # noqa: S603 — argument list, never shell=True
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                capture_output=True,
                check=False,
                timeout=30,
            )
        else:
            # Needs `start_new_session=True` at spawn, which `start_target` passes: without
            # it the group id is this script's own and killpg would kill the capture too.
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=15)
    _log(f"target stopped (exit {process.returncode})")


def port_is_closed(attempts: int = 10) -> bool:
    """True once nothing ACCEPTS on the port. `TIME_WAIT` entries are not a listener."""
    for _ in range(attempts):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.settimeout(2)
            if probe.connect_ex(("127.0.0.1", _PORT)) != 0:
                return True
        time.sleep(1)
    return False


# ---------------------------------------------------------------------------
# 5. The scan, through the shipped adapter
# ---------------------------------------------------------------------------


async def run_active_scan() -> tuple[str, float]:
    options = ScanOptions(active_scan_consented=True)
    # Nothing overridden but the ADR-013 escape hatch: `docker_image` and
    # `timeout_seconds` stay at the values production runs, which is the whole of
    # ADR-0027 decision 3's "driven through the shipped ZapAdapter".
    adapter = ZapAdapter(dns_resolver=SystemDnsResolver(), allow_private_targets=True)
    _log("starting the active scan (this takes minutes, not seconds)")
    started = time.monotonic()
    result = await adapter.run(_TARGET_URL, options)
    elapsed = time.monotonic() - started
    _log(f"scan finished in {elapsed:.1f}s")
    return result.raw_output, elapsed


# ---------------------------------------------------------------------------
# 6-7. Report what was found, and diff the key set
# ---------------------------------------------------------------------------


def _key_sets(report: dict) -> dict[str, set[str]]:
    sets: dict[str, set[str]] = {
        "top": set(report),
        "site": set(),
        "alert": set(),
        "instance": set(),
    }
    for site in report.get("site", []):
        sets["site"] |= set(site)
        for alert in site.get("alerts", []):
            sets["alert"] |= set(alert)
            for instance in alert.get("instances", []):
                sets["instance"] |= set(instance)
    return sets


def describe(report: dict, passive_report: dict) -> None:
    _log("--- alerts ---")
    for site in report.get("site", []):
        for alert in site["alerts"]:
            print(
                f"  {alert['alertRef']:<10} risk={alert['riskcode']} conf={alert['confidence']} "
                f"cwe={alert['cweid']:<6} n={len(alert['instances'])}  {alert['name']}"
            )

    uris = sorted(
        {i["uri"] for s in report.get("site", []) for a in s["alerts"] for i in a["instances"]}
    )
    _log(f"--- crawled URIs ({len(uris)}) ---")
    for uri in uris:
        print(f"  {uri}")

    _log("--- instance fields on /calculate, per alert (the parameter attribution) ---")
    for site in report.get("site", []):
        for alert in site["alerts"]:
            for instance in alert["instances"]:
                if "/calculate" in instance.get("uri", ""):
                    populated = {k: v for k, v in instance.items() if v not in ("", None)}
                    print(f"  {alert['alertRef']}: {json.dumps(populated)[:400]}")

    _log("--- key-set diff against the committed passive zap_scan.json ---")
    new, old = _key_sets(report), _key_sets(passive_report)
    for level in ("top", "site", "alert", "instance"):
        added, removed = sorted(new[level] - old[level]), sorted(old[level] - new[level])
        print(f"  {level:<9} added={added or '-'} removed={removed or '-'}")


# ---------------------------------------------------------------------------
# 8. Redaction and the leak scan
# ---------------------------------------------------------------------------


def _local_ipv4_addresses() -> set[str]:
    found = {"127.0.0.1"}
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            found.add(info[4][0])
    except socket.gaierror:
        pass
    return found


def _redact_text(text: str, capture_hosts: set[str]) -> str:
    text = text.replace("host.docker.internal", _REDACTED_HOST)
    for address in sorted(capture_hosts, key=len, reverse=True):
        text = text.replace(address, _REDACTED_CAPTURE_HOST)
    text = text.replace(socket.gethostname(), _REDACTED_CAPTURE_HOST)
    return text


def redact_report(raw_output: str, capture_hosts: set[str]) -> str:
    # Textual, then re-parsed: the corpus rewrote named fields, but the substring is the
    # same in every one of them and a field list is a second place to go stale.
    redacted = json.loads(_redact_text(raw_output, capture_hosts))
    return json.dumps(redacted, indent=2, ensure_ascii=False) + "\n"


_REQUEST_LINE = re.compile(r'"(?P<method>[A-Z]+) (?P<target>\S+) HTTP/[\d.]+" (?P<status>\d{3})')

# Counted per LINE, not per regex hit. Werkzeug writes one line per rejected request and
# that line carries both `code 400, message` and `Bad request version`, so an alternation
# over the whole document double-counts every event — 14 for the 7 malformed TLS probes of
# the first run. ADR-0024 counts events, so this must too.
_MALFORMED = re.compile(r"Bad request version|Bad request syntax|Bad HTTP/0\.9 request type")


def summarise_access_log(text: str) -> dict[str, object]:
    """ADR-0024's table, re-derived from this run's log rather than transcribed."""
    well_formed = list(_REQUEST_LINE.finditer(text))
    paths = {m.group("target").partition("?")[0] for m in well_formed}
    statuses: dict[str, int] = {}
    for match in well_formed:
        statuses[match.group("status")] = statuses.get(match.group("status"), 0) + 1
    return {
        "requests": len(well_formed),
        "paths": len(paths),
        "path_list": sorted(paths),
        "statuses": dict(sorted(statuses.items())),
        "malformed": sum(1 for line in text.splitlines() if _MALFORMED.search(line)),
        "server_errors": sum(n for code, n in statuses.items() if code.startswith("5")),
    }


def leak_scan(files: dict[str, str], extra_patterns: dict[str, str]) -> dict[str, dict[str, int]]:
    """Report hits per pattern per file. A zero is a claim about the LIST, not the files."""
    patterns = {
        "os-username": re.escape(os.environ.get("USERNAME", "\0no-username\0")),
        "AppData": "AppData",
        "Escritorio": "Escritorio",
        "OneDrive": "OneDrive",
        "drive-letter-path": r"[A-Za-z]:\\\\?Users",
        "host.docker.internal": r"host\.docker\.internal",
        "verion-scan-dir": r"verion-scan-[0-9a-z_]+",
        "verion-zap-dir": r"verion-zap-[0-9a-z_]+",
        # This driver's own clone directory. Named separately from the two above because
        # they are `GitRepoCheckout`'s and `ZapAdapter`'s; this one is `_capture`'s.
        "verion-capture-dir": r"verion-capture-[0-9a-z_]+",
        "email-address": r"[\w.+-]+@[\w-]+\.[A-Za-z]{2,}",
        "machine-hostname": re.escape(socket.gethostname()),
        # A SECONDARY net for docker gateway and bridge addresses, and named for exactly
        # what it matches rather than for what it is aimed at: leading octet 10, 172 or
        # 192 only. It does NOT reach link-local (169.254/16) or CGNAT (100.64/10), both
        # of which `ipaddress.is_private` calls private and this capture host holds one of
        # each. The primary net for capture-host identity is the per-address
        # `capture-host-*` patterns `_capture` generates from `_local_ipv4_addresses()`,
        # which cover every address the host answers on whatever its range.
        "rfc1918-shaped-ipv4": r"\b(?:10|172|192)\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
        **extra_patterns,
    }
    return {
        name: {label: len(re.findall(pattern, text)) for label, pattern in patterns.items()}
        for name, text in files.items()
    }


def non_private_addresses(text: str) -> set[str]:
    """Every IPv4 literal `ipaddress` does NOT call private, loopback or unspecified.

    Named for the predicate rather than for RFC1918: `is_private` is wider than RFC1918 —
    it includes link-local and CGNAT — so calling the result "non-RFC1918" would claim a
    narrower sweep than the one that ran.
    """
    found = set()
    for candidate in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text):
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if not (address.is_private or address.is_loopback or address.is_unspecified):
            found.add(candidate)
    return found


# ---------------------------------------------------------------------------


async def _capture(out_dir: Path, raw_dir: Path) -> None:
    passive = json.loads(
        (ROOT / "tests/fixtures/scanners/zap_scan.json").read_text(encoding="utf-8")
    )
    capture_hosts = _local_ipv4_addresses() - {"127.0.0.1"}
    _log(f"capture-host addresses to redact: {sorted(capture_hosts) or 'none found'}")

    workspace = Path(tempfile.mkdtemp(prefix="verion-capture-"))
    raw_log = raw_dir / "app_access.raw.log"
    raw_report = raw_dir / "zap_active_scan.raw.json"
    exposure_seconds = 0.0
    try:
        checkout = clone_at_pinned_sha(workspace)
        verify_closure(checkout)

        process = start_target(checkout, raw_log)
        exposure_started = time.monotonic()
        try:
            wait_for_liveness(process)
            raw_output, scan_seconds = await run_active_scan()
        finally:
            stop_target(process)
            exposure_seconds = time.monotonic() - exposure_started

        raw_report.write_text(raw_output, encoding="utf-8")
        _log(f"raw report written ({len(raw_output)} chars); target was up {exposure_seconds:.1f}s")
        if not port_is_closed():
            raise CaptureAborted(
                f"something is STILL LISTENING on {_PORT} after the target was killed. "
                "The intentionally vulnerable app is reachable and must be stopped by hand "
                "before anything else is done."
            )
        _log(f"port {_PORT} confirmed closed")

        report = json.loads(raw_output)
        describe(report, passive)

        log_text = raw_log.read_text(encoding="utf-8", errors="replace")
        summary = summarise_access_log(log_text)
        _log("--- ADR-0024 table, re-derived from this run ---")
        print(json.dumps({k: v for k, v in summary.items() if k != "path_list"}, indent=2))
        print(f"  scan wall-clock: {scan_seconds:.1f}s")
        _log(f"paths: {summary['path_list']}")

        out_dir.mkdir(parents=True, exist_ok=True)
        report_path = out_dir / "zap_active_scan.json"
        log_path = out_dir / "app_access.log"
        report_path.write_text(
            redact_report(raw_output, capture_hosts), encoding="utf-8", newline="\n"
        )
        log_path.write_text(_redact_text(log_text, capture_hosts), encoding="utf-8", newline="\n")

        _log("--- the plan this run used, reproduced from _build_plan_yaml ---")
        print(_build_plan_yaml(_TARGET_URL, ScanOptions(active_scan_consented=True)))

        texts = {
            report_path.name: report_path.read_text(encoding="utf-8"),
            log_path.name: log_path.read_text(encoding="utf-8"),
        }
        _log("--- leak scan (a zero is a claim about the pattern list) ---")
        # The capture host's own addresses are swept as well as rewritten: `_redact_text`
        # replacing them is the fix, and this is the check that the fix worked. Passing
        # them here rather than hard-coding them is what makes the sweep true on a
        # different machine.
        host_patterns = {f"capture-host-{address}": re.escape(address) for address in capture_hosts}
        print(json.dumps(leak_scan(texts, host_patterns), indent=2))
        for name, text in texts.items():
            public = non_private_addresses(text)
            print(f"  {name}: non-private addresses = {sorted(public) or 'none'}")
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Capture one active ZAP scan (M5.9, G42).")
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=ROOT / "tests" / "integration" / "fixtures" / "active_scan",
        help="where the two redacted artifacts are written",
    )
    parser.add_argument(
        "--raw-dir",
        type=Path,
        required=True,
        help="where the UNREDACTED artifacts are written; must be outside the repository",
    )
    args = parser.parse_args()
    try:
        _reject_raw_dir_inside_the_repository(args.raw_dir)
        args.raw_dir.mkdir(parents=True, exist_ok=True)
        asyncio.run(_capture(args.out_dir, args.raw_dir))
    except CaptureAborted as exc:
        _log(f"ABORTED: {exc}")
        raise SystemExit(1) from None


def _reject_raw_dir_inside_the_repository(raw_dir: Path) -> None:
    """`--raw-dir` receives the UNREDACTED pair, so it may not be inside the tree.

    Checked rather than documented. The help text said "must be outside the repository"
    and nothing enforced it, which is the inert-guard shape this project's register keeps
    collecting: a constraint that lives only in prose is satisfied only by whoever
    remembers to read it. What it protects is concrete — the raw log carries the capture
    host's LAN address and the raw report the real target hostname, and both are one
    `git add -A` away from being committed if they land in the tree.
    """
    resolved = raw_dir.resolve()
    if resolved == ROOT or ROOT in resolved.parents:
        raise CaptureAborted(
            f"--raw-dir {resolved} is inside the repository at {ROOT}. It receives the "
            "UNREDACTED report and access log; pick a path outside the tree."
        )


if __name__ == "__main__":
    main()
