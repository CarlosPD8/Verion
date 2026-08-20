import contextlib
import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from verion.modules.scanning.adapters.outbound.dns.system_dns_resolver import SystemDnsResolver
from verion.modules.scanning.adapters.outbound.scanners.zap_adapter import ZapAdapter
from verion.modules.scanning.domain.exceptions import ScannerExecutionFailed

# X-Content-Type-Options is one of several headers Python's stock
# http.server omits by default — verified directly against a real ZAP scan
# of this exact fixture during implementation, not assumed: ZAP's default
# passive scanner reliably flags alertRef 10021 ("X-Content-Type-Options
# Header Missing") against it, alongside CSP/clickjacking/Server-header
# alerts not asserted on here since one reliable, verified alert is enough
# to prove the adapter round-trips a real finding.
_EXPECTED_ALERT_REF = "10021"


class _MinimalTargetHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 (http.server's required method name)
        body = b"<html><body><h1>verion zap fixture</h1></body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass  # keep pytest output free of per-request access logs


@contextlib.contextmanager
def _local_target_server() -> Iterator[int]:
    # Bound to 0.0.0.0, not 127.0.0.1: on Docker Desktop for Windows (this
    # dev machine), host.docker.internal's routing happened to reach even a
    # 127.0.0.1-bound host server too — verified directly, not assumed — but
    # that's a Docker-Desktop-specific proxying behavior, not something to
    # rely on. On the Linux GitHub Actions runner, --add-host ...:host-gateway
    # routes to the host's real network interfaces, which does not include
    # loopback-only binds. 0.0.0.0 is the one binding that's reachable on
    # both, so it's the only one this test should use.
    server = ThreadingHTTPServer(("0.0.0.0", 0), _MinimalTargetHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        thread.join(timeout=5)


async def test_returns_raw_json_report_with_the_expected_finding():
    with _local_target_server() as port:
        adapter = ZapAdapter(dns_resolver=SystemDnsResolver(), allow_private_targets=True)
        result = await adapter.run(f"http://host.docker.internal:{port}/")

    assert result.tool == "zap"
    report = json.loads(result.raw_output)
    alert_refs = {alert["alertRef"] for site in report["site"] for alert in site["alerts"]}
    assert _EXPECTED_ALERT_REF in alert_refs


async def test_raises_on_an_unreachable_target():
    adapter = ZapAdapter(
        dns_resolver=SystemDnsResolver(), allow_private_targets=True, timeout_seconds=90.0
    )

    # Port 1 inside the container's network namespace refuses/unreaches the
    # connection immediately — verified directly during implementation
    # (ZAP's spider job reports "Network is unreachable" and the automation
    # plan exits nonzero), same class of "genuine tool/target failure" as
    # TrivyAdapter's nonexistent-path test.
    with pytest.raises(ScannerExecutionFailed):
        await adapter.run("http://host.docker.internal:1/")
