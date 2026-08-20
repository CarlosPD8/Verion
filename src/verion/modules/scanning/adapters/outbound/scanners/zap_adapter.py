import asyncio
import contextlib
import shutil
import tempfile
import uuid
from pathlib import Path
from urllib.parse import urlparse

import yaml

from verion.modules.scanning.domain.exceptions import ScannerExecutionFailed
from verion.modules.scanning.domain.raw_scan_result import RawScanResult
from verion.modules.scanning.domain.target_url import (
    validate_resolved_ips_are_public,
    validate_target_url_syntax,
)
from verion.modules.scanning.ports.dns_resolver import DnsResolverPort

_REPORT_FILENAME = "report.json"
_PLAN_FILENAME = "plan.yaml"
_WORKDIR_IN_CONTAINER = "/zap/wrk"


class ZapAdapter:
    def __init__(
        self,
        dns_resolver: DnsResolverPort,
        timeout_seconds: float = 300.0,
        # TEST-ONLY escape hatch, mirrors TrivyAdapter.skip_db_update's
        # "safe production default, explicit test-only override" shape (see
        # ADR-0012 for that precedent, ADR-0013 for this one). Production
        # code must never set this True: it disables the entire SSRF gate,
        # including the DNS-rebinding check. It exists only because a real
        # integration test needs a target ZAP can actually attack, and no
        # CI-reachable target exists outside a locally-bound fixture server.
        allow_private_targets: bool = False,
        # Pinned to a digest, not the floating `:stable` tag, per this repo's
        # ADR-0009 verification standard (mirrors ci.yml's SHA-pinned Trivy
        # action). Confirmed 2026-08-20: this is `ghcr.io/zaproxy/zaproxy
        # :stable` as of that date, pulled and run successfully against a
        # real local target during implementation.
        docker_image: str = (
            "ghcr.io/zaproxy/zaproxy@sha256:"
            "781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef"
        ),
    ) -> None:
        self._dns_resolver = dns_resolver
        self._timeout_seconds = timeout_seconds
        self._allow_private_targets = allow_private_targets
        self._docker_image = docker_image

    async def run(self, target: str) -> RawScanResult:
        # Validated before any subprocess/Docker call — the SSRF gate, same
        # placement convention as GitRepoCheckout.checkout's
        # parse_github_clone_url call. Two steps: syntax (pure, catches
        # literal-IP/localhost tricks with zero I/O) then resolved-IP (the
        # DNS-rebinding gate — a hostname string proves nothing on its own).
        if not self._allow_private_targets:
            validate_target_url_syntax(target)
            hostname = urlparse(target).hostname
            assert hostname  # guaranteed non-empty by validate_target_url_syntax above
            resolved_ips = await self._dns_resolver.resolve(hostname)
            validate_resolved_ips_are_public(resolved_ips)

        plan_dir = tempfile.mkdtemp(prefix="verion-zap-")
        container_name = f"verion-zap-{uuid.uuid4().hex}"
        try:
            Path(plan_dir, _PLAN_FILENAME).write_text(_build_plan_yaml(target))

            process = await asyncio.create_subprocess_exec(
                "docker",
                "run",
                "--rm",
                "--name",
                container_name,
                # Lets a container-side scan reach a target bound on the
                # docker host (e.g. this project's own integration-test
                # fixture server) without loosening the container's network
                # isolation for a real, publicly-reachable target — a no-op
                # unless the target literally references this hostname.
                "--add-host",
                "host.docker.internal:host-gateway",
                "-v",
                f"{plan_dir}:{_WORKDIR_IN_CONTAINER}:rw",
                self._docker_image,
                "zap.sh",
                "-cmd",
                "-autorun",
                f"{_WORKDIR_IN_CONTAINER}/{_PLAN_FILENAME}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                _, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=self._timeout_seconds
                )
            except TimeoutError:
                # asyncio.wait_for alone does not kill the underlying child,
                # and for a `docker run` client process, even killing THAT
                # does not stop the container running server-side on the
                # Docker daemon (ADR-0011 point #8) — both kills are needed,
                # not either/or.
                process.kill()
                await process.wait()
                await _docker_kill_best_effort(container_name)
                raise ScannerExecutionFailed(f"zap scan of '{target}' timed out") from None

            if process.returncode != 0:
                raise ScannerExecutionFailed(
                    f"zap scan of '{target}' failed: {stderr.decode(errors='replace')}"
                )

            report_path = Path(plan_dir, _REPORT_FILENAME)
            return RawScanResult(tool="zap", raw_output=report_path.read_text())
        finally:
            shutil.rmtree(plan_dir, ignore_errors=True)


async def _docker_kill_best_effort(container_name: str) -> None:
    # Best-effort: the container may have already exited on its own between
    # our timeout firing and this call, in which case `docker kill` fails —
    # that failure is expected and not itself an error worth surfacing.
    with contextlib.suppress(Exception):
        kill_process = await asyncio.create_subprocess_exec(
            "docker",
            "kill",
            container_name,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await kill_process.wait()


def _build_plan_yaml(target: str) -> str:
    # A bounded baseline-equivalent scan — spider + passive scanning only,
    # deliberately no `activeScan` job (an active scan is unbounded in scope
    # and makes real attack requests against the target; out of scope for
    # this issue). yaml.safe_dump (not an f-string) so a target URL
    # containing YAML-special characters can never corrupt the plan's
    # structure.
    plan = {
        "env": {
            "contexts": [
                {
                    "name": "verion-target",
                    "urls": [target],
                }
            ]
        },
        "jobs": [
            {
                "type": "spider",
                "parameters": {
                    "url": target,
                    "maxDuration": 2,
                },
            },
            {
                "type": "passiveScan-wait",
                "parameters": {
                    "maxDuration": 5,
                },
            },
            {
                "type": "report",
                "parameters": {
                    "template": "traditional-json",
                    "reportDir": _WORKDIR_IN_CONTAINER,
                    "reportFile": _REPORT_FILENAME,
                    "reportTitle": "Verion DAST scan",
                },
            },
        ],
    }
    return yaml.safe_dump(plan, sort_keys=False)
