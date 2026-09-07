import asyncio
import contextlib
import os
import shutil
import tempfile
import uuid
from pathlib import Path
from urllib.parse import urlparse

import yaml

from verion.modules.scanning.domain.exceptions import ScannerExecutionFailed
from verion.modules.scanning.domain.raw_scan_result import RawScanResult
from verion.modules.scanning.domain.scan_options import ScanOptions
from verion.modules.scanning.domain.scanner_target_kind import ScannerTargetKind
from verion.modules.scanning.domain.target_url import (
    validate_resolved_ips_are_public,
    validate_target_url_syntax,
)
from verion.modules.scanning.ports.dns_resolver import DnsResolverPort
from verion.shared_kernel.scanner_tools import ScannerTool

_REPORT_FILENAME = "report.json"
_PLAN_FILENAME = "plan.yaml"
_WORKDIR_IN_CONTAINER = "/zap/wrk"


class ZapAdapter:
    # The only URL-kind scanner. Dispatch reads target_kind to decide what to
    # pass as `target` — a configured target URL here, the shared checkout path
    # for the repo-based scanners — rather than branching on `tool == "zap"`,
    # which would special-case an integration inside application logic (rule 4).
    tool = ScannerTool.ZAP
    target_kind = ScannerTargetKind.URL

    def __init__(
        self,
        dns_resolver: DnsResolverPort,
        # 540s, raised from 300s at M5.4. ADR-0024 decision 5 leaves this
        # arithmetic to the issue that adds the activeScan job; it is:
        #
        #   plan ceilings   spider 2 + passiveScan-wait 2 + activeScan 3
        #                 = 7 min = 420s  <  540s          [inequality 1]
        #   checkout 30s (GitRepoCheckout's own timeout, its default and not
        #   overridden in worker.py) + max(semgrep 60, trivy 180, zap 540)
        #                 = 570s          <  600s          [inequality 2]
        #
        # `max`, not a sum, because ADR-016 decision 1 runs the enabled
        # scanners concurrently. 600 is WorkerSettings.job_timeout, which is
        # NOT raised to make room: settings.py's comment on
        # normalization_sweep_stale_after_seconds records that raising it makes
        # the sweep start continuously re-enqueuing live work.
        #
        # The two margins are CHOSEN, not measured, and they protect different
        # things. Inequality 1's 120s covers what the plan's own clock does not
        # — container start, image entrypoint, report write, teardown.
        # Inequality 2's 30s covers the rest of the arq job: the ScanResult
        # upserts, the normalization handoff row and the status update. No
        # committed ZAP test and no probe run has ever approached either bound.
        timeout_seconds: float = 540.0,
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

    async def run(self, target: str, options: ScanOptions) -> RawScanResult:
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
        # tempfile.mkdtemp creates the dir mode 0700 (owner-only). The ZAP
        # image runs zap.sh as a baked-in non-root user (uid 1000, "zap" -
        # confirmed via `docker inspect`/`id` against the real image, not
        # assumed), which on a native Linux Docker host is NOT the same uid
        # that created this directory - a bind mount does not remap
        # ownership, so 0700 leaves the container's user with no access at
        # all to even traverse into it (verified directly: reproduced this
        # exact permission-denied failure with a real cross-uid bind mount,
        # confirmed the container could read AND write once the directory
        # was reopened to 0777). Docker Desktop's Windows bind-mount layer
        # doesn't enforce this the same way, which is why this only surfaced
        # on the Linux CI runner (ADR-0011 point #9). 0777 is deliberately
        # permissive rather than matching uids: this directory holds a scan
        # target URL and (once written) alert findings, not a credential -
        # rule 12 doesn't apply - and it's removed in the finally block
        # below regardless of outcome, so the exposure window is this one
        # call's lifetime, not persistent.
        os.chmod(plan_dir, 0o777)
        container_name = f"verion-zap-{uuid.uuid4().hex}"
        try:
            # Consent is read HERE and nowhere earlier (ADR-0024 decisions 4
            # and 6). Both ADR-013 gates are already behind us, so a target
            # this adapter refused never reaches the plan builder at all —
            # consent narrows what is done to an admitted target and can never
            # widen which targets are admitted.
            Path(plan_dir, _PLAN_FILENAME).write_text(_build_plan_yaml(target, options))

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
            return RawScanResult(tool=self.tool, raw_output=report_path.read_text())
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


def _active_scan_jobs(options: ScanOptions) -> list[dict[str, object]]:
    """The `activeScan` job, or nothing at all — ADR-0024 decision 5's parameters.

    A list spliced into the plan rather than a job dict with a conditional inside
    it, so an unconsented plan carries no `activeScan` key at all instead of a
    disabled job somebody later has to reason about.

    `policy` is absent deliberately: ZAP's default is the only policy this project
    has any evidence about, since it is what the M5.4 probe ran. The bound is the
    context and the clock, not an allow-list of rule classes.
    """
    if not options.active_scan_consented:
        return []
    return [
        {
            "type": "activeScan",
            "parameters": {
                # The plan declares exactly one context and its `urls` is
                # [target], so this scopes the attack to that target's subtree.
                "context": "verion-target",
                "maxRuleDurationInMins": 1,
                "maxScanDurationInMins": 3,
                "threadPerHost": 2,
            },
        }
    ]


def _build_plan_yaml(target: str, options: ScanOptions) -> str:
    # Spider + passive scanning always; `activeScan` only behind explicit
    # per-project consent (ADR-0024). Without consent the job LIST is what it was
    # before M5.4 — spider, passiveScan-wait, report — but the plan is NOT
    # identical to it: `passiveScan-wait`'s ceiling drops here too. Both edits are
    # changes to a pinned scan plan and both fire G39; the unconsented path is
    # narrower, not untouched.
    #
    # `passiveScan-wait` dropped 5 -> 2 minutes here, and that is a ceiling
    # rather than a duration: it waits for the passive queue to drain, which no
    # committed ZAP test has ever spent more than seconds on. Lowered because
    # ADR-0024 decision 5's first inequality has to
    # hold and this is the cap furthest above anything ever observed; `spider`
    # is deliberately NOT lowered, since it bounds crawl coverage on a target
    # nobody here has measured.
    #
    # yaml.safe_dump (not an f-string) so a target URL containing YAML-special
    # characters can never corrupt the plan's structure.
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
                    "maxDuration": 2,
                },
            },
            *_active_scan_jobs(options),
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
