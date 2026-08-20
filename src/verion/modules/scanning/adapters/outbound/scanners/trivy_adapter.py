import asyncio

from verion.modules.scanning.domain.exceptions import ScannerExecutionFailed
from verion.modules.scanning.domain.raw_scan_result import RawScanResult


class TrivyAdapter:
    def __init__(self, timeout_seconds: float = 180.0, skip_db_update: bool = False) -> None:
        self._timeout_seconds = timeout_seconds
        # Deliberately the opposite default from SemgrepAdapter's bundled,
        # pinned ruleset (see rulesets/default.yml's own comment): Semgrep's
        # static pattern rules don't go stale, but a vulnerability database
        # does — freezing it would silently defeat this scanner's entire
        # value proposition, which is currency against newly-disclosed CVEs.
        # Production leaves this False (live DB refresh); tests pass
        # skip_db_update=True against a pre-warmed cache so assertions never
        # depend on live network access or on which CVEs are newly published
        # on a given run. See ADR-0012.
        self._skip_db_update = skip_db_update

    async def run(self, repo_path: str) -> RawScanResult:
        args = ["fs", "--format", "json"]
        if self._skip_db_update:
            args.append("--skip-db-update")
        args.append(repo_path)

        process = await asyncio.create_subprocess_exec(
            "trivy",
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=self._timeout_seconds
            )
        except TimeoutError:
            # asyncio.wait_for alone does not kill the underlying child.
            process.kill()
            await process.wait()
            raise ScannerExecutionFailed(f"trivy scan of '{repo_path}' timed out") from None

        if process.returncode != 0:
            # No --exit-code flag is passed above: Trivy's default behavior
            # already exits 0 when vulnerabilities ARE found (findings are
            # success data, not adapter failure) and only exits nonzero on a
            # genuine tool error (bad args, unreadable path, DB fetch
            # failure) — simpler than SemgrepAdapter's case, nothing to
            # opt out of here.
            raise ScannerExecutionFailed(
                f"trivy scan of '{repo_path}' failed: {stderr.decode(errors='replace')}"
            )

        return RawScanResult(tool="trivy", raw_output=stdout.decode())
