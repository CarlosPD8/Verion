import asyncio

from verion.modules.scanning.domain.exceptions import ScannerExecutionFailed
from verion.modules.scanning.domain.raw_scan_result import RawScanResult


class SemgrepAdapter:
    def __init__(self, config: str, timeout_seconds: float = 60.0) -> None:
        self._config = config
        self._timeout_seconds = timeout_seconds

    async def run(self, target: str) -> RawScanResult:
        process = await asyncio.create_subprocess_exec(
            "semgrep",
            "scan",
            "--config",
            self._config,
            "--json",
            target,
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
            raise ScannerExecutionFailed(f"semgrep scan of '{target}' timed out") from None

        if process.returncode != 0:
            # exit 1 only occurs when --error is passed (never done here), so
            # any non-zero code here is a genuine tool failure, not "findings
            # found" — per Semgrep's own documented exit codes.
            raise ScannerExecutionFailed(
                f"semgrep scan of '{target}' failed: {stderr.decode(errors='replace')}"
            )

        return RawScanResult(tool="semgrep", raw_output=stdout.decode())
