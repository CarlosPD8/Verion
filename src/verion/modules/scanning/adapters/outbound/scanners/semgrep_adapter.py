import asyncio

from verion.modules.scanning.domain.exceptions import ScannerExecutionFailed
from verion.modules.scanning.domain.raw_scan_result import RawScanResult
from verion.modules.scanning.domain.scanner_target_kind import ScannerTargetKind
from verion.shared_kernel.scanner_tools import ScannerTool


class SemgrepAdapter:
    # Declared before run(), so dispatch can select this adapter without
    # running it, and reused below as RawScanResult's tool so the identity
    # selected on and the identity persisted cannot drift (ADR-016 decision 4).
    tool = ScannerTool.SEMGREP
    target_kind = ScannerTargetKind.REPO_PATH

    def __init__(self, config: str, timeout_seconds: float = 60.0) -> None:
        self._config = config
        self._timeout_seconds = timeout_seconds

    async def run(self, target: str) -> RawScanResult:
        # Two flags and a `cwd` that exist for one reason: both `results[].path`
        # and `results[].check_id` are `dedup_hash` inputs (ADR-0019 decision 3),
        # and by default Semgrep renders BOTH of them relative to the process's
        # current working directory. `target` is a `tempfile.mkdtemp` path from
        # GitRepoCheckout, so neither was stable across scans. Measured across
        # four CWD/argument combinations, not deduced — see ADR-0019's Amendments,
        # G9 and G10.
        #
        # `cwd=target` + `.` fixes `path`: it becomes repo-relative instead of
        # carrying that scan's unique absolute prefix, which is what made every
        # Semgrep finding re-key on every scan while Trivy and ZAP deduped
        # correctly (G9).
        #
        # `--no-rewrite-rule-ids` fixes `check_id`, and it is also what DECOUPLES
        # the two — without it, the `cwd` above is precisely what breaks the other
        # field. `--rewrite-rule-ids` is on by default and prefixes each rule's own
        # id with the config file's directory path rendered relative to CWD; moving
        # CWD to a mkdtemp puts the ruleset outside it and flips `check_id` to the
        # absolute dotted install path. So fixing `path` naively re-keys every
        # finding through `rule_id` in the same change (G10). Negated, `check_id`
        # is the rule's own `id` from default.yml — invariant across CWD, install
        # path and container WORKDIR, and carrying no filesystem path into a field
        # M4.5 returns in a response body. Namespacing stays available and is ours
        # to author in the ruleset (`id: dangerous-eval` today).
        #
        # What pins each half, established by mutation rather than by reading —
        # and it is NOT one test covering both, which is what the obvious reading
        # would be:
        #
        # - Removing `--no-rewrite-rule-ids` alone fails ONLY the
        #   `check_id == "dangerous-eval"` equality in
        #   test_returns_raw_json_with_the_expected_finding. The CWD-invariance
        #   test still passes, because `cwd=target` already fixes the child's CWD,
        #   so the dotted form it produces is the same one from either parent CWD.
        # - Reverting `cwd`/`.` alone fails ONLY the `path == "vulnerable.py"`
        #   equality in that same test.
        # - Reverting both — the pre-M4.4 invocation — fails the equality test AND
        #   test_rule_id_and_path_do_not_depend_on_the_worker_s_working_directory,
        #   which is the only one of the three that observes the parent process's
        #   CWD leaking into a hash input at all.
        #
        # So the two equality assertions guard the two flags, one each, and the
        # invariance test guards the broader shape (an absolute target with no
        # `cwd`). Do not weaken either equality to `endswith` — the assertion this
        # replaced was `endswith("dangerous-eval")`, which passed for all three of
        # the CWD-dependent dotted forms G10 measured.
        process = await asyncio.create_subprocess_exec(
            "semgrep",
            "scan",
            "--config",
            self._config,
            "--no-rewrite-rule-ids",
            "--json",
            ".",
            cwd=target,
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

        return RawScanResult(tool=self.tool, raw_output=stdout.decode())
