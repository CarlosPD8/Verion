from typing import Protocol

from verion.modules.scanning.domain.raw_scan_result import RawScanResult
from verion.modules.scanning.domain.scan_options import ScanOptions
from verion.modules.scanning.domain.scanner_target_kind import ScannerTargetKind
from verion.shared_kernel.scanner_tools import ScannerTool


class ScannerPort(Protocol):
    tool: ScannerTool
    """Which scanner this is, known *before* run() is called.

    Dispatch selects scanners by name, but `tool` used to be knowable only
    after run() returned, inside RawScanResult. Each adapter declares it as a
    class-level constant and builds its RawScanResult from that same constant,
    so the identity used to select a scanner and the identity persisted with
    its output cannot drift apart.
    """

    target_kind: ScannerTargetKind
    """What this scanner's `target` argument is — see ScannerTargetKind."""

    async def run(self, target: str, options: ScanOptions) -> RawScanResult:
        """Runs the tool and returns its raw output.

        `target` means different things per adapter — a local, already-
        checked-out filesystem path for repo-based scanners (SemgrepAdapter,
        TrivyAdapter), or a live target URL for a scanner that attacks a
        running application (ZapAdapter). `target_kind` declares which, so a
        caller no longer has to know per adapter.

        `options` carries per-scan, per-project verdicts that dispatch computes
        once and hands to every scanner (ADR-0024 decision 4). **SemgrepAdapter
        and TrivyAdapter read nothing from it** and say so at their own
        signatures; today only ZapAdapter does, reading
        `active_scan_consented` to decide whether its plan carries an
        `activeScan` job.

        **Required, with no default, and that is deliberate.** A default would
        make omitting it legal at a call site, and the value being omitted is a
        consent verdict — the failure would be an active scan silently
        downgraded, or worse, a future field defaulting to the permissive value.
        `mypy --strict` over the three adapters is what makes the omission
        impossible instead.
        """
        ...
