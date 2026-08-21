from collections.abc import Sequence

from verion.modules.scanning.domain.scan import ScanStatus
from verion.modules.scanning.domain.scan_result import ScanResult, ScanResultStatus
from verion.shared_kernel.scanner_tools import ScannerTool

# Semgrep and Trivy need nothing but a checked-out repo — no user-supplied
# target, so no SSRF surface — which is what makes them safe to run without an
# explicit opt-in. ZAP's absence is that same reasoning inverted, not a
# convenience: it requires a target URL only a user can supply, so it cannot be
# defaulted on at all.
#
# The default lives in `scanning`, not in `projects` alongside ScannerConfig,
# because its rationale is a property of the scanners — what they take as a
# target and what that exposes — which is this module's knowledge. `projects`
# records what a user chose; this decides what happens when they chose nothing.
# (It also could not live there: `scanning` may not import another module's
# domain, only its ports — rule 3.)
#
# A constant rather than a backfill migration: every project predating
# scanner_configs works immediately, with no rows to keep in sync and nothing
# to go stale. See ADR-016 decision 3.
DEFAULT_ENABLED_TOOLS: tuple[ScannerTool, ...] = (ScannerTool.SEMGREP, ScannerTool.TRIVY)


def resolve_enabled_tools(configured: Sequence[ScannerTool] | None) -> tuple[ScannerTool, ...]:
    """Which scanners to run, given what a project configured (or didn't).

    `None` means *never configured* and gets the default. An empty sequence
    means *configured to run nothing*, and is returned as-is — the two are
    different answers and this is the one place that distinction is made, so a
    caller can't collapse them with a truthiness check.
    """
    return DEFAULT_ENABLED_TOOLS if configured is None else tuple(configured)


def derive_scan_status(results: Sequence[ScanResult]) -> ScanStatus:
    """The Scan-level summary of a set of per-tool outcomes.

    Pure, and separate from RunScanUseCase, because this is the rule M8's
    dashboard and any future reader will reason about — it should be readable
    and testable without standing up a use case.

    Note this is only ever a *summary*. M4 asks get_succeeded_by_scan_id which
    results it can trust; it does not re-derive that from this value.
    """
    if not results:
        # Callers reaching here with no results have already raised
        # NoScannersEnabled; this keeps the function total rather than
        # returning something misleading for an input it should never see.
        return ScanStatus.FAILED

    succeeded = sum(1 for result in results if result.status is ScanResultStatus.SUCCEEDED)
    if succeeded == len(results):
        return ScanStatus.COMPLETED
    if succeeded == 0:
        return ScanStatus.FAILED
    return ScanStatus.PARTIAL
