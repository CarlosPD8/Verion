from dataclasses import dataclass


@dataclass(frozen=True)
class ScanOptions:
    """Per-scan, per-project switches that dispatch hands to every scanner.

    **Carries verdicts, never the state a verdict was computed from.**
    `active_scan_consented` is `ScannerConfig.active_scan_consent_in_force` copied
    across the module boundary as a bool, which is the whole reason commit 1 made
    that a derived property rather than three columns a reader compares. Putting
    `active_scan_consent_target` and `zap_target_url` here instead would give
    `scanning` a second copy of `projects`' consent rule (rule 3) — two
    implementations of one policy, agreeing until somebody edits one.

    **One value passed to every scanner, not a per-tool payload**, which is what
    keeps dispatch's shape generic: each adapter reads the fields it understands and
    `RunScanUseCase` has no `tool == "zap"` branch (rule 4). It is the same move
    ADR-016 decision 4 made for `target_kind`, applied to a value rather than to
    routing, and ADR-0024 decision 4 is where it is decided.

    Deliberately not defaulted anywhere it is constructed or consumed. `False` is the
    safe value, so a default would be safe *today* — and it is exactly the door
    through which a later field gets omitted at one call site and silently takes its
    default. `mypy --strict` over three adapters and one use case is the cheaper
    guarantee.
    """

    active_scan_consented: bool
