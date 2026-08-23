class NormalizationError(Exception):
    """Base for this module's own failures.

    Deliberately not raised for the two cases that look like errors and are not:
    a scan whose every tool failed normalizes to zero findings and a `completed`
    run (ADR-0017 decision 3), and a finding group that disagrees on a rule-level
    attribute is skipped rather than raised past (ADR-0019 decision 2, decided in
    ADR-0021).
    """


class UnknownScannerOutput(NormalizationError):
    """A persisted `ScanResult` names a tool this module has no mapper for.

    Unreachable through the write path: `RunScanUseCase` persists
    `str(scanner.tool)` from a `ScannerTool` member, and dispatch is keyed by that
    enum. It is raised rather than skipped because reaching it means either a row
    was written around the repository or a tool was removed from the enum while
    its rows remained — deployment configuration this project controls, which
    ADR-016 decision 2 draws the raise/degrade line at. Contrast an unrecognised
    *severity* string, which degrades to `UNKNOWN`: that is upstream data a tool
    can change in any release.
    """
