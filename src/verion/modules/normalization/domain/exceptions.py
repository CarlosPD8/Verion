class NormalizationError(Exception):
    """Base for this module's own failures.

    Deliberately not raised for the two cases that look like errors and are not:
    a scan whose every tool failed normalizes to zero findings and a `completed`
    run (ADR-0017 decision 3), and a finding group that disagrees on a rule-level
    attribute is skipped rather than raised past (ADR-0019 decision 2, decided in
    ADR-0021).
    """


class ProjectAccessDenied(NormalizationError):
    """The caller may not read this project — because it does not exist, or
    because they are not a member, and this type deliberately cannot say which.

    That is not vagueness, it is the policy. `ProjectAccessPort.may_read_project`
    returns one bool precisely so no consumer can distinguish the two cases, and
    the route maps this to **404** for both. A 403 here would tell an
    unauthorized caller that the project exists, which on a *findings* endpoint
    is project enumeration against the most sensitive read in the system.

    It is this module's own exception rather than `projects`' `InsufficientPermissions`
    because that type lives in another module's `domain/` (rule 3). Nothing is
    lost: the two carry the same information, which is none beyond "no".
    """


class FindingNotFound(NormalizationError):
    """No such finding in this project.

    Raised for a `finding_id` that does not exist AND for one that exists in a
    different project, indistinguishably — the same reasoning as
    `ProjectAccessDenied`, one level down. A caller who is authorized for project
    A must not be able to probe which finding ids exist in project B.
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
