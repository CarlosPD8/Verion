class CorrelationError(Exception):
    """Base for this module's own failures."""


class ProjectAccessDenied(CorrelationError):
    """The caller may not read this project — because it does not exist, or because they
    are not a member, and this type deliberately cannot say which.

    That is not vagueness, it is the policy. `ProjectAccessPort.may_read_project` returns
    one bool precisely so no consumer can distinguish the two cases, and a 403 here would
    tell an unauthorized caller that the project exists.

    **This module's own exception rather than `normalization`'s identically-named one**,
    for exactly the reason that one gives for not being `projects`' `InsufficientPermissions`:
    it lives in another module's `domain/` (rule 3). The two carry the same information,
    which is none beyond "no", so nothing is lost by the duplication and a boundary is kept.
    """
