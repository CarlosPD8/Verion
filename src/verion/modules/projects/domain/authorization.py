from verion.modules.projects.domain.exceptions import InsufficientPermissions
from verion.modules.projects.domain.project import ProjectMembership, Role


def require_owner(membership: ProjectMembership | None) -> None:
    if membership is None or membership.role is not Role.OWNER:
        raise InsufficientPermissions("This action requires an owner membership")


def require_member(membership: ProjectMembership | None) -> None:
    if membership is None:
        raise InsufficientPermissions("This action requires project membership")


def may_read(membership: ProjectMembership | None) -> bool:
    """Whether this membership permits reading the project's data. THE rule.

    **This module owns what membership means, and that is the whole point of this
    function existing separately from `require_member`.** Since M4.5 a second
    module authorizes against project membership — `normalization`'s findings
    routes — and it may not import anything from this package's `domain/` (rule 3,
    `cross-module-projects`). It reaches this rule through
    `ProjectAccessPort.may_read_project`, which returns the *verdict* rather than
    the `ProjectMembership` the verdict is made from.

    The alternative was for each consumer to read a membership through
    `ProjectMembershipRepositoryPort` and check `is None` itself. That is
    contract-legal and design-wrong: a *persistence* port would be carrying this
    module's domain knowledge — "authorization is a membership row existing" —
    out to every consumer, and the rule would then have one copy per module with
    nothing relating them. When a VIEWER role lands, or reads become
    role-sensitive, this function changes and every consumer follows. Under the
    copies, none of them would hear about it, and none would fail loudly: they
    would keep authorizing under the old rule.

    Returns a bool where `require_member` raises, because its caller is an adapter
    implementing a port that answers a question, not a use case enforcing a
    policy. `require_member` stays for this module's own use cases, and the two
    agree by construction: both are "a membership exists".
    """
    return membership is not None
