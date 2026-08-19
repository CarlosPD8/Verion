from verion.modules.projects.domain.exceptions import InsufficientPermissions
from verion.modules.projects.domain.project import ProjectMembership, Role


def require_owner(membership: ProjectMembership | None) -> None:
    if membership is None or membership.role is not Role.OWNER:
        raise InsufficientPermissions("This action requires an owner membership")
