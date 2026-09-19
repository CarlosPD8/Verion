"""`projects`' verdict rules agree with the raising rules they sit beside.

`may_manage` is the rule behind `ProjectAccessPort.may_manage_project` (ADR-0035 decision 2),
and its docstring claims it agrees with `require_owner` by construction. This pins that claim
for every membership the model can express, so the verdict another module consumes cannot
drift from the check `projects`' own use cases run.
"""

import pytest

from verion.modules.projects.domain.authorization import may_manage, require_owner
from verion.modules.projects.domain.exceptions import InsufficientPermissions
from verion.modules.projects.domain.project import ProjectMembership, Role


def _owner_check_passes(membership: ProjectMembership | None) -> bool:
    try:
        require_owner(membership)
    except InsufficientPermissions:
        return False
    return True


@pytest.mark.parametrize(
    "membership",
    [
        ProjectMembership(project_id="p", user_id="u", role=Role.OWNER),
        ProjectMembership(project_id="p", user_id="u", role=Role.MEMBER),
        None,
    ],
    ids=["owner", "member", "no-membership"],
)
def test_may_manage_agrees_with_require_owner(membership):
    """Kills `may_manage = membership is not None`, which fails on the member case."""
    assert may_manage(membership) is _owner_check_passes(membership)


def test_only_an_owner_may_manage():
    assert may_manage(ProjectMembership(project_id="p", user_id="u", role=Role.OWNER))
    assert not may_manage(ProjectMembership(project_id="p", user_id="u", role=Role.MEMBER))
    assert not may_manage(None)
