"""`ProjectAccessPort`'s contract, held by the fake AND `PostgresProjectAccessReader` alike.

**Why the fake is tested at all.** Every unit test of a use case that authorizes through this
port runs against `InMemoryProjectAccess`, and a fake nobody checks against the real adapter
proves only the consumer's side of a contract (G65). M8.8 added a second verdict,
`may_manage_project`, so the two now have a table of answers to agree on: this file builds
one scenario both ways and asks both for the whole table.

The fake arrives through `project_access_factory` (`tests/conftest.py`), so it is the same
class every unit test uses.
"""

from datetime import UTC, datetime

import pytest

from verion.modules.projects.adapters.outbound.db.repository import (
    PostgresProjectAccessReader,
    PostgresProjectMembershipRepository,
    PostgresProjectRepository,
)
from verion.modules.projects.domain.project import Project, ProjectMembership, Role

_PROJECT = "project-contract"
_ABSENT = "project-absent"
_OWNER = "user-owner"
_MEMBER = "user-member"
_STRANGER = "user-stranger"

# (project, user) → (may_read_project, may_manage_project). The whole contract, as data.
_EXPECTED = {
    (_PROJECT, _OWNER): (True, True),
    (_PROJECT, _MEMBER): (True, False),
    (_PROJECT, _STRANGER): (False, False),
    (_ABSENT, _OWNER): (False, False),
}


async def _postgres(db_session, _factory):
    await PostgresProjectRepository(db_session).add(
        Project(id=_PROJECT, owner_id=_OWNER, name="Contract", created_at=datetime.now(UTC))
    )
    memberships = PostgresProjectMembershipRepository(db_session)
    await memberships.add(ProjectMembership(project_id=_PROJECT, user_id=_OWNER, role=Role.OWNER))
    await memberships.add(ProjectMembership(project_id=_PROJECT, user_id=_MEMBER, role=Role.MEMBER))
    await db_session.commit()
    return PostgresProjectAccessReader(db_session)


async def _fake(_db_session, factory):
    access = factory()
    access.permit_manage(_PROJECT, _OWNER)
    access.permit(_PROJECT, _MEMBER)
    return access


@pytest.mark.parametrize("build", [_fake, _postgres], ids=["fake", "postgres"])
async def test_both_implementations_answer_the_same_verdict_table(
    build, db_session, project_access_factory
):
    """Kills `PostgresProjectAccessReader.may_manage_project` returning the read verdict (the
    member row fails), and a fake that drifts from the real rule in either direction."""
    access = await build(db_session, project_access_factory)

    observed = {
        (project, user): (
            await access.may_read_project(project_id=project, user_id=user),
            await access.may_manage_project(project_id=project, user_id=user),
        )
        for project, user in _EXPECTED
    }

    assert observed == _EXPECTED
