"""`ListSecurityBriefsUseCase`: the verdict first, then `brief`'s own table. ADR-0033."""

import pytest

from verion.modules.brief.application.list_security_briefs import (
    DEFAULT_PAGE_LIMIT,
    ListSecurityBriefsUseCase,
)
from verion.modules.brief.domain.exceptions import SecurityBriefAccessDenied

PROJECT = "proj-1"
USER = "user-1"


class _ExplodingBriefs:
    """Raises if touched, so a denial is shown to happen before any read."""

    async def list_for_project(self, **_):
        raise AssertionError("read before authorization")

    async def count_for_project(self, _):
        raise AssertionError("read before authorization")


class _RecordingBriefs:
    def __init__(self):
        self.calls = []

    async def list_for_project(self, *, project_id, limit, offset):
        self.calls.append(("list", project_id, limit, offset))
        return ["brief-a", "brief-b"]

    async def count_for_project(self, project_id):
        self.calls.append(("count", project_id))
        return 7


async def test_a_refused_caller_is_denied_before_any_read(project_access):
    use_case = ListSecurityBriefsUseCase(project_access=project_access, briefs=_ExplodingBriefs())

    with pytest.raises(SecurityBriefAccessDenied):
        await use_case.execute(project_id=PROJECT, user_id=USER)

    assert project_access.calls == [(PROJECT, USER)]


async def test_a_permitted_caller_gets_the_page_and_the_total(project_access):
    project_access.permit(PROJECT, USER)
    briefs = _RecordingBriefs()

    page = await ListSecurityBriefsUseCase(project_access=project_access, briefs=briefs).execute(
        project_id=PROJECT, user_id=USER, limit=2, offset=4
    )

    assert (page.items, page.total, page.limit, page.offset) == (["brief-a", "brief-b"], 7, 2, 4)
    assert briefs.calls == [("list", PROJECT, 2, 4), ("count", PROJECT)]


async def test_the_default_page_is_m4_5s_bound(project_access):
    project_access.permit(PROJECT, USER)
    briefs = _RecordingBriefs()

    await ListSecurityBriefsUseCase(project_access=project_access, briefs=briefs).execute(
        project_id=PROJECT, user_id=USER
    )

    assert briefs.calls[0] == ("list", PROJECT, DEFAULT_PAGE_LIMIT, 0)
    assert DEFAULT_PAGE_LIMIT == 50
