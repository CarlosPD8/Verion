"""`GetBriefGenerationUseCase` against in-memory fakes. M8.6, ADR-0038 decision 8.

**Two conditions, and this file exists for the second.** `may_read_project` is the shape every
read route in this project has; the **actor match** is new, and it is the load-bearing half of
decision 6's argument that `ExplainableRiskAccessDenied` needs no `failure_kind` of its own.

**Three refusals here, and the use case's docstring names five.** The two not covered at this
level — a generation of another project, and an absent project — are one query result to this
code, because the repository scopes by project; they are asserted where that scoping is real, in
`test_security_brief_routes.py`. What makes "one 404 for every denial" (**G17**) checkable is that
the three below raise one exception type with one of two message templates, neither of which
varies by reason.
"""

from datetime import UTC, datetime

import pytest

from verion.modules.brief.application.get_brief_generation import GetBriefGenerationUseCase
from verion.modules.brief.domain.brief_generation import BriefGeneration, BriefGenerationStatus
from verion.modules.brief.domain.exceptions import BriefGenerationAccessDenied

_AT = datetime(2026, 1, 1, tzinfo=UTC)


def _generation(*, user_id: str = "u-1") -> BriefGeneration:
    return BriefGeneration(
        id="gen-1",
        project_id="p-1",
        user_id=user_id,
        finding_ids=("f-1",),
        status=BriefGenerationStatus.PENDING,
        brief_id=None,
        failure_kind=None,
        requested_at=_AT,
    )


class _Generations:
    def __init__(self, row: BriefGeneration | None):
        self._row = row
        self.asked: list[tuple[str, str]] = []

    async def get(self, *, project_id, generation_id):
        self.asked.append((project_id, generation_id))
        if self._row is None or self._row.id != generation_id:
            return None
        # The real repository scopes by project, so a generation of another project is None
        # here and indistinguishable from an absent id.
        return self._row if self._row.project_id == project_id else None


class _Access:
    def __init__(self, *, allowed: bool):
        self._allowed = allowed

    async def may_read_project(self, *, project_id, user_id):
        return self._allowed


async def test_the_requester_reads_their_own_generation():
    row = _generation()

    result = await GetBriefGenerationUseCase(
        project_access=_Access(allowed=True), generations=_Generations(row)
    ).execute(project_id="p-1", user_id="u-1", generation_id="gen-1")

    assert result is row


async def test_a_member_who_did_not_request_it_is_refused():
    """**The actor match.** `may_read_project` says yes — this caller is a member of the same
    project — and the generation is still not theirs.

    Killed by removing the `user_id` comparison, which is otherwise invisible: every other
    assertion in the suite passes with a poll that authorizes on the project alone.
    """
    generations = _Generations(_generation(user_id="somebody-else"))

    with pytest.raises(BriefGenerationAccessDenied) as raised:
        await GetBriefGenerationUseCase(
            project_access=_Access(allowed=True), generations=generations
        ).execute(project_id="p-1", user_id="u-1", generation_id="gen-1")

    assert str(raised.value) == "No brief generation with id 'gen-1' in project 'p-1'"


async def test_an_absent_generation_is_refused_with_the_same_sentence():
    """The generation-level refusals share one message template, so a member cannot learn that a
    generation exists by being refused a different one (**G17**)."""
    with pytest.raises(BriefGenerationAccessDenied) as raised:
        await GetBriefGenerationUseCase(
            project_access=_Access(allowed=True), generations=_Generations(None)
        ).execute(project_id="p-1", user_id="u-1", generation_id="gen-1")

    assert str(raised.value) == "No brief generation with id 'gen-1' in project 'p-1'"


async def test_a_caller_who_may_not_read_the_project_is_refused_before_the_read():
    """**It authorizes on its own and inherits nothing from the POST**, which may have been
    answered long before — a poll trusting that verdict would serve a revoked caller.

    Refused before the repository is touched, so a denied caller learns nothing from what the
    read does. `_Generations.asked` is what pins that.
    """
    generations = _Generations(_generation())

    with pytest.raises(BriefGenerationAccessDenied) as raised:
        await GetBriefGenerationUseCase(
            project_access=_Access(allowed=False), generations=generations
        ).execute(project_id="p-1", user_id="u-1", generation_id="gen-1")

    assert generations.asked == []
    assert str(raised.value) == "No readable project with id 'p-1'"
