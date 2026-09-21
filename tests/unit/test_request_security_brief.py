"""`RequestSecurityBriefUseCase` against in-memory fakes. M8.6, ADR-0038.

The route-side half of generation: authorize, mint, write, ask for the job. What an integration
test cannot see from here is the ORDER — the row must be added before the enqueue is asked for,
and a fake that records both is the only way to assert it, because in production the enqueue is
deferred past a commit and both look simultaneous from outside.
"""

from datetime import UTC, datetime

import pytest

from verion.modules.brief.application.request_security_brief import RequestSecurityBriefUseCase
from verion.modules.brief.domain.brief_generation import (
    BriefGeneration,
    BriefGenerationStatus,
)
from verion.modules.brief.domain.exceptions import BriefGenerationAccessDenied

_AT = datetime(2026, 1, 1, tzinfo=UTC)


class _Clock:
    def now(self):
        return _AT


class _Ids:
    def __init__(self):
        self._n = 0

    def new_id(self):
        self._n += 1
        return f"gen-{self._n}"


class _Recorder:
    """One log across the repository and the queue, so ORDER is assertable."""

    def __init__(self):
        self.events: list[str] = []
        self.added: list[BriefGeneration] = []

    async def add(self, generation):
        self.added.append(generation)
        self.events.append(f"add:{generation.id}")

    async def enqueue_brief_generation(self, generation_id):
        self.events.append(f"enqueue:{generation_id}")

    async def claim(self, generation_id):  # pragma: no cover - not this use case's method
        raise AssertionError("claim is the job's, never the route's")

    async def succeed(self, *, generation_id, brief_id):  # pragma: no cover
        raise AssertionError("succeed is the job's, never the route's")

    async def fail(self, *, generation_id, failure_kind):  # pragma: no cover
        raise AssertionError("fail is the job's, never the route's")

    async def get(self, *, project_id, generation_id):  # pragma: no cover
        raise AssertionError("get is the poll's, never the route's")


class _Access:
    def __init__(self, *, allowed: bool):
        self._allowed = allowed
        self.asked: list[tuple[str, str]] = []

    async def may_read_project(self, *, project_id, user_id):
        self.asked.append((project_id, user_id))
        return self._allowed


def _use_case(recorder, access):
    return RequestSecurityBriefUseCase(
        project_access=access,
        generations=recorder,
        queue=recorder,
        clock=_Clock(),
        ids=_Ids(),
    )


async def test_an_accepted_request_writes_a_pending_row_then_asks_for_the_job():
    """**Order is the point.** `add` before `enqueue`, on `TriggerScanUseCase`'s shape, so the
    after-commit wrapper registers its callback against a session that already holds the row."""
    recorder = _Recorder()
    access = _Access(allowed=True)

    generation = await _use_case(recorder, access).execute(
        project_id="p-1", user_id="u-1", finding_ids=("f-1", "f-2")
    )

    assert recorder.events == ["add:gen-1", "enqueue:gen-1"]
    assert generation.status is BriefGenerationStatus.PENDING
    assert generation.brief_id is None
    assert generation.failure_kind is None
    assert generation.requested_at == _AT
    assert recorder.added == [generation]


async def test_the_stored_row_carries_the_requesting_user_and_the_requested_set():
    """`user_id` is what the job re-authorizes with (decision 4), and `finding_ids` is the
    CALLER's set, not the engine's — the engine has not run yet, and the two differing is what
    `surface_changed` reports."""
    recorder = _Recorder()

    generation = await _use_case(recorder, _Access(allowed=True)).execute(
        project_id="p-1", user_id="u-1", finding_ids=("f-2", "f-1")
    )

    assert generation.user_id == "u-1"
    assert generation.project_id == "p-1"
    # Preserved verbatim, order included: nothing here normalizes it, because nothing here
    # resolves it.
    assert generation.finding_ids == ("f-2", "f-1")


async def test_a_caller_who_may_not_read_the_project_is_refused_before_anything_is_written():
    """The first of ADR-0038 decision 4's two gates. **Nothing written and nothing queued** —
    which is the whole reason the route checks at all, given that the job checks again: without
    it, an unauthorized request still spends a job and two billed calls."""
    recorder = _Recorder()
    access = _Access(allowed=False)

    with pytest.raises(BriefGenerationAccessDenied) as raised:
        await _use_case(recorder, access).execute(
            project_id="p-1", user_id="stranger", finding_ids=("f-1",)
        )

    assert recorder.events == []
    assert access.asked == [("p-1", "stranger")]
    # The same sentence `ListSecurityBriefsUseCase` raises, so a refused POST and a refused list
    # are indistinguishable from each other and from an absent project (**G17**).
    assert str(raised.value) == "No readable project with id 'p-1'"


async def test_a_second_request_for_the_same_set_is_a_second_generation():
    """ADR-0033 decision 3, which ADR-0038 decision 11 leans on: a repeat POST is a
    regeneration, never a no-op, and that is what makes "ask again" a real recovery for a
    generation whose enqueue was lost.

    Two rows, two ids, two jobs. **Nothing deduplicates**, which is also **G100**: the request
    now returns before the work, so repeats are cheaper to send than they were, not dearer.
    """
    recorder = _Recorder()
    use_case = _use_case(recorder, _Access(allowed=True))

    first = await use_case.execute(project_id="p-1", user_id="u-1", finding_ids=("f-1",))
    second = await use_case.execute(project_id="p-1", user_id="u-1", finding_ids=("f-1",))

    assert first.id != second.id
    assert recorder.events == ["add:gen-1", "enqueue:gen-1", "add:gen-2", "enqueue:gen-2"]
