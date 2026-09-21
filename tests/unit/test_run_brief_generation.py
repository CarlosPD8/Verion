"""`RunBriefGenerationUseCase` against in-memory fakes. M8.6, ADR-0038 decision 6.

**The exception-to-`failure_kind` mapping, every branch, in one place.** Five terminal failures
onto three kinds, and the integration file reaches them three different ways: `NoCurrentRisk` with
real data, the two provider failures by handing a substitute provider in `ctx`, and
`ExplainableRiskInconsistent` and `BriefMemberMissing` only by **monkeypatching a worker symbol** —
because neither can be produced by any real read (**G11**). Two of the five, not three. So the
total check belongs here, where all six raises (the five plus `ExplainableRiskAccessDenied`) are
one parametrized table.

It also pins the two properties the mapping's argument rests on:

- **`ExplainableRiskAccessDenied` maps to `surface_changed` and never to a kind of its own**, so
  no response body names a denial (**G17**).
- **Nothing else is caught.** An unnamed exception propagates rather than becoming a terminal row
  claiming a classification this code did not make.
"""

from datetime import UTC, datetime

import pytest

from verion.modules.brief.application.run_brief_generation import RunBriefGenerationUseCase
from verion.modules.brief.domain.brief_generation import (
    BriefGeneration,
    BriefGenerationFailureKind,
    BriefGenerationStatus,
)
from verion.modules.brief.domain.exceptions import (
    BriefMemberMissing,
    ExplanationUnavailable,
    WhatHappenedRejected,
)
from verion.modules.risk_engine.ports.explainable_risk import (
    ExplainableRiskAccessDenied,
    ExplainableRiskInconsistent,
    NoCurrentRisk,
)

_AT = datetime(2026, 1, 1, tzinfo=UTC)
_CLAIMED = BriefGeneration(
    id="gen-1",
    project_id="p-1",
    user_id="u-1",
    finding_ids=("f-1",),
    status=BriefGenerationStatus.RUNNING,
    brief_id=None,
    failure_kind=None,
    requested_at=_AT,
)


class _Generations:
    def __init__(self):
        self.terminal: tuple[str, object] | None = None

    async def succeed(self, *, generation_id, brief_id):
        assert self.terminal is None, "a generation reaches a terminal state exactly once"
        self.terminal = ("succeeded", brief_id)

    async def fail(self, *, generation_id, failure_kind):
        assert self.terminal is None, "a generation reaches a terminal state exactly once"
        self.terminal = ("failed", failure_kind)

    async def claim(self, generation_id):  # pragma: no cover
        raise AssertionError("the claim is worker.py's, and a second one is a silent no-op")


class _Brief:
    id = "brief-1"


class _Generate:
    """Stands in for `GenerateSecurityBriefUseCase`, recording what it was asked."""

    def __init__(self, raises: Exception | None = None):
        self._raises = raises
        self.calls: list[dict] = []

    async def execute(self, *, project_id, user_id, finding_ids):
        self.calls.append(
            {"project_id": project_id, "user_id": user_id, "finding_ids": finding_ids}
        )
        if self._raises is not None:
            raise self._raises
        return _Brief()


async def test_a_successful_narration_records_the_brief_it_stored():
    generations = _Generations()
    generate = _Generate()

    await RunBriefGenerationUseCase(generations=generations, generate=generate).execute(_CLAIMED)

    assert generations.terminal == ("succeeded", "brief-1")


async def test_the_job_narrates_with_the_STORED_user_id():
    """**The second authorization gate** (ADR-0038 decision 4), and the whole of what the job
    contributes to it.

    There is ONE verdict in the chain — `CorrelateFindingsUseCase`'s `may_read_project`, reached
    through `ScoredExplainableRisks` and `ComputeRiskUseCase` — so what decides whether it
    catches a revoked membership is which `user_id` arrives. Passing any other id asks a
    question nobody asked and answers it for the wrong person.

    The integration kill for this is
    `test_security_brief_routes.py::test_a_membership_revoked_between_enqueue_and_run_fails_the_generation`;
    this is the same claim at the seam where the value is chosen.
    """
    generate = _Generate()

    await RunBriefGenerationUseCase(generations=_Generations(), generate=generate).execute(_CLAIMED)

    assert generate.calls == [{"project_id": "p-1", "user_id": "u-1", "finding_ids": ("f-1",)}]


@pytest.mark.parametrize(
    ("raised", "expected"),
    [
        (NoCurrentRisk("gone"), BriefGenerationFailureKind.SURFACE_CHANGED),
        (
            ExplainableRiskAccessDenied("no readable project"),
            BriefGenerationFailureKind.SURFACE_CHANGED,
        ),
        (
            ExplanationUnavailable("provider said no"),
            BriefGenerationFailureKind.PROVIDER_UNAVAILABLE,
        ),
        (
            WhatHappenedRejected("names a bucket no member supplied"),
            BriefGenerationFailureKind.PROVIDER_UNAVAILABLE,
        ),
        (
            ExplainableRiskInconsistent("two reads disagreed"),
            BriefGenerationFailureKind.INTERNAL_ERROR,
        ),
        (BriefMemberMissing("could not read back"), BriefGenerationFailureKind.INTERNAL_ERROR),
    ],
    ids=[
        "no-current-risk",
        "access-denied",
        "explanation-unavailable",
        "what-happened-rejected",
        "inconsistent",
        "member-missing",
    ],
)
async def test_every_named_failure_maps_to_its_client_action(raised, expected):
    """Six raises, three kinds. `WhatHappenedRejected` is `ExplanationUnavailable`'s subclass and
    lands on the same kind deliberately: to a client the two are one outcome."""
    generations = _Generations()

    await RunBriefGenerationUseCase(
        generations=generations, generate=_Generate(raises=raised)
    ).execute(_CLAIMED)

    assert generations.terminal == ("failed", expected)


async def test_an_unnamed_exception_propagates_and_writes_no_terminal_state():
    """**G87 and ADR-0038 decision 11's cost, as a property of this class.**

    A blanket `except Exception` here would write a terminal row for a failure nobody
    classified, which is worse than a stranded `running` row: it would tell a client one of
    three definite things about a failure this code does not understand.
    """
    generations = _Generations()

    with pytest.raises(RuntimeError):
        await RunBriefGenerationUseCase(
            generations=generations, generate=_Generate(raises=RuntimeError("unnamed"))
        ).execute(_CLAIMED)

    assert generations.terminal is None
