"""`platform/worker.py`'s `generate_brief`, against real Postgres. M8.6, ADR-0038.

`test_worker_run_scan.py`'s sibling, and it exists for the same reason: the job function is
where transaction boundaries and the claim live, and neither is visible from a route test.

**What this file covers that `test_security_brief_routes.py` does not**, because that file always
reaches the job through a POST that has just minted a `pending` row:

- **The claim is conditional**, so a redelivered job is a no-op rather than a second run and a
  second billed pair of calls.
- **A job for a row that does not exist** returns rather than raising, which is what stops a
  stale message failing a worker.
- **An exception `RunBriefGenerationUseCase` does not name propagates**, leaving the row
  `running` with nothing to re-drive it. That is **G87** and ADR-0038 decision 11's stated cost,
  pinned here so it cannot change silently into a swallowed failure.

The provider comes from `ctx`, which is the real wiring (decision 9), not a test seam.
"""

from datetime import UTC, datetime

import pytest
import pytest_asyncio
from sqlalchemy import text

from verion.modules.brief.adapters.outbound.db.repository import (
    PostgresBriefGenerationRepository,
)
from verion.modules.brief.domain.brief_generation import (
    BriefGeneration,
    BriefGenerationStatus,
)
from verion.modules.normalization.adapters.outbound.db.repository import PostgresFindingRepository
from verion.modules.normalization.domain.finding import Evidence, Finding, Location
from verion.modules.projects.adapters.outbound.db.repository import (
    PostgresProjectMembershipRepository,
    PostgresProjectRepository,
)
from verion.modules.projects.domain.project import Project, ProjectMembership, Role
from verion.platform import worker as worker_module
from verion.platform.worker import generate_brief
from verion.shared_kernel.scanner_tools import ScannerTool
from verion.shared_kernel.severity import Severity

_PROJECT = "project-worker-brief"
_OWNER = "user-worker-owner"
_AT = datetime(2026, 1, 1, tzinfo=UTC)


@pytest_asyncio.fixture
async def fake_provider(explanation_provider_factory):
    """The contract-tested fake, handed to the job in `ctx` exactly as `on_startup` does."""
    return explanation_provider_factory()


async def _seed(db_session) -> None:
    await PostgresProjectRepository(db_session).add(
        Project(id=_PROJECT, owner_id=_OWNER, name="Project", created_at=_AT)
    )
    await PostgresProjectMembershipRepository(db_session).add(
        ProjectMembership(project_id=_PROJECT, user_id=_OWNER, role=Role.OWNER)
    )
    await PostgresFindingRepository(db_session).upsert(
        Finding(
            id="f-1",
            project_id=_PROJECT,
            source=ScannerTool.TRIVY,
            rule_id="rule-f-1",
            severity=Severity.HIGH,
            native_severity="HIGH",
            title="title f-1",
            location=Location(
                file_path="requirements.txt", package="urllib3", installed_version="1.0"
            ),
            evidence=Evidence(
                id="evidence-f-1",
                finding_id="f-1",
                scan_id="scan-1",
                raw_payload="{}",
                source_tool=ScannerTool.TRIVY,
                captured_at=_AT,
            ),
        )
    )
    await db_session.commit()


async def _add_generation(db_session, generation_id: str) -> None:
    await PostgresBriefGenerationRepository(db_session).add(
        BriefGeneration(
            id=generation_id,
            project_id=_PROJECT,
            user_id=_OWNER,
            finding_ids=("f-1",),
            status=BriefGenerationStatus.PENDING,
            brief_id=None,
            failure_kind=None,
            requested_at=_AT,
        )
    )
    await db_session.commit()


async def _row(db_session, generation_id: str):
    return (
        (
            await db_session.execute(
                text("SELECT status, brief_id, failure_kind FROM brief_generations WHERE id = :i"),
                {"i": generation_id},
            )
        )
        .mappings()
        .one()
    )


async def test_a_job_for_a_generation_that_does_not_exist_returns(fake_provider):
    """No row, no raise. A message for a row that was never committed — or was wiped — must not
    fail the worker, because arq would mark the job failed and never retry it for nothing."""
    await generate_brief({"explanations": fake_provider}, "no-such-generation")

    assert fake_provider.calls == []
    assert fake_provider.describe_calls == []


async def test_the_claim_is_conditional_so_a_redelivered_job_runs_once(db_session, fake_provider):
    """**The dedup that matters is the row's, not arq's.**

    arq's in-progress key stops a duplicate enqueue while the first is live; it does not stop a
    message redelivered after the job finished. `claim`'s conditional `pending -> running` does,
    and this is what pins it: the second call must not narrate again, because each narration is
    two billed provider calls and would write a second Brief.
    """
    await _seed(db_session)
    await _add_generation(db_session, "g-redelivered")

    await generate_brief({"explanations": fake_provider}, "g-redelivered")
    first_row = await _row(db_session, "g-redelivered")
    await generate_brief({"explanations": fake_provider}, "g-redelivered")
    second_row = await _row(db_session, "g-redelivered")

    assert first_row["status"] == "succeeded"
    assert dict(second_row) == dict(first_row)
    assert len(fake_provider.calls) == 1
    assert len(fake_provider.describe_calls) == 1
    assert (
        await db_session.execute(
            text("SELECT count(*) FROM security_briefs WHERE project_id = :p"), {"p": _PROJECT}
        )
    ).scalar_one() == 1


async def test_the_brief_id_written_to_the_row_is_the_brief_that_was_stored(
    db_session, fake_provider
):
    """`succeed` and the Brief are one transaction, so a poll that says `succeeded` can never
    point at a row `GET …/briefs` cannot serve."""
    await _seed(db_session)
    await _add_generation(db_session, "g-linked")

    await generate_brief({"explanations": fake_provider}, "g-linked")

    row = await _row(db_session, "g-linked")
    assert row["status"] == "succeeded"
    assert row["failure_kind"] is None
    stored = (
        await db_session.execute(
            text("SELECT id FROM security_briefs WHERE project_id = :p"), {"p": _PROJECT}
        )
    ).scalar_one()
    assert row["brief_id"] == stored


async def test_an_unnamed_exception_propagates_and_leaves_the_row_running(
    db_session, fake_provider, monkeypatch
):
    """**G87, and ADR-0038 decision 11's cost, pinned rather than described.**

    `RunBriefGenerationUseCase` names five exceptions and classifies them. Anything else reaches
    arq, which marks the job failed and — arq 0.28 — does not retry it, leaving the row `running`
    forever because this ADR declines a sweep.

    This test exists so that stops being invisible. If someone later wraps the job in a bare
    `except Exception` and writes a terminal row, this goes red and the register entry that says
    the row is stranded stops being true in the same commit.
    """

    class _Exploding:
        def __init__(self, _compute=None):
            pass

        async def explainable_risk(self, *, project_id, user_id, finding_ids):
            raise RuntimeError("something nobody named")

    await _seed(db_session)
    await _add_generation(db_session, "g-unnamed")
    monkeypatch.setattr(worker_module, "ScoredExplainableRisks", _Exploding)

    with pytest.raises(RuntimeError):
        await generate_brief({"explanations": fake_provider}, "g-unnamed")

    row = await _row(db_session, "g-unnamed")
    assert row["status"] == "running"
    assert row["brief_id"] is None
    assert row["failure_kind"] is None


async def test_the_job_is_registered_with_keep_result_zero():
    """ADR-0038 decision 10, read off `WorkerSettings` rather than from the ADR.

    `keep_result=0` releases arq's RESULT key while leaving the in-progress key alone. It matters
    here for M4.4's measured reason: a result key reserves the job id for an hour after the job
    dies, and a generation's id is also its arq job id.
    """
    registered = {
        getattr(function, "name", getattr(function, "__name__", None)): function
        for function in worker_module.WorkerSettings.functions
    }
    assert "generate_brief" in registered
    # `keep_result_s` is what arq 0.28 stores the `keep_result=` argument as — read off the
    # installed package, because asserting `keep_result` passes `hasattr` nowhere and would
    # have been an `AttributeError` dressed as a check.
    assert registered["generate_brief"].keep_result_s == 0
    # `normalize_scan` is the precedent this decision argues from rather than copies, so it is
    # asserted beside it: both are wrapped in `func(...)` and both release the result key.
    assert registered["normalize_scan"].keep_result_s == 0
    # **The contrast that makes 0 mean something**: `run_scan` is registered as a BARE function,
    # so arq applies its own `keep_result` default of 3600 s and there is no `keep_result_s`
    # attribute at all. That is the hour-long id reservation M4.4 measured, and the reason a
    # generation — whose id is also its arq job id — must not keep one.
    assert not hasattr(registered["run_scan"], "keep_result_s")
