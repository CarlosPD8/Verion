"""`PostgresSecurityBriefRepository` against real Postgres, built by the real migration. ADR-0033.

Whole-object round trips on a frozen dataclass, so a column mapped wrong, a signal field
dropped from the JSONB, or a timezone lost fails on the one assertion that covers them all.
"""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from verion.modules.brief.adapters.outbound.db.repository import PostgresSecurityBriefRepository
from verion.modules.brief.domain.exceptions import StoredBriefUnreadable
from verion.modules.brief.domain.explanation import Explanation
from verion.modules.brief.domain.security_brief import SecurityBrief
from verion.modules.risk_engine.application.explainable_decision import explainable_decision
from verion.modules.risk_engine.domain.scoring import SurfaceMember, score_surface
from verion.shared_kernel.scanner_tools import ScannerTool
from verion.shared_kernel.severity import Severity

_PROJECT = "project-1"
_OTHER_PROJECT = "project-2"
_AT = datetime(2026, 1, 1, tzinfo=UTC)


def _brief(
    *,
    brief_id: str,
    project_id: str = _PROJECT,
    finding_ids: tuple[str, ...] = ("f-1", "f-2"),
    generated_at: datetime = _AT,
) -> SecurityBrief:
    surface = score_surface(
        project_id=project_id,
        package=None,
        url="/calculate",
        members=[
            SurfaceMember(finding_id="f-1", source=ScannerTool.SEMGREP, severity=Severity.HIGH),
            SurfaceMember(finding_id="f-2", source=ScannerTool.ZAP, severity=Severity.LOW),
        ],
    )
    return SecurityBrief(
        id=brief_id,
        project_id=project_id,
        finding_ids=finding_ids,
        decision=explainable_decision(surface),
        explanation=Explanation(
            text=f"narrative {brief_id}", model="gpt-5-mini-2025-08-07", prompt_version="m7.1-1"
        ),
        generated_at=generated_at,
    )


async def _add(db_session, *briefs: SecurityBrief) -> None:
    repository = PostgresSecurityBriefRepository(db_session)
    for brief in briefs:
        await repository.add(brief)
    await db_session.commit()


async def test_a_brief_round_trips_whole(db_session):
    brief = _brief(brief_id="b-1")
    await _add(db_session, brief)

    stored = await PostgresSecurityBriefRepository(db_session).list_for_project(
        project_id=_PROJECT, limit=50, offset=0
    )

    assert stored == [brief]


async def test_the_list_is_newest_first_and_paged(db_session):
    briefs = [_brief(brief_id=f"b-{n}", generated_at=_AT + timedelta(minutes=n)) for n in range(3)]
    await _add(db_session, *briefs)
    repository = PostgresSecurityBriefRepository(db_session)

    first_page = await repository.list_for_project(project_id=_PROJECT, limit=2, offset=0)
    second_page = await repository.list_for_project(project_id=_PROJECT, limit=2, offset=2)

    assert [b.id for b in first_page] == ["b-2", "b-1"]
    assert [b.id for b in second_page] == ["b-0"]
    assert await repository.count_for_project(_PROJECT) == 3


async def test_equal_timestamps_order_by_id_ascending(db_session):
    """The tie-break is pinned here, with ids the test chooses, so no route test relies on it."""
    await _add(db_session, _brief(brief_id="b-zzz"), _brief(brief_id="b-aaa"))

    stored = await PostgresSecurityBriefRepository(db_session).list_for_project(
        project_id=_PROJECT, limit=50, offset=0
    )

    assert [b.id for b in stored] == ["b-aaa", "b-zzz"]


async def test_another_projects_briefs_are_neither_listed_nor_counted(db_session):
    await _add(
        db_session,
        _brief(brief_id="b-mine"),
        _brief(brief_id="b-theirs", project_id=_OTHER_PROJECT),
    )
    repository = PostgresSecurityBriefRepository(db_session)

    stored = await repository.list_for_project(project_id=_PROJECT, limit=50, offset=0)

    assert [b.id for b in stored] == ["b-mine"]
    assert await repository.count_for_project(_PROJECT) == 1


async def test_a_brief_with_no_members_is_refused_by_the_database(db_session):
    """`ck_security_briefs_finding_ids_not_empty`: a Brief that links back to nothing (FR-9)."""
    with pytest.raises(IntegrityError, match="ck_security_briefs_finding_ids_not_empty"):
        await PostgresSecurityBriefRepository(db_session).add(
            _brief(brief_id="b-0", finding_ids=())
        )
    await db_session.rollback()


async def test_an_unreadable_stored_decision_fails_the_read_rather_than_being_skipped(db_session):
    await _add(db_session, _brief(brief_id="b-good"))
    await db_session.execute(
        text(
            "INSERT INTO security_briefs (id, project_id, finding_ids, decision, why_it_matters,"
            " model, prompt_version, generated_at) VALUES ('b-bad', :project, ARRAY['f-9'],"
            " CAST(:decision AS JSONB), 'x', 'm', 'v', :at)"
        ),
        {"project": _PROJECT, "decision": '{"version": 2, "decision": {}}', "at": _AT},
    )
    await db_session.commit()

    with pytest.raises(StoredBriefUnreadable):
        await PostgresSecurityBriefRepository(db_session).list_for_project(
            project_id=_PROJECT, limit=50, offset=0
        )
