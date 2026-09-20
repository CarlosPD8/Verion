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
from verion.shared_kernel.confidence import Confidence
from verion.shared_kernel.scanner_tools import ScannerTool
from verion.shared_kernel.severity import Severity

_PROJECT = "project-1"
_OTHER_PROJECT = "project-2"
_AT = datetime(2026, 1, 1, tzinfo=UTC)
_WHAT_HAPPENED = Explanation(
    text="Semgrep flagged dangerous-eval in app.py at line 28.",
    model="gpt-5-mini-2025-08-07",
    prompt_version="m7.3-1",
)


def _brief(
    *,
    brief_id: str,
    project_id: str = _PROJECT,
    finding_ids: tuple[str, ...] = ("f-1", "f-2"),
    generated_at: datetime = _AT,
    what_happened: Explanation | None = _WHAT_HAPPENED,
) -> SecurityBrief:
    surface = score_surface(
        project_id=project_id,
        package=None,
        url="/calculate",
        members=[
            SurfaceMember(
                finding_id="f-1",
                source=ScannerTool.SEMGREP,
                severity=Severity.HIGH,
                confidence=Confidence.REPORTED,
            ),
            SurfaceMember(
                finding_id="f-2",
                source=ScannerTool.ZAP,
                severity=Severity.LOW,
                confidence=Confidence.REPORTED,
            ),
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
        what_happened=what_happened,
        confidence=surface.confidence,
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


# --- what_happened (M7.3, ADR-0034 decision 3) ---------------------------------------------


async def test_a_brief_without_what_happened_round_trips_as_none(db_session):
    """Only a Brief written before M7.3 has none; the repository must still read it whole."""
    brief = _brief(brief_id="b-legacy", what_happened=None)
    await _add(db_session, brief)

    stored = await PostgresSecurityBriefRepository(db_session).list_for_project(
        project_id=_PROJECT, limit=50, offset=0
    )

    assert stored == [brief]


async def test_a_row_written_before_the_migration_reads_with_no_what_happened(db_session):
    """The M7.2 insert shape, naming no new column, as rows existing at the migration look."""
    await _add(db_session, _brief(brief_id="b-good"))
    await db_session.execute(
        text(
            "INSERT INTO security_briefs (id, project_id, finding_ids, decision, why_it_matters,"
            " model, prompt_version, generated_at) SELECT 'b-old', project_id, finding_ids,"
            " decision, 'old', 'm', 'm7.1-1', generated_at - interval '1 minute'"
            " FROM security_briefs WHERE id = 'b-good'"
        )
    )
    await db_session.commit()

    stored = await PostgresSecurityBriefRepository(db_session).list_for_project(
        project_id=_PROJECT, limit=50, offset=0
    )

    assert [b.id for b in stored] == ["b-good", "b-old"]
    assert stored[1].what_happened is None
    assert stored[1].explanation.text == "old"


@pytest.mark.parametrize(
    "columns",
    [
        "what_happened = 'text only'",
        "what_happened_model = 'm'",
        "what_happened = 'text', what_happened_model = 'm'",
        "what_happened_prompt_version = 'v'",
    ],
)
async def test_a_partial_what_happened_is_refused_by_the_database(db_session, columns):
    """`ck_security_briefs_what_happened_all_or_none`: a narration without its producer, or the
    reverse, is not a state a Brief can be in."""
    await _add(db_session, _brief(brief_id="b-1", what_happened=None))

    with pytest.raises(IntegrityError, match="ck_security_briefs_what_happened_all_or_none"):
        await db_session.execute(text(f"UPDATE security_briefs SET {columns} WHERE id = 'b-1'"))
    await db_session.rollback()


# ---------------------------------------------------------------------------
# M8.5, ADR-0037 decision 8 — the confidence column
# ---------------------------------------------------------------------------


async def test_a_row_written_before_m8_5_reads_back_with_no_confidence(db_session):
    """The M7.3 insert shape, naming no `confidence`, as rows existing at the migration look.

    `NULL` has exactly one meaning — written before M8.5 — because the migration adds the
    column nullable and does not backfill. There is nothing to backfill FROM: the surface a
    stored Brief describes may have moved since it was narrated, so a value invented now would
    describe a grouping that never produced this Brief.
    """
    await _add(db_session, _brief(brief_id="b-good"))
    await db_session.execute(
        text(
            "INSERT INTO security_briefs (id, project_id, finding_ids, decision, why_it_matters,"
            " model, prompt_version, generated_at) SELECT 'b-old', project_id, finding_ids,"
            " decision, 'old', 'm', 'm7.1-1', generated_at - interval '1 minute'"
            " FROM security_briefs WHERE id = 'b-good'"
        )
    )
    await db_session.commit()

    stored = await PostgresSecurityBriefRepository(db_session).list_for_project(
        project_id=_PROJECT, limit=50, offset=0
    )

    assert [b.id for b in stored] == ["b-good", "b-old"]
    assert stored[1].confidence is None
    assert stored[0].confidence is not None


async def test_a_stored_confidence_reads_back_as_the_enum_and_not_a_string(db_session):
    """ADR-0018 decision 2's persistence asymmetry, honoured rather than rediscovered.

    That decision records it for `Severity`: *"a severity crossing a persistence or HTTP
    boundary must be reconstructed as `Severity(...)` before it is compared."* The trap is that
    `Confidence.REPORTED == "reported"` is `True`, so a repository returning the raw column
    passes every equality assertion and fails only where identity or membership is used —
    which is what `_confidence`'s fold and `scoring.py` do.

    Asserted with `is`, deliberately: `==` would pass against the bare string.
    """
    await _add(db_session, _brief(brief_id="b-1"))

    [stored] = await PostgresSecurityBriefRepository(db_session).list_for_project(
        project_id=_PROJECT, limit=50, offset=0
    )

    assert stored.confidence is Confidence.REPORTED


async def test_an_unrecognised_stored_confidence_raises_rather_than_flowing_on_as_a_string(
    db_session,
):
    """A value the vocabulary does not contain is a broken row, and it fails loudly.

    The alternative — passing the raw string through — would put a word the API never
    advertises into a response, and `CONFIDENCE_DEFINITION` would not define it. This is the
    same preference `Severity`'s note states: loud beats silent, and the column is a plain
    `String` precisely so adding a legitimate value needs no type migration.
    """
    await _add(db_session, _brief(brief_id="b-1"))
    await db_session.execute(
        text("UPDATE security_briefs SET confidence = 'somewhat' WHERE id = 'b-1'")
    )
    await db_session.commit()

    with pytest.raises(ValueError, match="somewhat"):
        await PostgresSecurityBriefRepository(db_session).list_for_project(
            project_id=_PROJECT, limit=50, offset=0
        )
