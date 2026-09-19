"""`ListRiskDismissalsUseCase` over in-memory ports. ADR-0036 decisions 10 and 12."""

from datetime import UTC, datetime, timedelta

import pytest

from verion.modules.history.application.list_risk_dismissals import ListRiskDismissalsUseCase
from verion.modules.history.domain.exceptions import RiskDismissalAccessDenied
from verion.modules.history.domain.risk import Risk, RiskEvent, RiskEventKind

_PROJECT = "project-1"
_MEMBER = "user-member"
_AT = datetime(2026, 1, 1, tzinfo=UTC)


async def _dismiss(repository, risk_id: str, at: datetime) -> None:
    await repository.add(
        Risk(id=risk_id, project_id=_PROJECT, finding_ids=(f"f-{risk_id}",)),
        RiskEvent(
            id=f"{risk_id}-event",
            risk_id=risk_id,
            ordinal=1,
            kind=RiskEventKind.DISMISSED,
            actor_user_id=_MEMBER,
            reason="accepted",
            occurred_at=at,
        ),
    )


async def test_a_denied_caller_is_refused_before_any_read(project_access):
    class _Exploding:
        def __getattr__(self, name):
            raise AssertionError(f"repository touched: {name}")

    with pytest.raises(RiskDismissalAccessDenied):
        await ListRiskDismissalsUseCase(
            project_access=project_access, dismissals=_Exploding()
        ).execute(project_id=_PROJECT, user_id=_MEMBER)


async def test_a_page_is_newest_dismissal_first_with_an_exact_total(
    project_access, risk_dismissal_repository_factory
):
    project_access.permit(_PROJECT, _MEMBER)
    repository = risk_dismissal_repository_factory()
    await _dismiss(repository, "risk-old", _AT)
    await _dismiss(repository, "risk-new", _AT + timedelta(minutes=1))
    await _dismiss(repository, "risk-mid", _AT + timedelta(seconds=30))

    page = await ListRiskDismissalsUseCase(
        project_access=project_access, dismissals=repository
    ).execute(project_id=_PROJECT, user_id=_MEMBER, limit=2, offset=0)

    assert [item.risk.id for item in page.items] == ["risk-new", "risk-mid"]
    assert (page.total, page.limit, page.offset) == (3, 2, 0)
