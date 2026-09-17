from dataclasses import fields
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from verion.modules.brief.adapters.outbound.db.models import SecurityBriefModel
from verion.modules.brief.domain.exceptions import StoredBriefUnreadable
from verion.modules.brief.domain.explanation import Explanation
from verion.modules.brief.domain.security_brief import SecurityBrief
from verion.modules.risk_engine.ports.explainable_decision import (
    ExplainableDecision,
    ExplainableSignal,
)

# The stored `decision` value's shape version. Bump it, and keep a reader for every older
# version or migrate the rows, whenever `ExplainableDecision` or `ExplainableSignal` changes
# its fields. `test_security_brief_decision_json.py` fails until someone does.
_DECISION_VERSION = 1


# **Every key below is DERIVED from `dataclasses.fields`, and that is load-bearing** (ADR-0033
# Consequences). A field the carrier gains is written without anyone editing this file, so a
# stored row can never silently narrow what the narrator was shown. The pinned v1 test compares
# a literal enumeration against this same derivation, which is what turns a carrier change into
# a failure. Rewriting these functions field by field, or pinning that test against their own
# output, makes carrier evolution silent again.
def _signal_to_json(signal: ExplainableSignal) -> dict[str, Any]:
    body: dict[str, Any] = {}
    for field in fields(ExplainableSignal):
        value = getattr(signal, field.name)
        body[field.name] = list(value) if isinstance(value, tuple) else value
    return body


def _decision_to_json(decision: ExplainableDecision) -> dict[str, Any]:
    body: dict[str, Any] = {}
    for field in fields(ExplainableDecision):
        value = getattr(decision, field.name)
        body[field.name] = _signal_to_json(value) if isinstance(value, ExplainableSignal) else value
    return {"version": _DECISION_VERSION, "decision": body}


def _leaf(value: Any, annotation: Any) -> Any:
    """One stored leaf, checked against the carrier field's own annotation.

    Every annotation v1's carrier uses has a check here. A `bool` is refused where an `int` is
    declared, because `True == 1` would otherwise read a malformed row as valid. An annotation
    with no check here is refused rather than trusted: it can only appear after a carrier
    change, which the pinned v1 test already fails on.
    """
    if annotation is str and isinstance(value, str):
        return value
    if annotation is int and type(value) is int:
        return value
    if annotation == (str | None) and (value is None or isinstance(value, str)):
        return value
    if (
        annotation == tuple[str, ...]
        and isinstance(value, list)
        and all(isinstance(item, str) for item in value)
    ):
        return tuple(value)
    raise TypeError("stored value does not match the carrier field")


def _signal_from_json(body: Any) -> ExplainableSignal:
    if not isinstance(body, dict):
        raise TypeError("stored signal is not an object")
    values: dict[str, Any] = {
        field.name: _leaf(body[field.name], field.type) for field in fields(ExplainableSignal)
    }
    return ExplainableSignal(**values)


def _decision_from_json(stored: Any) -> ExplainableDecision:
    version = stored.get("version") if isinstance(stored, dict) else None
    # `type(...) is int`, not `==`: `True` and `1.0` both compare equal to 1.
    if type(version) is not int or version != _DECISION_VERSION:
        # A version number at most, never stored content, in the message.
        shown = version if type(version) is int else "missing or unrecognized"
        raise StoredBriefUnreadable(f"Stored Brief decision has unreadable version: {shown}")
    try:
        body = stored["decision"]
        if not isinstance(body, dict):
            raise TypeError("stored decision is not an object")
        values: dict[str, Any] = {
            field.name: _signal_from_json(body[field.name])
            if field.type is ExplainableSignal
            else _leaf(body[field.name], field.type)
            for field in fields(ExplainableDecision)
        }
        return ExplainableDecision(**values)
    except (KeyError, TypeError):
        # A field the v1 reader expects is missing, or the value is not the shape v1 wrote:
        # exactly what a carrier change without a version bump produces on an old row.
        raise StoredBriefUnreadable(
            f"Stored Brief decision does not match version {_DECISION_VERSION}"
        ) from None


def _to_domain(model: SecurityBriefModel) -> SecurityBrief:
    return SecurityBrief(
        id=model.id,
        project_id=model.project_id,
        finding_ids=tuple(model.finding_ids),
        decision=_decision_from_json(model.decision),
        explanation=Explanation(
            text=model.why_it_matters, model=model.model, prompt_version=model.prompt_version
        ),
        generated_at=model.generated_at,
    )


class PostgresSecurityBriefRepository:
    """`SecurityBriefRepositoryPort` over Postgres. Flushes, never commits: the request's
    session does (`platform/db.py`)."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, brief: SecurityBrief) -> None:
        self._session.add(
            SecurityBriefModel(
                id=brief.id,
                project_id=brief.project_id,
                finding_ids=list(brief.finding_ids),
                decision=_decision_to_json(brief.decision),
                why_it_matters=brief.explanation.text,
                model=brief.explanation.model,
                prompt_version=brief.explanation.prompt_version,
                generated_at=brief.generated_at,
            )
        )
        await self._session.flush()

    async def list_for_project(
        self, *, project_id: str, limit: int, offset: int
    ) -> list[SecurityBrief]:
        result = await self._session.execute(
            select(SecurityBriefModel)
            .where(SecurityBriefModel.project_id == project_id)
            # `id` after `generated_at` makes the order total, so two Briefs with one timestamp
            # cannot swap places between pages.
            .order_by(SecurityBriefModel.generated_at.desc(), SecurityBriefModel.id.asc())
            .limit(limit)
            .offset(offset)
        )
        return [_to_domain(model) for model in result.scalars()]

    async def count_for_project(self, project_id: str) -> int:
        result = await self._session.execute(
            select(func.count())
            .select_from(SecurityBriefModel)
            .where(SecurityBriefModel.project_id == project_id)
        )
        return result.scalar_one()
