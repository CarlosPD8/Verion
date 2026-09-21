from dataclasses import fields
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from verion.modules.brief.adapters.outbound.db.models import (
    BriefGenerationModel,
    SecurityBriefModel,
)
from verion.modules.brief.domain.brief_generation import (
    BriefGeneration,
    BriefGenerationFailureKind,
    BriefGenerationStatus,
)
from verion.modules.brief.domain.exceptions import StoredBriefUnreadable
from verion.modules.brief.domain.explanation import Explanation
from verion.modules.brief.domain.security_brief import SecurityBrief
from verion.modules.risk_engine.ports.explainable_decision import (
    ExplainableDecision,
    ExplainableSignal,
)
from verion.shared_kernel.confidence import Confidence

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


def _what_happened(model: SecurityBriefModel) -> Explanation | None:
    """The second narration, or `None` for a Brief written before M7.3.

    `ck_security_briefs_what_happened_all_or_none` makes a partial row impossible, so testing
    all three is a type narrowing, not a policy.
    """
    if (
        model.what_happened is None
        or model.what_happened_model is None
        or model.what_happened_prompt_version is None
    ):
        return None
    return Explanation(
        text=model.what_happened,
        model=model.what_happened_model,
        prompt_version=model.what_happened_prompt_version,
    )


def _to_domain(model: SecurityBriefModel) -> SecurityBrief:
    return SecurityBrief(
        id=model.id,
        project_id=model.project_id,
        finding_ids=tuple(model.finding_ids),
        decision=_decision_from_json(model.decision),
        explanation=Explanation(
            text=model.why_it_matters, model=model.model, prompt_version=model.prompt_version
        ),
        what_happened=_what_happened(model),
        # **Reconstructed, never the raw column.** ADR-0018 decision 2's asymmetry note: a
        # value crossing a persistence boundary must be rebuilt as its enum before anything
        # compares it, because `Confidence.INFERRED == "inferred"` is True while an ordering
        # or an `is` comparison against a bare str is not. An unrecognised stored value
        # raises `ValueError` here rather than flowing on as a str, which is the loud
        # failure `Severity`'s note prefers.
        confidence=None if model.confidence is None else Confidence(model.confidence),
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
                what_happened=brief.what_happened.text if brief.what_happened else None,
                what_happened_model=brief.what_happened.model if brief.what_happened else None,
                what_happened_prompt_version=(
                    brief.what_happened.prompt_version if brief.what_happened else None
                ),
                confidence=None if brief.confidence is None else str(brief.confidence),
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


def _generation_to_domain(model: BriefGenerationModel) -> BriefGeneration:
    return BriefGeneration(
        id=model.id,
        project_id=model.project_id,
        user_id=model.user_id,
        finding_ids=tuple(model.finding_ids),
        # Reconstructed as the enum, never the raw column, for `_to_domain`'s `confidence`
        # reason (ADR-0018 decision 2's asymmetry). An unrecognised stored value raises
        # `ValueError` here rather than flowing on as a str.
        status=BriefGenerationStatus(model.status),
        brief_id=model.brief_id,
        failure_kind=(
            None if model.failure_kind is None else BriefGenerationFailureKind(model.failure_kind)
        ),
        requested_at=model.requested_at,
    )


class PostgresBriefGenerationRepository:
    """`BriefGenerationRepositoryPort` over Postgres. M8.6, ADR-0038.

    **Flushes, never commits**, like its sibling above — with one consequence worth naming: the
    worker calls `claim` inside a session it commits immediately and alone, because the claim
    must be durable before the work starts (`normalize_scan`'s split, for its reason).
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, generation: BriefGeneration) -> None:
        self._session.add(
            BriefGenerationModel(
                id=generation.id,
                project_id=generation.project_id,
                user_id=generation.user_id,
                finding_ids=list(generation.finding_ids),
                status=str(generation.status),
                brief_id=generation.brief_id,
                failure_kind=(
                    None if generation.failure_kind is None else str(generation.failure_kind)
                ),
                requested_at=generation.requested_at,
            )
        )
        await self._session.flush()

    async def claim(self, generation_id: str) -> BriefGeneration | None:
        # **Conditional on `pending`, which is what makes a redelivered job a no-op.** One
        # statement, so two workers racing cannot both win: Postgres serialises the row lock and
        # the loser's WHERE no longer matches. `returning` avoids a second SELECT that could read
        # a row another transaction has since moved.
        result = await self._session.execute(
            update(BriefGenerationModel)
            .where(
                BriefGenerationModel.id == generation_id,
                BriefGenerationModel.status == str(BriefGenerationStatus.PENDING),
            )
            .values(status=str(BriefGenerationStatus.RUNNING))
            .returning(BriefGenerationModel)
        )
        model = result.scalar_one_or_none()
        return None if model is None else _generation_to_domain(model)

    async def succeed(self, *, generation_id: str, brief_id: str) -> None:
        await self._session.execute(
            update(BriefGenerationModel)
            .where(BriefGenerationModel.id == generation_id)
            .values(status=str(BriefGenerationStatus.SUCCEEDED), brief_id=brief_id)
        )
        await self._session.flush()

    async def fail(self, *, generation_id: str, failure_kind: BriefGenerationFailureKind) -> None:
        await self._session.execute(
            update(BriefGenerationModel)
            .where(BriefGenerationModel.id == generation_id)
            .values(status=str(BriefGenerationStatus.FAILED), failure_kind=str(failure_kind))
        )
        await self._session.flush()

    async def get(self, *, project_id: str, generation_id: str) -> BriefGeneration | None:
        # Scoped to the project in the caller's own path, so a generation of another project is
        # `None` here and indistinguishable from an absent id at the route (**G17**).
        result = await self._session.execute(
            select(BriefGenerationModel).where(
                BriefGenerationModel.id == generation_id,
                BriefGenerationModel.project_id == project_id,
            )
        )
        model = result.scalar_one_or_none()
        return None if model is None else _generation_to_domain(model)
