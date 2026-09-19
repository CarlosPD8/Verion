from datetime import datetime

from sqlalchemy import (
    ARRAY,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from verion.modules.history.domain.risk import MAX_REASON_CHARS
from verion.platform.db import Base

# **G37's partition, as data** (ADR-0036 decision 8, on ADR-0020 decision 4's layer 1).
# `risks` holds identity columns only. Its protected and refreshed sets are empty, and that
# is the point: user state lives in `risk_events`, where no projection writer can name it.
# `test_postgres_risk_dismissal_repository.py` asserts these three are disjoint and cover
# `RiskModel`'s columns exactly, so a column added to `risks` fails until it is classified.
RISK_IDENTITY_COLUMNS = frozenset({"id", "project_id", "finding_ids"})
RISK_PROTECTED_COLUMNS: frozenset[str] = frozenset()
RISK_REFRESHED_COLUMNS: frozenset[str] = frozenset()


class RiskModel(Base):
    """A dismissal record: a snapshot of one surface's members. M8.1, ADR-0036 decision 1.

    Written once, by a dismissal, and never updated. No foreign key on `project_id`
    (cross-module) or on `finding_ids` (cross-module, and an ARRAY cannot carry one): **G11**.
    """

    __tablename__ = "risks"
    __table_args__ = (
        # A snapshot with no members would dismiss nothing and link back to nothing (FR-9).
        CheckConstraint("cardinality(finding_ids) >= 1", name="ck_risks_finding_ids_not_empty"),
        # Shipped with its queries: every read is project-scoped.
        Index("ix_risks_project_id", "project_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(36), nullable=False)
    finding_ids: Mapped[list[str]] = mapped_column(ARRAY(String), nullable=False)


class RiskEventModel(Base):
    """One append-only event in a dismissal record's log. ADR-0036 decision 7.

    **No statement updates or deletes a row here.** `ordinal` orders a record's events, and
    `uq_risk_events_risk_id_ordinal` is what makes two concurrent appends collide rather than
    interleave; its index also serves every latest-event read. The reason's invariants are
    enforced here and by `RiskEvent.__post_init__`.
    """

    __tablename__ = "risk_events"
    __table_args__ = (
        UniqueConstraint("risk_id", "ordinal", name="uq_risk_events_risk_id_ordinal"),
        CheckConstraint("ordinal >= 1", name="ck_risk_events_ordinal_positive"),
        CheckConstraint("kind IN ('dismissed', 'undismissed')", name="ck_risk_events_kind"),
        CheckConstraint(
            "kind <> 'dismissed' OR reason IS NOT NULL", name="ck_risk_events_dismissal_has_reason"
        ),
        # `btrim` strips only the characters it is given: `REASON_BLANK_CHARS`, as an E-string.
        CheckConstraint(
            "reason IS NULL OR btrim(reason, E' \\t\\n\\r\\x0B\\f') <> ''",
            name="ck_risk_events_reason_not_blank",
        ),
        CheckConstraint(
            f"reason IS NULL OR char_length(reason) <= {MAX_REASON_CHARS}",
            name="ck_risk_events_reason_length",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    # Within the module, so a foreign key.
    risk_id: Mapped[str] = mapped_column(String(36), ForeignKey("risks.id"), nullable=False)
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    kind: Mapped[str] = mapped_column(String, nullable=False)
    # `identity`'s users, cross-module, so no foreign key (G11).
    actor_user_id: Mapped[str] = mapped_column(String(36), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
