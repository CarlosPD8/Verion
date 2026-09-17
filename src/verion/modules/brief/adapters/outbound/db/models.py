from datetime import datetime
from typing import Any

from sqlalchemy import ARRAY, CheckConstraint, DateTime, Index, String, Text, desc
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from verion.platform.db import Base


class SecurityBriefModel(Base):
    """One generated Security Brief. M7.2, ADR-0033.

    **Append-only, so no unique constraint.** Two rows for one member set are regenerations,
    which ADR-0033 decision 3 allows on purpose.

    **`decision` is JSONB and versioned.** It is `risk_engine`'s published carrier, written
    whole and read whole, and SQL never looks inside it, which is `RouteMapModel`'s argument
    for JSONB. The value carries `"version": 1` because it outlives a type another module owns.
    `repository.py`'s mapping derives every key from `dataclasses.fields`, so a carrier change
    fails loudly rather than storing short.

    `finding_ids` is ARRAY(String), a flat list of strings, on
    `SecurityContextModel.exposure_tags`' precedent. It is the Risk's members held as data,
    not an address, and nothing queries by it yet.
    """

    __tablename__ = "security_briefs"
    __table_args__ = (
        # A Brief with no members would link back to nothing (FR-9).
        CheckConstraint(
            "cardinality(finding_ids) >= 1", name="ck_security_briefs_finding_ids_not_empty"
        ),
        # Shipped with its query, `list_for_project`: `project_id` leading serves the filter
        # and the count, and `generated_at DESC` serves the page order without a sort. The
        # `ix_normalization_runs_project_id` idiom.
        Index("ix_security_briefs_project_id", "project_id", desc("generated_at")),
        # M7.3, ADR-0034: the second narration is stored whole or not at all. All three are
        # NULL exactly for a Brief written before M7.3; generation never writes a partial one.
        CheckConstraint(
            "(what_happened IS NULL) = (what_happened_model IS NULL)"
            " AND (what_happened IS NULL) = (what_happened_prompt_version IS NULL)",
            name="ck_security_briefs_what_happened_all_or_none",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    # No FK to projects — a cross-module reference, the same precedent as
    # `FindingModel.project_id`.
    project_id: Mapped[str] = mapped_column(String(36), nullable=False)
    # No FK to findings either, and an ARRAY cannot carry one: **G11**.
    finding_ids: Mapped[list[str]] = mapped_column(ARRAY(String), nullable=False)
    decision: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    why_it_matters: Mapped[str] = mapped_column(Text, nullable=False)
    model: Mapped[str] = mapped_column(String, nullable=False)
    prompt_version: Mapped[str] = mapped_column(String, nullable=False)
    # The *what happened* narration and its producer (M7.3, ADR-0034 decision 3). Nullable only
    # because Briefs written before M7.3 have none, and a narration cannot be backfilled.
    what_happened: Mapped[str | None] = mapped_column(Text, nullable=True)
    what_happened_model: Mapped[str | None] = mapped_column(String, nullable=True)
    what_happened_prompt_version: Mapped[str | None] = mapped_column(String, nullable=True)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
