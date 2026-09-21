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
    # The surface's grouping provenance as the engine computed it (M8.5, ADR-0037). A plain
    # String rather than a DB enum: `Confidence` is `shared_kernel`'s vocabulary and adding a
    # value must not need a type migration. NULL only for a Brief written before M8.5, and
    # never backfilled — the surface it described may have moved. No CHECK pairing it with
    # anything: one column, nothing to be all-or-none with.
    confidence: Mapped[str | None] = mapped_column(String, nullable=True)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class BriefGenerationModel(Base):
    """One request to generate a Brief, and what became of it. M8.6, ADR-0038.

    **A table of its own, not a `pending` row in `security_briefs`** (decision 2). That fork
    needed five of this module's other table's eight `NOT NULL` columns made nullable — a
    migration weakening invariants every existing row satisfies — and it broke
    `test_security_brief.py`'s **equality** assertion over `SecurityBrief`'s field set. A CHECK
    could have re-expressed them (`ck_security_briefs_what_happened_all_or_none` is that template,
    on that very table), so the fork was not rejected for lack of one: it was rejected because the
    CHECK would have to be conditioned on a status column that does not belong on a table whose
    every row is a completed Brief, and because the domain type would carry three existing fields
    turned optional plus two new state fields, all to describe a state no Brief reaches.

    **This table ships NO index beyond its primary key**, and that is the `SecurityBriefModel`
    rule above applied the other way: an index ships *with its query*, and this table has no
    query that filters or orders. ADR-0038 puts a list of generations out of scope and the poll
    addresses one row by id.

    **No FK to `security_briefs`.** `brief_id` is NULL until `SUCCEEDED`, and the CHECK below is
    what governs when it may be set — which is the property worth enforcing here. Both tables
    belong to this module, so an FK would be legal; it buys nothing the CHECK does not.

    `finding_ids` is the caller's REQUESTED set, held as data on
    `SecurityBriefModel.finding_ids`' precedent. The engine's members are what a stored Brief
    carries; the two differing is exactly the `surface_changed` outcome.
    """

    __tablename__ = "brief_generations"
    __table_args__ = (
        # **Written here rather than inherited, and `scans` is NOT the precedent.** `ScanModel`
        # has no `__table_args__` at all, so its `status`/`failure_reason` pairing is a
        # convention nothing enforces. The template is `ck_scan_results_outcome_shape` on
        # `ScanResultModel` — a different table, in another module, that actually has one.
        # ADR-0038 decision 7.
        #
        # Every column this constraint governs is one the poll returns. `detail` is NOT a column:
        # it is derived from `failure_kind` at the adapter, so there is nothing for a fourth
        # nullable column to drift from and nothing outside this CHECK to correlate by hand.
        CheckConstraint(
            "(status IN ('pending','running') AND brief_id IS NULL AND failure_kind IS NULL)"
            " OR (status = 'succeeded' AND brief_id IS NOT NULL AND failure_kind IS NULL)"
            " OR (status = 'failed' AND brief_id IS NULL AND failure_kind IS NOT NULL)",
            name="ck_brief_generations_outcome_shape",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    # No FK to projects — a cross-module reference, `SecurityBriefModel.project_id`'s precedent.
    project_id: Mapped[str] = mapped_column(String(36), nullable=False)
    # **The requesting caller, stored because the JOB re-authorizes with it** (decision 4). Not a
    # verdict carried across the queue: `explainable_risk` authorizes and selects in one call and
    # cannot be split, so this id crosses under every design. What storing it buys is a second,
    # independent check in the worker, which also catches a membership revoked between enqueue
    # and run.
    user_id: Mapped[str] = mapped_column(String(36), nullable=False)
    finding_ids: Mapped[list[str]] = mapped_column(ARRAY(String), nullable=False)
    # A plain String, not a DB enum, on `security_briefs.confidence`'s ground: adding a value
    # must not need a type migration. Reconstructed as the enum on read.
    status: Mapped[str] = mapped_column(String, nullable=False)
    brief_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    failure_kind: Mapped[str | None] = mapped_column(String, nullable=True)
    # The row's own audit time (rule 14), which `scans` and `normalization_runs` both carry.
    #
    # **There is deliberately no `started_at` or `finished_at`.** `normalization_runs` carries a
    # start time to serve its SWEEP's staleness rule, and ADR-0038 decision 11 declines the
    # sweep, so nothing would read one. Two nullable columns outside the CHECK above would also
    # make a succeeded row with no finish time, and a pending row with one, both legal — "a
    # convention nothing enforces", which is the phrase decision 7 uses for what it declines to
    # copy from `scans`.
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
