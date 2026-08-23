from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from verion.platform.db import Base


class NormalizationRunModel(Base):
    __tablename__ = "normalization_runs"
    __table_args__ = (
        # The idempotency key. A retried run_scan job re-requests normalization
        # for a scan it already requested it for; this constraint is what turns
        # that into a no-op instead of a second row (ADR-0017 decision 2).
        UniqueConstraint("scan_id", name="uq_normalization_runs_scan_id"),
        # Deliberately more defence than scan_results gives its own status
        # column, for one specific reason: this column is what a reconciliation
        # sweep selects on, so an unrecognised value would make the row
        # *invisible to the sweep* rather than merely odd — a scan that silently
        # never gets normalized, which is the exact failure this record exists
        # to prevent.
        CheckConstraint(
            "status IN ('pending', 'running', 'completed', 'failed')",
            name="ck_normalization_runs_status",
        ),
        # The same invariant NormalizationRun.__post_init__ enforces, enforced
        # again where nothing can route around it — the idiom ADR-016 decision 2
        # established with ck_scan_results_outcome_shape.
        CheckConstraint(
            "(status = 'failed' AND failure_reason IS NOT NULL)"
            " OR (status <> 'failed' AND failure_reason IS NULL)",
            name="ck_normalization_runs_failure_reason_shape",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    # No FK to scans — scans belongs to `scanning`, and cross-module references
    # go unconstrained at the persistence layer too, the same precedent as
    # ScanModel.project_id and ProjectModel.owner_id.
    scan_id: Mapped[str] = mapped_column(String(36), nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # Unconstrained on purpose: these belong to transitions M4.1 writes.
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    failure_reason: Mapped[str | None] = mapped_column(String, nullable=True)
