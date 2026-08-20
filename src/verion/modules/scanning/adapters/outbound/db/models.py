from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from verion.platform.db import Base


class ScanModel(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    # No FK to projects' table — module independence at the persistence
    # layer too, same precedent as ProjectModel.owner_id having no FK to
    # identity's users.
    project_id: Mapped[str] = mapped_column(String(36), nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False)
    triggered_by: Mapped[str] = mapped_column(String(36), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    failure_reason: Mapped[str | None] = mapped_column(String, nullable=True)


class ScanResultModel(Base):
    __tablename__ = "scan_results"
    __table_args__ = (UniqueConstraint("scan_id", "tool", name="uq_scan_results_scan_id_tool"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    # FK to scans — both tables belong to this module (same precedent as
    # ConnectedRepoModel.project_id -> projects.id: FKs are used within a
    # module, only cross-module references go unconstrained).
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), nullable=False)
    tool: Mapped[str] = mapped_column(String, nullable=False)
    raw_output: Mapped[str] = mapped_column(String, nullable=False)


class WebhookDeliveryModel(Base):
    __tablename__ = "webhook_deliveries"

    # delivery_id (GitHub's X-GitHub-Delivery GUID) as the primary key IS
    # the dedup mechanism: record_if_new relies on the resulting unique-
    # constraint violation to detect a redelivery race-safely, the same
    # defensive-constraint idiom as ScanResultModel's (scan_id, tool).
    delivery_id: Mapped[str] = mapped_column(String, primary_key=True)
