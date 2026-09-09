from datetime import datetime

from sqlalchemy import ARRAY, DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from verion.platform.db import Base


class ProjectModel(Base):
    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    # No FK to identity's users table — module independence at the persistence
    # layer too. owner_id is a plain, unconstrained string end-to-end.
    owner_id: Mapped[str] = mapped_column(String(36), nullable=False)
    name: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ConnectedRepoModel(Base):
    __tablename__ = "connected_repos"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), nullable=False)
    provider: Mapped[str] = mapped_column(String, nullable=False)
    url: Mapped[str] = mapped_column(String, nullable=False)
    default_branch: Mapped[str] = mapped_column(String, nullable=False)


class ProjectMembershipModel(Base):
    __tablename__ = "project_memberships"

    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), primary_key=True)
    # No FK to identity's users table — see ProjectModel.owner_id above.
    user_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    role: Mapped[str] = mapped_column(String, nullable=False)


class SecurityContextModel(Base):
    __tablename__ = "security_contexts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), nullable=False)
    language: Mapped[str | None] = mapped_column(String, nullable=True)
    framework: Mapped[str | None] = mapped_column(String, nullable=True)
    database: Mapped[str | None] = mapped_column(String, nullable=True)
    deployment_target: Mapped[str | None] = mapped_column(String, nullable=True)
    ci_provider: Mapped[str | None] = mapped_column(String, nullable=True)
    exposure_tags: Mapped[list[str]] = mapped_column(ARRAY(String), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ScannerConfigModel(Base):
    __tablename__ = "scanner_configs"
    # Named explicitly (same idiom as ScanResultModel's (scan_id, tool)) so the
    # repository's ON CONFLICT can target it by name. It also enforces the
    # one-row-per-project shape at the storage layer, not just by convention —
    # a second row for a project would make "which config applies?" ambiguous.
    __table_args__ = (UniqueConstraint("project_id", name="uq_scanner_configs_project_id"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), nullable=False)
    # ARRAY(String), same precedent as SecurityContextModel.exposure_tags above.
    # Absent from this list means the tool is off; there is no separate row
    # whose absence would have to be interpreted (ADR-016 decision 3).
    enabled_tools: Mapped[list[str]] = mapped_column(ARRAY(String), nullable=False)
    zap_target_url: Mapped[str | None] = mapped_column(String, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # ADR-0024 decision 1. Three nullable columns, no boolean: consent is present
    # only when all three are set, and the target is what decision 3 compares.
    # No FK on granted_by, for the reason ProjectModel.owner_id already gives:
    # `users` is identity's table, and module independence holds at the
    # persistence layer too. The project_id FKs in this file are the other side
    # of that same rule — inside the module, so they stay.
    active_scan_consent_target: Mapped[str | None] = mapped_column(String, nullable=True)
    active_scan_consent_granted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    active_scan_consent_granted_by: Mapped[str | None] = mapped_column(String(36), nullable=True)


class ServingDeclarationModel(Base):
    __tablename__ = "serving_declarations"
    # Named explicitly, same idiom as ScannerConfigModel above, so the repository's
    # ON CONFLICT can target it by name — and so the one-row-per-project shape is
    # enforced at the storage layer rather than by convention. ADR-0028 decision 1.
    __table_args__ = (UniqueConstraint("project_id", name="uq_serving_declarations_project_id"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), nullable=False)
    # All three sides stored by value and all three NOT NULL: ADR-0028 decision 2's
    # rule compares each against its live counterpart, and a nullable column here
    # would introduce a fourth state — "declared, but not about this field" — that
    # the rule has no answer for.
    declared_target_url: Mapped[str] = mapped_column(String, nullable=False)
    declared_repo_url: Mapped[str] = mapped_column(String, nullable=False)
    declared_default_branch: Mapped[str] = mapped_column(String, nullable=False)
    declared_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # No FK on declared_by, for the reason ProjectModel.owner_id and
    # ScannerConfigModel.active_scan_consent_granted_by both already give: `users`
    # is identity's table, and module independence holds at the persistence layer
    # too. The project_id FK above is the other side of that same rule — inside the
    # module, so it stays.
    declared_by: Mapped[str] = mapped_column(String(36), nullable=False)
