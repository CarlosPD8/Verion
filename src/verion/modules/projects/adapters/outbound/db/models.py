from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String
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
