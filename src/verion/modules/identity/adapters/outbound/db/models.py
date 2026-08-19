from datetime import datetime

from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from verion.platform.db import Base


class UserModel(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, nullable=False, index=True)
    hashed_password: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class GitHubConnectionModel(Base):
    __tablename__ = "github_connections"

    # user_id is the natural key — no FK to identity's own users table isn't
    # needed here (same module), but there's deliberately no FK either since
    # nothing else queries by it relationally; a plain unique column is enough.
    user_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    # Stored in plaintext. Encryption at rest is a deliberate MVP deferral to
    # M10 (real secrets management), same treatment as M1.1's refresh-token
    # deferral — CLAUDE.md rules 12/13 (non-leakage in logs/exceptions/
    # responses/redirects) still apply in full regardless.
    access_token: Mapped[str] = mapped_column(String, nullable=False)
    github_username: Mapped[str] = mapped_column(String, nullable=False)
    connected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
