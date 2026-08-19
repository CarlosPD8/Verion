from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class Role(StrEnum):
    OWNER = "owner"
    MEMBER = "member"


@dataclass(frozen=True)
class Project:
    id: str
    owner_id: str
    name: str
    created_at: datetime


@dataclass(frozen=True)
class ConnectedRepo:
    id: str
    project_id: str
    provider: str
    url: str
    default_branch: str


@dataclass(frozen=True)
class ProjectMembership:
    project_id: str
    user_id: str
    role: Role
