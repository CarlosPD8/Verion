from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class SecurityContext:
    id: str
    project_id: str
    language: str | None
    framework: str | None
    database: str | None
    deployment_target: str | None
    ci_provider: str | None
    exposure_tags: list[str]
    created_at: datetime
