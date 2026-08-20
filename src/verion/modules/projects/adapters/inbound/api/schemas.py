from datetime import datetime

from pydantic import BaseModel


class CreateProjectRequest(BaseModel):
    name: str


class ConnectRepositoryRequest(BaseModel):
    provider: str
    url: str
    default_branch: str


class ConnectRepositoryViaGitHubRequest(BaseModel):
    owner: str
    repo: str


class UpdateExposureTagsRequest(BaseModel):
    exposure_tags: list[str]


class ProjectResponse(BaseModel):
    """Dedicated response schema, never the domain Project directly (rule 10)."""

    id: str
    owner_id: str
    name: str
    created_at: datetime


class ConnectedRepoResponse(BaseModel):
    """Dedicated response schema, never the domain ConnectedRepo directly (rule 10)."""

    id: str
    project_id: str
    provider: str
    url: str
    default_branch: str


class SecurityContextResponse(BaseModel):
    """Dedicated response schema, never the domain SecurityContext directly (rule 10)."""

    id: str
    project_id: str
    language: str | None
    framework: str | None
    database: str | None
    deployment_target: str | None
    ci_provider: str | None
    exposure_tags: list[str]
    created_at: datetime
