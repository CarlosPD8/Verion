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


class UpdateScannerConfigRequest(BaseModel):
    # Plain list[str], not list[ScannerTool]: an unknown name should come back
    # as this API's own "Unknown scanner 'x'. Known scanners: ..." message from
    # the use case, not as a pydantic enum-coercion error that names the field
    # but not the alternatives.
    enabled_tools: list[str]
    zap_target_url: str | None = None


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


class ScannerConfigResponse(BaseModel):
    """Dedicated response schema, never the domain ScannerConfig directly (rule 10)."""

    id: str
    project_id: str
    enabled_tools: list[str]
    zap_target_url: str | None
    updated_at: datetime
