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
    # Tri-state, and omitted is not the same as false: `None` leaves the stored
    # grant alone so an owner can repoint `zap_target_url` without restating
    # consent, which is the case ADR-0024 decision 3's rule exists for. `false`
    # is an explicit withdrawal.
    active_scan_consent: bool | None = None


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
    # The verdict is returned alongside the stored fields rather than instead of
    # them, because the two answer different questions: an owner who repointed
    # the target needs to see both that consent is no longer in force AND which
    # target it was granted against, or the false verdict looks like a bug.
    # `granted_by` is a user id, not a credential — rule 12 does not reach it,
    # and it is the only actor this resource records (G43).
    active_scan_consent_in_force: bool
    active_scan_consent_target: str | None
    active_scan_consent_granted_at: datetime | None
    active_scan_consent_granted_by: str | None


class DeclareServingRequest(BaseModel):
    # Plain `str`, never pydantic's HttpUrl or AnyUrl, for UpdateScannerConfigRequest's
    # reason: the failure should surface as this API's own message out of
    # `validate_zap_target_url` — which names the scheme it got, or refuses userinfo
    # without echoing the URL — rather than as a pydantic 422 that names the field and
    # nothing else.
    #
    # All three are required and none defaults. ADR-0028's 2026-09-09 amendment A makes
    # this request a compare-and-set: the owner is attesting to three values they were
    # shown, so an omitted one would be the server filling in what the declarer never
    # saw, which is the blind-attestation shape that amendment rejects.
    declared_target_url: str
    declared_repo_url: str
    declared_default_branch: str


class ServingDeclarationResponse(BaseModel):
    """Dedicated response schema, never the domain ServingDeclaration directly (rule 10)."""

    id: str
    project_id: str
    # The verdict alongside the stored values rather than instead of them, exactly as
    # ScannerConfigResponse does it and for the same reason: an owner whose declaration
    # has gone out of force needs to see both that it has and what it was declared
    # against, or the false verdict looks like a bug.
    #
    # `declared_by` is a user id, not a credential — rule 12 does not reach it, the same
    # reading `active_scan_consent_granted_by` already carries, and it is the only actor
    # this resource records.
    #
    # `declared_repo_url` is where rule 12 DOES reach, and it is made safe at the write
    # path rather than here: this route is member-level, which is a wider audience than
    # ConnectedRepo.url otherwise has (both routes exposing that are owner-gated writes),
    # and that value is stored completely unvalidated. `validate_declared_repo_url`
    # refuses userinfo before any row exists, so no credential can reach this response.
    in_force: bool
    declared_target_url: str
    declared_repo_url: str
    declared_default_branch: str
    declared_at: datetime
    declared_by: str
