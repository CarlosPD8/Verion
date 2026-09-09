from fastapi import APIRouter, HTTPException, status

from verion.modules.projects.adapters.inbound.api.schemas import (
    ConnectedRepoResponse,
    ConnectRepositoryRequest,
    ConnectRepositoryViaGitHubRequest,
    CreateProjectRequest,
    DeclareServingRequest,
    ProjectResponse,
    ScannerConfigResponse,
    SecurityContextResponse,
    ServingDeclarationResponse,
    UpdateExposureTagsRequest,
    UpdateScannerConfigRequest,
)
from verion.modules.projects.domain.exceptions import (
    ConnectedRepoNotFound,
    GitHubApiError,
    InsufficientPermissions,
    InvalidScannerConfig,
    ProjectNotFound,
    SecurityContextNotFound,
    ServingDeclarationMismatch,
    ServingDeclarationNotFound,
    UnsupportedRepoProvider,
)
from verion.modules.projects.domain.scanner_config import ScannerConfig
from verion.modules.projects.domain.security_context import SecurityContext
from verion.modules.projects.domain.serving_declaration import ServingDeclaration
from verion.platform.di import (
    BuildSecurityContextFromGitHubUseCaseDep,
    ConnectRepositoryUseCaseDep,
    ConnectRepositoryViaGitHubUseCaseDep,
    CreateProjectUseCaseDep,
    CurrentGitHubAccessTokenDep,
    CurrentUserIdDep,
    DeclareServingUseCaseDep,
    GetSecurityContextUseCaseDep,
    GetServingDeclarationUseCaseDep,
    UpdateExposureTagsUseCaseDep,
    UpdateScannerConfigUseCaseDep,
)

router = APIRouter()


@router.post("/", status_code=status.HTTP_201_CREATED, response_model=ProjectResponse)
async def create_project(
    request: CreateProjectRequest, user_id: CurrentUserIdDep, use_case: CreateProjectUseCaseDep
) -> ProjectResponse:
    project = await use_case.execute(owner_id=user_id, name=request.name)

    return ProjectResponse(
        id=project.id, owner_id=project.owner_id, name=project.name, created_at=project.created_at
    )


@router.post(
    "/{project_id}/repositories",
    status_code=status.HTTP_201_CREATED,
    response_model=ConnectedRepoResponse,
)
async def connect_repository(
    project_id: str,
    request: ConnectRepositoryRequest,
    user_id: CurrentUserIdDep,
    use_case: ConnectRepositoryUseCaseDep,
) -> ConnectedRepoResponse:
    try:
        connected_repo = await use_case.execute(
            project_id=project_id,
            user_id=user_id,
            provider=request.provider,
            url=request.url,
            default_branch=request.default_branch,
        )
    except ProjectNotFound as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except InsufficientPermissions as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc

    return ConnectedRepoResponse(
        id=connected_repo.id,
        project_id=connected_repo.project_id,
        provider=connected_repo.provider,
        url=connected_repo.url,
        default_branch=connected_repo.default_branch,
    )


def _security_context_response(context: SecurityContext) -> SecurityContextResponse:
    return SecurityContextResponse(
        id=context.id,
        project_id=context.project_id,
        language=context.language,
        framework=context.framework,
        database=context.database,
        deployment_target=context.deployment_target,
        ci_provider=context.ci_provider,
        exposure_tags=context.exposure_tags,
        created_at=context.created_at,
    )


@router.post(
    "/{project_id}/repositories/github",
    status_code=status.HTTP_201_CREATED,
    response_model=ConnectedRepoResponse,
)
async def connect_repository_via_github(
    project_id: str,
    request: ConnectRepositoryViaGitHubRequest,
    user_id: CurrentUserIdDep,
    access_token: CurrentGitHubAccessTokenDep,
    use_case: ConnectRepositoryViaGitHubUseCaseDep,
) -> ConnectedRepoResponse:
    try:
        connected_repo = await use_case.execute(
            project_id=project_id,
            user_id=user_id,
            access_token=access_token,
            owner=request.owner,
            repo=request.repo,
        )
    except ProjectNotFound as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except InsufficientPermissions as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except GitHubApiError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail="GitHub API request failed"
        ) from exc

    return ConnectedRepoResponse(
        id=connected_repo.id,
        project_id=connected_repo.project_id,
        provider=connected_repo.provider,
        url=connected_repo.url,
        default_branch=connected_repo.default_branch,
    )


@router.post(
    "/{project_id}/security-context/detect",
    status_code=status.HTTP_201_CREATED,
    response_model=SecurityContextResponse,
)
async def detect_security_context(
    project_id: str,
    user_id: CurrentUserIdDep,
    access_token: CurrentGitHubAccessTokenDep,
    use_case: BuildSecurityContextFromGitHubUseCaseDep,
) -> SecurityContextResponse:
    try:
        context = await use_case.execute(
            project_id=project_id, user_id=user_id, access_token=access_token
        )
    except ProjectNotFound as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except InsufficientPermissions as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except ConnectedRepoNotFound as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except UnsupportedRepoProvider as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except GitHubApiError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail="GitHub API request failed"
        ) from exc

    return _security_context_response(context)


@router.get(
    "/{project_id}/security-context",
    status_code=status.HTTP_200_OK,
    response_model=SecurityContextResponse,
)
async def get_security_context(
    project_id: str,
    user_id: CurrentUserIdDep,
    use_case: GetSecurityContextUseCaseDep,
) -> SecurityContextResponse:
    try:
        context = await use_case.execute(project_id=project_id, user_id=user_id)
    except ProjectNotFound as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except InsufficientPermissions as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except SecurityContextNotFound as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    return _security_context_response(context)


@router.patch(
    "/{project_id}/security-context",
    status_code=status.HTTP_200_OK,
    response_model=SecurityContextResponse,
)
async def update_exposure_tags(
    project_id: str,
    request: UpdateExposureTagsRequest,
    user_id: CurrentUserIdDep,
    use_case: UpdateExposureTagsUseCaseDep,
) -> SecurityContextResponse:
    try:
        context = await use_case.execute(
            project_id=project_id, user_id=user_id, exposure_tags=request.exposure_tags
        )
    except ProjectNotFound as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except InsufficientPermissions as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc

    return _security_context_response(context)


def _scanner_config_response(config: ScannerConfig) -> ScannerConfigResponse:
    return ScannerConfigResponse(
        id=config.id,
        project_id=config.project_id,
        enabled_tools=[str(tool) for tool in config.enabled_tools],
        zap_target_url=config.zap_target_url,
        updated_at=config.updated_at,
        active_scan_consent_in_force=config.active_scan_consent_in_force,
        active_scan_consent_target=config.active_scan_consent_target,
        active_scan_consent_granted_at=config.active_scan_consent_granted_at,
        active_scan_consent_granted_by=config.active_scan_consent_granted_by,
    )


@router.put(
    "/{project_id}/scanner-config",
    status_code=status.HTTP_200_OK,
    response_model=ScannerConfigResponse,
)
async def update_scanner_config(
    project_id: str,
    request: UpdateScannerConfigRequest,
    user_id: CurrentUserIdDep,
    use_case: UpdateScannerConfigUseCaseDep,
) -> ScannerConfigResponse:
    try:
        config = await use_case.execute(
            project_id=project_id,
            user_id=user_id,
            enabled_tools=request.enabled_tools,
            zap_target_url=request.zap_target_url,
            active_scan_consent=request.active_scan_consent,
        )
    except ProjectNotFound as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except InsufficientPermissions as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except InvalidScannerConfig as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return _scanner_config_response(config)


def _serving_declaration_response(
    declaration: ServingDeclaration, in_force: bool
) -> ServingDeclarationResponse:
    return ServingDeclarationResponse(
        id=declaration.id,
        project_id=declaration.project_id,
        in_force=in_force,
        declared_target_url=declaration.declared_target_url,
        declared_repo_url=declaration.declared_repo_url,
        declared_default_branch=declaration.declared_default_branch,
        declared_at=declaration.declared_at,
        declared_by=declaration.declared_by,
    )


@router.put(
    "/{project_id}/serving-declaration",
    status_code=status.HTTP_200_OK,
    response_model=ServingDeclarationResponse,
)
async def declare_serving(
    project_id: str,
    request: DeclareServingRequest,
    user_id: CurrentUserIdDep,
    use_case: DeclareServingUseCaseDep,
) -> ServingDeclarationResponse:
    """PUT rather than POST, and a compare-and-set rather than a plain write.

    PUT because there is one declaration per project and re-declaring replaces it, which
    is `update_scanner_config`'s shape one resource over.

    **409 is this router's only one**, and it is the status ADR-0028's 2026-09-09
    amendment A argues for: the body carries three values the owner was shown, and a
    mismatch means the resource is not in the state the request presumes — not that the
    request is malformed, which is what 400 says and what `InvalidScannerConfig` covers
    here. `identity`'s `EmailAlreadyRegistered` is the existing 409 in this codebase.
    """
    try:
        declaration, in_force = await use_case.execute(
            project_id=project_id,
            user_id=user_id,
            declared_target_url=request.declared_target_url,
            declared_repo_url=request.declared_repo_url,
            declared_default_branch=request.declared_default_branch,
        )
    except ProjectNotFound as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except InsufficientPermissions as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except ConnectedRepoNotFound as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except InvalidScannerConfig as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except ServingDeclarationMismatch as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    return _serving_declaration_response(declaration, in_force)


@router.get(
    "/{project_id}/serving-declaration",
    status_code=status.HTTP_200_OK,
    response_model=ServingDeclarationResponse,
)
async def get_serving_declaration(
    project_id: str,
    user_id: CurrentUserIdDep,
    use_case: GetServingDeclarationUseCaseDep,
) -> ServingDeclarationResponse:
    try:
        declaration, in_force = await use_case.execute(project_id=project_id, user_id=user_id)
    except ProjectNotFound as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except InsufficientPermissions as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except ServingDeclarationNotFound as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    return _serving_declaration_response(declaration, in_force)
