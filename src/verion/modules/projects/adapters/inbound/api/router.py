from fastapi import APIRouter, HTTPException, status

from verion.modules.projects.adapters.inbound.api.schemas import (
    ConnectedRepoResponse,
    ConnectRepositoryRequest,
    ConnectRepositoryViaGitHubRequest,
    CreateProjectRequest,
    ProjectResponse,
    ScannerConfigResponse,
    SecurityContextResponse,
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
    UnsupportedRepoProvider,
)
from verion.modules.projects.domain.scanner_config import ScannerConfig
from verion.modules.projects.domain.security_context import SecurityContext
from verion.platform.di import (
    BuildSecurityContextFromGitHubUseCaseDep,
    ConnectRepositoryUseCaseDep,
    ConnectRepositoryViaGitHubUseCaseDep,
    CreateProjectUseCaseDep,
    CurrentGitHubAccessTokenDep,
    CurrentUserIdDep,
    GetSecurityContextUseCaseDep,
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
        )
    except ProjectNotFound as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except InsufficientPermissions as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except InvalidScannerConfig as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return _scanner_config_response(config)
