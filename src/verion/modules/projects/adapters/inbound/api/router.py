from fastapi import APIRouter, HTTPException, status

from verion.modules.projects.adapters.inbound.api.schemas import (
    ConnectedRepoResponse,
    ConnectRepositoryRequest,
    CreateProjectRequest,
    ProjectResponse,
)
from verion.modules.projects.domain.exceptions import InsufficientPermissions, ProjectNotFound
from verion.platform.di import (
    ConnectRepositoryUseCaseDep,
    CreateProjectUseCaseDep,
    CurrentUserIdDep,
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
