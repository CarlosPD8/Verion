from fastapi import APIRouter, HTTPException, status

from verion.modules.identity.adapters.inbound.api.schemas import (
    AuthenticatedUser,
    LoginRequest,
    LoginResponse,
    RegisterRequest,
)
from verion.modules.identity.domain.exceptions import (
    EmailAlreadyRegistered,
    InvalidCredentials,
    InvalidEmail,
)
from verion.platform.di import (
    AccessTokenIssuerDep,
    AuthenticateUserUseCaseDep,
    RegisterUserUseCaseDep,
    SettingsDep,
)

router = APIRouter()


@router.post("/register", status_code=status.HTTP_201_CREATED, response_model=AuthenticatedUser)
async def register(request: RegisterRequest, use_case: RegisterUserUseCaseDep) -> AuthenticatedUser:
    try:
        user = await use_case.execute(email=request.email, plaintext_password=request.password)
    except InvalidEmail as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc
    except EmailAlreadyRegistered as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    return AuthenticatedUser(id=user.id, email=str(user.email))


@router.post("/login", response_model=LoginResponse)
async def login(
    request: LoginRequest,
    authenticate: AuthenticateUserUseCaseDep,
    token_issuer: AccessTokenIssuerDep,
    settings: SettingsDep,
) -> LoginResponse:
    try:
        user = await authenticate.execute(email=request.email, plaintext_password=request.password)
    except InvalidCredentials as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc

    access_token = token_issuer.issue(subject=user.id)

    return LoginResponse(
        access_token=access_token.value,
        expires_in=settings.jwt_expires_minutes * 60,
        user=AuthenticatedUser(id=user.id, email=str(user.email)),
    )
