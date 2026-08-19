from fastapi import APIRouter, HTTPException, status
from fastapi.responses import RedirectResponse

from verion.modules.identity.adapters.inbound.api.schemas import (
    AuthenticatedUser,
    LoginRequest,
    LoginResponse,
    RegisterRequest,
)
from verion.modules.identity.domain.exceptions import (
    EmailAlreadyRegistered,
    GitHubApiError,
    InvalidCredentials,
    InvalidEmail,
    InvalidOAuthState,
)
from verion.modules.identity.domain.github_connection import GitHubConnection
from verion.platform.di import (
    AccessTokenIssuerDep,
    AuthenticateUserUseCaseDep,
    ClockDep,
    CurrentUserIdDep,
    GitHubConnectionRepositoryDep,
    GitHubOAuthClientDep,
    OAuthStateSignerDep,
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


@router.get("/github/login")
async def github_login(
    user_id: CurrentUserIdDep,
    state_signer: OAuthStateSignerDep,
    oauth_client: GitHubOAuthClientDep,
) -> RedirectResponse:
    state = state_signer.sign(user_id)
    return RedirectResponse(url=oauth_client.build_authorize_url(state))


@router.get("/github/callback")
async def github_callback(
    settings: SettingsDep,
    state_signer: OAuthStateSignerDep,
    oauth_client: GitHubOAuthClientDep,
    connections: GitHubConnectionRepositoryDep,
    clock: ClockDep,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
) -> RedirectResponse:
    # GitHub redirects here with ?error=... if the user declines on GitHub's
    # consent screen — the single most common real path through this flow,
    # not a hypothetical edge case.
    if error is not None:
        return RedirectResponse(
            url=f"{settings.oauth_success_redirect_url}?error=github_oauth_denied"
        )

    if code is None or state is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing code or state")

    try:
        user_id = state_signer.verify(state)
    except InvalidOAuthState as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid OAuth state"
        ) from exc

    try:
        github_identity = await oauth_client.exchange_code_for_identity(code)
    except GitHubApiError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail="GitHub API request failed"
        ) from exc

    await connections.add(
        GitHubConnection(
            user_id=user_id,
            access_token=github_identity.access_token,
            github_username=github_identity.username,
            connected_at=clock.now(),
        )
    )

    # CLAUDE.md rule 13: never put the access token in a redirect Location.
    return RedirectResponse(url=settings.oauth_success_redirect_url)
