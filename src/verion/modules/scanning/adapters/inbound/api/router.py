import json

from fastapi import APIRouter, HTTPException, Request, Response, status

from verion.modules.scanning.adapters.inbound.api.schemas import (
    ScanAcceptedResponse,
    ScanResponse,
    WebhookAckResponse,
)
from verion.modules.scanning.domain.exceptions import (
    InvalidWebhookPayload,
    ProjectAccessDenied,
    ProjectNotFound,
    RepoNotConnected,
    ScanNotFound,
)
from verion.modules.scanning.domain.webhook_signature import verify_signature
from verion.platform.di import (
    CurrentUserIdDep,
    GetScanUseCaseDep,
    HandleGitHubWebhookUseCaseDep,
    StartScanUseCaseDep,
    WebhookSecretDep,
)

router = APIRouter()

# A second router, mounted under /projects by platform/app.py, because the resource these
# routes hang off is a project — the same reason findings, risks and Briefs share that
# prefix. The webhook above stays under /scanning (ADR-0035 decision 1).
project_scans_router = APIRouter()


@router.post(
    "/webhooks/github",
    response_model=WebhookAckResponse,
)
async def github_webhook(
    request: Request,
    response: Response,
    webhook_secret: WebhookSecretDep,
    use_case: HandleGitHubWebhookUseCaseDep,
) -> WebhookAckResponse:
    # Raw bytes, read before any parsing — HMAC must run over exactly what
    # GitHub signed. A re-serialized/parsed-then-dumped body would never
    # reproduce the same bytes and would always fail verification, even for
    # a genuine delivery.
    raw_body = await request.body()

    # Signature gate: the very first thing this handler does with the
    # payload. No use case is invoked and no header/payload content beyond
    # the signature itself is read below this point until verification
    # passes.
    if not verify_signature(raw_body, request.headers.get("x-hub-signature-256"), webhook_secret):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid signature")

    delivery_id = request.headers.get("x-github-delivery")
    if not delivery_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Missing X-GitHub-Delivery header"
        )
    event_type = request.headers.get("x-github-event", "")

    try:
        payload = json.loads(raw_body)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Malformed JSON payload"
        ) from exc

    try:
        scan = await use_case.execute(
            delivery_id=delivery_id, event_type=event_type, payload=payload
        )
    except RepoNotConnected as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ProjectNotFound as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except InvalidWebhookPayload as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    if scan is None:
        # A redelivery of an already-seen X-GitHub-Delivery, or a
        # non-push event (e.g. "ping") — acknowledged, nothing enqueued.
        response.status_code = status.HTTP_200_OK
        return WebhookAckResponse(status="ignored")

    # Work was enqueued, not synchronously completed.
    response.status_code = status.HTTP_202_ACCEPTED
    return WebhookAckResponse(status="accepted")


@project_scans_router.post(
    "/{project_id}/scans",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=ScanAcceptedResponse,
)
async def start_scan(
    project_id: str, user_id: CurrentUserIdDep, use_case: StartScanUseCaseDep
) -> ScanAcceptedResponse:
    """Start a scan of a project the caller owns. M8's exit condition, first clause.

    **202**, because the scan runs as an arq job. By the time this answers, the `Scan` row is
    committed and its job is queued, in that order (ADR-0035 decision 5). Poll the GET below
    for its status.

    **404 for every denial**: an absent project, a non-member and a member who is not an
    owner get the same status and the same body (ADR-0035 decision 2, **G17**).
    """
    try:
        scan = await use_case.execute(project_id=project_id, user_id=user_id)
    except ProjectAccessDenied as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    return ScanAcceptedResponse(id=scan.id, status=str(scan.status))


@project_scans_router.get(
    "/{project_id}/scans/{scan_id}",
    status_code=status.HTTP_200_OK,
    response_model=ScanResponse,
)
async def get_scan(
    project_id: str, scan_id: str, user_id: CurrentUserIdDep, use_case: GetScanUseCaseDep
) -> ScanResponse:
    """One scan's status, for any member of its project (ADR-0035 decision 4).

    404 for a project the caller may not read, and 404 for a scan that is absent or belongs
    to another project, so a member of one project cannot probe scan ids in another.
    """
    try:
        scan = await use_case.execute(project_id=project_id, user_id=user_id, scan_id=scan_id)
    except ProjectAccessDenied as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ScanNotFound as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    return ScanResponse(id=scan.id, status=str(scan.status), failure_reason=scan.failure_reason)
