import json

from fastapi import APIRouter, HTTPException, Request, Response, status

from verion.modules.scanning.adapters.inbound.api.schemas import WebhookAckResponse
from verion.modules.scanning.domain.exceptions import (
    InvalidWebhookPayload,
    ProjectNotFound,
    RepoNotConnected,
)
from verion.modules.scanning.domain.webhook_signature import verify_signature
from verion.platform.di import HandleGitHubWebhookUseCaseDep, WebhookSecretDep

router = APIRouter()


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
