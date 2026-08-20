import hashlib
import hmac

_SIGNATURE_PREFIX = "sha256="


def verify_signature(payload: bytes, signature_header: str | None, secret: str) -> bool:
    """Verifies GitHub's X-Hub-Signature-256 header against the raw request
    body, per https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries.

    `payload` must be the exact raw bytes GitHub signed — parsing then
    re-serializing JSON before this call would not reproduce the same bytes
    and would always fail verification, even for a genuine delivery.

    hmac.compare_digest, not `==`: GitHub's own docs explicitly warn a plain
    `==` leaks timing information an attacker can use to recover the correct
    signature byte-by-byte.
    """
    if signature_header is None or not signature_header.startswith(_SIGNATURE_PREFIX):
        return False

    expected = (
        _SIGNATURE_PREFIX
        + hmac.new(secret.encode("utf-8"), msg=payload, digestmod=hashlib.sha256).hexdigest()
    )
    return hmac.compare_digest(expected, signature_header)
