import hashlib
import hmac

from verion.modules.scanning.domain.webhook_signature import verify_signature

_SECRET = "test-webhook-secret"
_PAYLOAD = b'{"ref": "refs/heads/main"}'


def _sign(payload: bytes, secret: str = _SECRET) -> str:
    digest = hmac.new(secret.encode("utf-8"), msg=payload, digestmod=hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def test_accepts_a_correctly_signed_payload():
    assert verify_signature(_PAYLOAD, _sign(_PAYLOAD), _SECRET) is True


def test_rejects_a_signature_computed_with_the_wrong_secret():
    assert verify_signature(_PAYLOAD, _sign(_PAYLOAD, secret="wrong-secret"), _SECRET) is False


def test_rejects_a_signature_over_a_different_payload():
    other_signature = _sign(b'{"ref": "refs/heads/tampered"}')
    assert verify_signature(_PAYLOAD, other_signature, _SECRET) is False


def test_rejects_a_missing_signature_header():
    assert verify_signature(_PAYLOAD, None, _SECRET) is False


def test_rejects_a_header_without_the_sha256_prefix():
    digest = hmac.new(_SECRET.encode("utf-8"), msg=_PAYLOAD, digestmod=hashlib.sha256).hexdigest()
    assert verify_signature(_PAYLOAD, digest, _SECRET) is False


def test_rejects_a_malformed_header():
    assert verify_signature(_PAYLOAD, "sha256=not-a-real-digest", _SECRET) is False
