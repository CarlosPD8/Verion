import base64
import json
from datetime import UTC, datetime, timedelta

import jwt
import pytest

from verion.modules.identity.adapters.outbound.oauth.state_signer import (
    _PURPOSE,
    GitHubOAuthStateSigner,
)
from verion.modules.identity.domain.exceptions import InvalidOAuthState


class _FixedClock:
    def __init__(self, now: datetime) -> None:
        self._now = now

    def now(self) -> datetime:
        return self._now


def _signer(clock: _FixedClock, expires_minutes: int = 10) -> GitHubOAuthStateSigner:
    return GitHubOAuthStateSigner(
        secret_key="test-secret-that-is-32-bytes-long",
        algorithm="HS256",
        expires_minutes=expires_minutes,
        clock=clock,
    )


def test_sign_and_verify_round_trip():
    # Real current time, not a fixed past date — verify() checks `exp`
    # against real wall-clock time, so a hardcoded past clock would make
    # the token look expired immediately (see test_expired_state_is_rejected
    # for the deliberate-expiry case).
    clock = _FixedClock(datetime.now(UTC))
    signer = _signer(clock)

    state = signer.sign("user-1")

    assert signer.verify(state) == "user-1"


def _decoded_segments(token: str) -> tuple[bytes, ...]:
    """Every segment of a JWT, base64url-decoded.

    Decoded bytes are compared rather than the raw strings because base64url
    is not injective over a fixed byte length: an HS256 signature is 32 bytes
    carried in 43 characters — 258 bits of alphabet for 256 bits of signature
    — so the final character's low two bits are padding and are discarded on
    decode. Two different strings can be the same token.
    """
    segments: list[bytes] = []
    for segment in token.split("."):
        try:
            segments.append(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))
        except ValueError:
            # An undecodable segment is still a genuine difference from a
            # decodable one, which is all this comparison needs to establish.
            segments.append(segment.encode())
    return tuple(segments)


def _assert_rejected_as_tampered(
    signer: GitHubOAuthStateSigner, original: str, tampered: str
) -> None:
    """Assert `tampered` really is a different token, *then* that it's rejected.

    The first assertion is the point of this helper, and matters more than the
    second. Until 2026-08-21 this file tampered by replacing the token's final
    character — which lands in the signature's base64url padding bits about one
    time in sixteen and produced a byte-identical token. On those runs the test
    asserted that a perfectly valid token was rejected, and failed; on the rest
    it passed while mutating something it had not checked was a mutation.

    Shared by every case below rather than repeated inline, so that no future
    tampering can be a silent no-op: one that changes nothing fails here,
    loudly, instead of reporting green.
    """
    assert _decoded_segments(tampered) != _decoded_segments(original), (
        "the 'tampered' token decodes identically to the original, so this case proves "
        "nothing about verification — fix the mutation, not this assertion"
    )
    with pytest.raises(InvalidOAuthState):
        signer.verify(tampered)


def _claims_of(state: str) -> dict[str, object]:
    payload = state.split(".")[1]
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    assert isinstance(claims, dict)
    return claims


def test_a_tampered_payload_is_rejected():
    """Swap the subject, keep the signature — the impersonation this state
    parameter exists to stop, and the case the old single mutation never
    exercised on any run, since it only ever touched the signature."""
    clock = _FixedClock(datetime.now(UTC))
    signer = _signer(clock)
    state = signer.sign("user-1")

    header, _, signature = state.split(".")
    claims = _claims_of(state)
    claims["sub"] = "attacker"
    forged_payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()

    _assert_rejected_as_tampered(signer, state, f"{header}.{forged_payload}.{signature}")


def test_a_signature_made_with_a_different_key_is_rejected():
    """Identical claims, attacker's key — the forgery a shared-secret HMAC
    exists to detect. Deterministic by construction: a different key cannot
    produce the same signature, so there is no padding-bit trap to fall into."""
    clock = _FixedClock(datetime.now(UTC))
    signer = _signer(clock)
    state = signer.sign("user-1")

    forged = GitHubOAuthStateSigner(
        secret_key="a-different-secret-that-is-32-b!",
        algorithm="HS256",
        expires_minutes=10,
        clock=clock,
    ).sign("user-1")

    _assert_rejected_as_tampered(signer, state, forged)


@pytest.mark.parametrize("algorithm", ["none", "HS512"])
def test_a_swapped_algorithm_is_rejected(algorithm: str):
    """`verify` pins `algorithms=[self._algorithm]`. `none` is the classic
    signature-stripping attack; `HS512` proves the pin is to one algorithm
    rather than to a family that happens to share a secret.

    Uses a 64-byte secret on *both* sides, unlike every other test here. The
    key has to be identical to the signer's or this would prove only that a
    wrong key is rejected — which is the previous test — instead of that the
    algorithm alone is. 64 bytes because PyJWT warns below RFC 7518's minimum
    for SHA-512, and a security test file should not be emitting an
    insecure-key warning of its own making.
    """
    secret = "s" * 64
    clock = _FixedClock(datetime.now(UTC))
    signer = GitHubOAuthStateSigner(
        secret_key=secret, algorithm="HS256", expires_minutes=10, clock=clock
    )
    state = signer.sign("user-1")

    swapped = jwt.encode(
        _claims_of(state), "" if algorithm == "none" else secret, algorithm=algorithm
    )

    _assert_rejected_as_tampered(signer, state, swapped)


@pytest.mark.parametrize("mode", ["signature-dropped", "signature-shortened"])
def test_a_truncated_state_is_rejected(mode: str):
    """A JWT missing or short of its signature must not decode as valid."""
    clock = _FixedClock(datetime.now(UTC))
    signer = _signer(clock)
    state = signer.sign("user-1")

    truncated = state.rsplit(".", 1)[0] if mode == "signature-dropped" else state[:-8]

    _assert_rejected_as_tampered(signer, state, truncated)


def test_expired_state_is_rejected():
    # jwt.decode checks `exp` against real wall-clock time, so build an
    # already-expired token directly rather than relying on a fake clock.
    now = datetime(2026, 1, 1, tzinfo=UTC)
    signer = _signer(_FixedClock(now))
    expired_token = jwt.encode(
        {
            "sub": "user-1",
            "purpose": "github_oauth_state",
            "iat": now,
            "exp": now - timedelta(minutes=1),
        },
        "test-secret-that-is-32-bytes-long",
        algorithm="HS256",
    )

    with pytest.raises(InvalidOAuthState):
        signer.verify(expired_token)


def test_state_with_wrong_purpose_claim_is_rejected():
    now = datetime(2026, 1, 1, tzinfo=UTC)
    signer = _signer(_FixedClock(now))

    wrong_purpose_token = jwt.encode(
        {
            "sub": "user-1",
            "purpose": "something_else",
            "iat": now,
            "exp": now + timedelta(minutes=10),
        },
        "test-secret-that-is-32-bytes-long",
        algorithm="HS256",
    )

    with pytest.raises(InvalidOAuthState):
        signer.verify(wrong_purpose_token)


def _validly_signed(claims: dict[str, object]) -> str:
    # Real wall-clock exp — verify() checks expiry against real time, same
    # reason test_sign_and_verify_round_trip uses a real-now clock.
    now = datetime.now(UTC)
    return jwt.encode(
        {"purpose": "github_oauth_state", "iat": now, "exp": now + timedelta(minutes=10), **claims},
        "test-secret-that-is-32-bytes-long",
        algorithm="HS256",
    )


def test_state_with_no_subject_is_rejected():
    # Reachable with a real token: PyJWT accepts a payload with no `sub` at all,
    # so this previously raised KeyError rather than InvalidOAuthState.
    signer = _signer(_FixedClock(datetime.now(UTC)))

    with pytest.raises(InvalidOAuthState):
        signer.verify(_validly_signed({}))


def test_a_non_string_subject_is_rejected_even_if_pyjwt_lets_one_through(monkeypatch):
    # Same shape as JwtAccessTokenIssuer's equivalent test, same reasoning:
    # PyJWT 2.13 already rejects a non-str `sub`, so stubbing decode is the only
    # way to reach our own narrowing. Kept as defense in depth because this
    # `sub` is the user identity the OAuth callback resolves against.
    signer = _signer(_FixedClock(datetime.now(UTC)))
    monkeypatch.setattr(jwt, "decode", lambda *a, **kw: {"sub": 12345, "purpose": _PURPOSE})

    with pytest.raises(InvalidOAuthState):
        signer.verify("irrelevant-the-decode-is-stubbed")
