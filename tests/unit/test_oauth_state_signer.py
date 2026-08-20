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


def test_tampered_state_is_rejected():
    clock = _FixedClock(datetime.now(UTC))
    signer = _signer(clock)
    state = signer.sign("user-1")

    tampered = state[:-1] + ("A" if state[-1] != "A" else "B")

    with pytest.raises(InvalidOAuthState):
        signer.verify(tampered)


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
