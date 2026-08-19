from datetime import UTC, datetime, timedelta

import jwt
import pytest

from verion.modules.identity.adapters.outbound.oauth.state_signer import GitHubOAuthStateSigner
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
