from datetime import UTC, datetime, timedelta

import jwt
import pytest

from verion.modules.identity.adapters.outbound.security.jwt_issuer import JwtAccessTokenIssuer
from verion.modules.identity.domain.exceptions import InvalidAccessToken


class _FixedClock:
    def __init__(self, now: datetime) -> None:
        self._now = now

    def now(self) -> datetime:
        return self._now


def _issuer(expires_minutes: int = 30) -> tuple[JwtAccessTokenIssuer, datetime]:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    issuer = JwtAccessTokenIssuer(
        secret_key="test-secret-that-is-32-bytes-long",
        algorithm="HS256",
        expires_minutes=expires_minutes,
        clock=_FixedClock(now),
    )
    return issuer, now


def test_issue_and_decode_round_trip():
    issuer, now = _issuer()

    token = issuer.issue(subject="user-123")
    # verify_exp=False: this test only checks the round-trip of the claim
    # itself. Real wall-clock time is later than the fixed test clock, so
    # the token would otherwise look expired — expiry behavior is checked
    # separately in test_expiry_matches_configured_minutes.
    decoded = jwt.decode(
        token.value,
        "test-secret-that-is-32-bytes-long",
        algorithms=["HS256"],
        options={"verify_exp": False},
    )

    assert decoded["sub"] == "user-123"


def test_expiry_matches_configured_minutes():
    issuer, now = _issuer(expires_minutes=45)

    token = issuer.issue(subject="user-123")

    assert token.expires_at == now + timedelta(minutes=45)


def test_decoding_with_the_wrong_secret_fails():
    issuer, _ = _issuer()
    token = issuer.issue(subject="user-123")

    try:
        jwt.decode(token.value, "wrong-secret", algorithms=["HS256"])
        raised = False
    except jwt.InvalidSignatureError:
        raised = True

    assert raised


def _validly_signed(claims: dict[str, object]) -> str:
    # Real wall-clock exp, not the fixed test clock: decode() verifies expiry
    # against real time, so a token built off _issuer's 2026-01-01 clock would
    # be rejected as expired before reaching the check under test.
    now = datetime.now(UTC)
    return jwt.encode(
        {"iat": now, "exp": now + timedelta(minutes=30), **claims},
        "test-secret-that-is-32-bytes-long",
        algorithm="HS256",
    )


def test_a_validly_signed_token_with_no_subject_is_rejected():
    # Reachable with a real token: PyJWT accepts a payload with no `sub` at all
    # (it only validates the claim when present). Previously this was a KeyError
    # escaping as an unhandled 500 instead of a 401.
    issuer, _ = _issuer()

    with pytest.raises(InvalidAccessToken):
        issuer.decode(_validly_signed({}))


def test_a_non_string_subject_is_rejected_even_if_pyjwt_lets_one_through(monkeypatch):
    # Defense in depth, and deliberately not reachable with a real token today:
    # PyJWT 2.13 rejects a non-str `sub` itself (InvalidSubjectError, a subclass
    # of InvalidTokenError caught by decode's existing handler). Stubbing decode
    # out is the only way to exercise OUR narrowing rather than PyJWT's.
    #
    # This layer earns its place because `sub` becomes the user_id every
    # downstream permission check resolves against — it must not depend on a
    # third party continuing to validate a claim it is not contractually
    # required to. If PyJWT ever relaxes this, the guard is already here.
    issuer, _ = _issuer()
    monkeypatch.setattr(jwt, "decode", lambda *a, **kw: {"sub": 12345})

    with pytest.raises(InvalidAccessToken):
        issuer.decode("irrelevant-the-decode-is-stubbed")
