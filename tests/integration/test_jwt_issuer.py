from datetime import UTC, datetime, timedelta

import jwt

from verion.modules.identity.adapters.outbound.security.jwt_issuer import JwtAccessTokenIssuer


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
