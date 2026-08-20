from datetime import timedelta

import jwt

from verion.modules.identity.domain.exceptions import InvalidAccessToken
from verion.modules.identity.ports.access_token_issuer import AccessToken
from verion.shared_kernel.ports import ClockPort

# Sync is deliberate — see access_token_issuer.py's port-level comment.


class JwtAccessTokenIssuer:
    def __init__(
        self, secret_key: str, algorithm: str, expires_minutes: int, clock: ClockPort
    ) -> None:
        self._secret_key = secret_key
        self._algorithm = algorithm
        self._expires_minutes = expires_minutes
        self._clock = clock

    def issue(self, subject: str) -> AccessToken:
        now = self._clock.now()
        expires_at = now + timedelta(minutes=self._expires_minutes)

        token = jwt.encode(
            {"sub": subject, "iat": now, "exp": expires_at},
            self._secret_key,
            algorithm=self._algorithm,
        )
        return AccessToken(value=token, expires_at=expires_at)

    def decode(self, token: str) -> str:
        try:
            payload = jwt.decode(token, self._secret_key, algorithms=[self._algorithm])
        except jwt.InvalidTokenError as exc:
            raise InvalidAccessToken("Access token is malformed, invalid, or expired") from exc
        # Runtime check rather than a cast, even though issue() above is the
        # only writer of `sub` and always writes a str: this value becomes the
        # user_id every downstream permission check resolves against, so it's a
        # security control, not a typing formality. A cast asserts an invariant
        # that holds by our own convention today; this holds regardless of a
        # future PyJWT change or a token-generation bug. Same reasoning as
        # SystemDnsResolver narrowing its resolved IPs for ADR-013's gate.
        # Also closes a latent KeyError on a signed token with no `sub` at all.
        subject = payload.get("sub")
        if not isinstance(subject, str):
            raise InvalidAccessToken("Access token is malformed, invalid, or expired")
        return subject
