from datetime import timedelta

import jwt

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
