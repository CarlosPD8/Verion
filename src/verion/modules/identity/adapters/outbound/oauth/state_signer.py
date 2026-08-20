from datetime import timedelta

import jwt

from verion.modules.identity.domain.exceptions import InvalidOAuthState
from verion.shared_kernel.ports import ClockPort

_PURPOSE = "github_oauth_state"


class GitHubOAuthStateSigner:
    def __init__(
        self, secret_key: str, algorithm: str, expires_minutes: int, clock: ClockPort
    ) -> None:
        self._secret_key = secret_key
        self._algorithm = algorithm
        self._expires_minutes = expires_minutes
        self._clock = clock

    def sign(self, user_id: str) -> str:
        now = self._clock.now()
        return jwt.encode(
            {
                "sub": user_id,
                "purpose": _PURPOSE,
                "iat": now,
                "exp": now + timedelta(minutes=self._expires_minutes),
            },
            self._secret_key,
            algorithm=self._algorithm,
        )

    def verify(self, state: str) -> str:
        try:
            payload = jwt.decode(state, self._secret_key, algorithms=[self._algorithm])
        except jwt.InvalidTokenError as exc:
            raise InvalidOAuthState("OAuth state is malformed, invalid, or expired") from exc

        if payload.get("purpose") != _PURPOSE:
            raise InvalidOAuthState("OAuth state has the wrong purpose claim")

        # Runtime check rather than a cast — same reasoning as
        # JwtAccessTokenIssuer.decode: this `sub` is the user identity the OAuth
        # callback resolves the connection against, so it's a security control
        # and not a typing formality, regardless of the signature and purpose
        # claim already being verified above.
        subject = payload.get("sub")
        if not isinstance(subject, str):
            raise InvalidOAuthState("OAuth state is malformed, invalid, or expired")
        return subject
