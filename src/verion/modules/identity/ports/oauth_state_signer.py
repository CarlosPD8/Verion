from typing import Protocol

# Deliberately separate from AccessTokenIssuer: an OAuth CSRF state value and
# an API access credential are different things with different expiry needs
# (minutes, not the configured access-token lifetime) — a leaked state value
# should never double as a bearer token. Same secret/algorithm as
# AccessTokenIssuer (both reuse settings.jwt_secret_key/jwt_algorithm — this
# is what "HMAC using existing JWT secret infrastructure" means), but its own
# short-lived, purpose-tagged payload so the two can never be confused or
# replayed as each other.
#
# Sync, not async — local computation, same rule 7 carve-out as
# AccessTokenIssuer/PasswordHasherPort.


class OAuthStateSignerPort(Protocol):
    def sign(self, user_id: str) -> str: ...

    def verify(self, state: str) -> str:
        """Return the user_id encoded in `state`. Raises InvalidOAuthState
        (identity/domain/exceptions.py) if tampered, expired, or missing the
        expected purpose claim."""
        ...
