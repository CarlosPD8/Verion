from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

# Deliberately separate from AuthenticateUserUseCase: authentication (verifying
# credentials) and session representation (how that identity is carried on
# future requests) are distinct concerns. Coupling them would force every
# future consumer of AuthenticateUserUseCase (e.g. a password-change flow
# re-verifying current credentials) to depend on JWT issuance even when it
# doesn't need a token. The login route composes the two itself.
#
# Sync, not async: JWT signing is local/CPU-bound (like Argon2 hashing),
# not I/O-bound, so it isn't subject to the async-by-default rule for
# outbound ports (CLAUDE.md rule 7).


@dataclass(frozen=True)
class AccessToken:
    value: str
    expires_at: datetime


class AccessTokenIssuer(Protocol):
    def issue(self, subject: str) -> AccessToken: ...

    def decode(self, token: str) -> str:
        """Return the subject encoded in `token`. Raises InvalidAccessToken
        (identity/domain/exceptions.py) if the token is malformed, has a
        bad signature, or has expired."""
        ...
