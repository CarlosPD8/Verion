from verion.modules.identity.domain.exceptions import InvalidCredentials
from verion.modules.identity.domain.user import User
from verion.modules.identity.ports.password_hasher import PasswordHasherPort
from verion.modules.identity.ports.user_repository import UserRepositoryPort

# MVP: returns the authenticated User only; does not mint an access token.
# Token issuance (PyJWT, access-token-only, no refresh-token flow — a
# deliberate MVP simplification, not an oversight) happens at the API layer
# in M1.2, once the login route exists.


class AuthenticateUserUseCase:
    def __init__(self, users: UserRepositoryPort, password_hasher: PasswordHasherPort) -> None:
        self._users = users
        self._password_hasher = password_hasher

    def execute(self, email: str, plaintext_password: str) -> User:
        user = self._users.get_by_email(email)

        if user is None or not self._password_hasher.verify(
            plaintext_password, user.hashed_password
        ):
            # Deliberately generic: don't reveal whether the email exists.
            raise InvalidCredentials("Invalid email or password")

        return user
