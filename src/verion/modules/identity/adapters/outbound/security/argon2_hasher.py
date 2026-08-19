from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# Sync is deliberate: Argon2 hashing is CPU-bound, not I/O-bound, so it isn't
# subject to the async-by-default rule for outbound ports (CLAUDE.md rule 7).
# Revisit with FastAPI's run_in_threadpool if concurrent load becomes a real
# concern — out of scope for MVP.


class Argon2PasswordHasher:
    def __init__(self) -> None:
        self._hasher = PasswordHasher()

    def hash(self, plaintext_password: str) -> str:
        return self._hasher.hash(plaintext_password)

    def verify(self, plaintext_password: str, hashed_password: str) -> bool:
        try:
            return self._hasher.verify(hashed_password, plaintext_password)
        except VerifyMismatchError:
            return False
