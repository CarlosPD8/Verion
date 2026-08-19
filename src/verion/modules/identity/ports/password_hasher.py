from typing import Protocol

# Concrete adapter: Argon2PasswordHasher (argon2-cffi), added in M1.2 alongside
# the Postgres adapter — verified against PyPI per ADR-009 (maintained by
# hynek, not passlib, which has reduced maintenance activity).


class PasswordHasherPort(Protocol):
    def hash(self, plaintext_password: str) -> str: ...

    def verify(self, plaintext_password: str, hashed_password: str) -> bool: ...
