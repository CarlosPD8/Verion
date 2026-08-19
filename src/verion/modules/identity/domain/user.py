import re
from dataclasses import dataclass
from datetime import datetime

from verion.modules.identity.domain.exceptions import InvalidEmail

_EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@dataclass(frozen=True)
class Email:
    value: str

    def __post_init__(self) -> None:
        if not _EMAIL_PATTERN.match(self.value):
            raise InvalidEmail(f"'{self.value}' is not a valid email address")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class User:
    id: str
    email: Email
    hashed_password: str
    created_at: datetime
