from datetime import datetime
from typing import Protocol


class ClockPort(Protocol):
    def now(self) -> datetime: ...


class IdGeneratorPort(Protocol):
    def new_id(self) -> str: ...
