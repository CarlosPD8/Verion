from uuid import uuid4


class UuidIdGenerator:
    def new_id(self) -> str:
        return str(uuid4())
