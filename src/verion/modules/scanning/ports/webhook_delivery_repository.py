from typing import Protocol


class WebhookDeliveryRepositoryPort(Protocol):
    async def record_if_new(self, delivery_id: str) -> bool:
        """Records delivery_id and returns True if it hadn't been seen
        before, False if it had (a GitHub redelivery of the same event).

        Must be race-safe under concurrent redelivery — implementations
        enforce this via a DB unique constraint, not check-then-act.
        """
        ...
