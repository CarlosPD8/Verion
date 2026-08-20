from typing import Protocol


class DnsResolverPort(Protocol):
    async def resolve(self, hostname: str) -> list[str]:
        """Resolves hostname to its IP addresses. Genuine I/O - kept out of
        domain/ so target_url.py's validation logic stays unit-testable
        without a real network call.
        """
        ...
