import asyncio
import socket


class SystemDnsResolver:
    async def resolve(self, hostname: str) -> list[str]:
        # loop.getaddrinfo is async-native (delegates internally, unlike a
        # hand-rolled asyncio.to_thread(socket.getaddrinfo, ...) wrapper) and
        # resolves both A and AAAA records via AF_UNSPEC.
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(hostname, None, family=socket.AF_UNSPEC)
        # sockaddr is (ip, port) for IPv4 and (ip, port, flowinfo, scopeid)
        # for IPv6 — the ip is always element 0 either way. typeshed types
        # sockaddr as a union that also covers AF_PACKET's (int, bytes), so
        # element 0 widens to `str | int`. AF_UNSPEC over a hostname cannot
        # produce that variant, but this list feeds ADR-013's SSRF gate: an
        # int reaching validate_resolved_ips_are_public would fail its
        # ip_address() parse rather than being screened, so narrow explicitly
        # here instead of casting the check away.
        ips = {ip for info in infos if isinstance(ip := info[4][0], str)}
        return list(ips)
