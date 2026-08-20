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
        # for IPv6 — the ip is always element 0 either way.
        ips = {info[4][0] for info in infos}
        return list(ips)
