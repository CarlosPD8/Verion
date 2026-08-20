import ipaddress
from urllib.parse import urlparse

from verion.modules.scanning.domain.exceptions import UnsafeDastTarget

# Hostnames that mean "this machine" without ever needing DNS resolution to
# prove it - rejected outright, independent of the resolved-IP check below.
_LOCALHOST_HOSTNAMES = {"localhost", "localhost."}


def validate_target_url_syntax(url: str) -> None:
    """Rejects a DAST target URL on syntax alone, before any DNS resolution.

    This is the pure half of the SSRF gate (mirrors parse_github_clone_url's
    pure-validation role for repo URLs): scheme restricted to http/https,
    userinfo-in-URL tricks rejected, and a hostname that is itself a literal
    IP address (v4 or v6, including the bracketed "[::1]" URL form - urlparse
    strips the brackets into `.hostname` automatically) checked against the
    same private/loopback/link-local/reserved ranges as the resolved-IP
    check. A hostname that is a genuine DNS name (not a literal IP) is not
    fully safe yet - it still has to be resolved and the RESOLVED IP checked
    (see validate_resolved_ips_are_public), because a hostname string looking
    external proves nothing on its own: that is exactly the DNS-rebinding gap
    this two-step design closes.
    """
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise UnsafeDastTarget(f"'{url}' must use http or https, not '{parsed.scheme}'")

    if parsed.username is not None or parsed.password is not None:
        raise UnsafeDastTarget(f"'{url}' must not contain userinfo (user:pass@host)")

    hostname = parsed.hostname
    if not hostname:
        raise UnsafeDastTarget(f"'{url}' has no resolvable hostname")

    if hostname in _LOCALHOST_HOSTNAMES:
        raise UnsafeDastTarget(f"'{url}' targets localhost, which is never a valid DAST target")

    try:
        literal_ip = ipaddress.ip_address(hostname)
    except ValueError:
        # Not an IP literal - a genuine DNS name, deferred to the resolved-IP
        # check once it's been looked up.
        return

    if _is_unsafe_ip(literal_ip):
        raise UnsafeDastTarget(f"'{url}' resolves to a disallowed IP range: {literal_ip}")


def validate_resolved_ips_are_public(ips: list[str]) -> None:
    """The DNS-rebinding gate: validates the IPs a hostname ACTUALLY resolved
    to, not just the hostname string. A hostname can pass syntax validation
    and still resolve to an internal address - this is the check that
    catches it, and it must run after every DNS resolution, immediately
    before the target is ever used, not just once at input time.
    """
    for ip in ips:
        if _is_unsafe_ip(ipaddress.ip_address(ip)):
            raise UnsafeDastTarget(f"resolved IP '{ip}' is in a disallowed range")


def _is_unsafe_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )
