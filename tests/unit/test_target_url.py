import pytest

from verion.modules.scanning.domain.exceptions import UnsafeDastTarget
from verion.modules.scanning.domain.target_url import (
    validate_resolved_ips_are_public,
    validate_target_url_syntax,
)


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/app",
        "http://example.com:8080/app",
        "https://sub.example.com/",
    ],
)
def test_accepts_a_legitimate_public_looking_url(url: str):
    validate_target_url_syntax(url)


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "ftp://example.com/app",
        "git://example.com/app",
        "http://localhost/app",
        "http://localhost./app",
        "https://user:pass@example.com/app",
        "https://evil.com@example.com/app",
        # IPv4: loopback, private, link-local
        "http://127.0.0.1/app",
        "http://10.0.0.5/app",
        "http://192.168.1.1/app",
        "http://172.16.0.1/app",
        "http://169.254.169.254/app",
        # IPv6: loopback, private (ULA), link-local - bracketed URL form
        "http://[::1]/app",
        "http://[fc00::1]/app",
        "http://[fe80::1]/app",
    ],
)
def test_rejects_unsafe_or_malformed_urls(url: str):
    with pytest.raises(UnsafeDastTarget):
        validate_target_url_syntax(url)


@pytest.mark.parametrize(
    "url",
    [
        "https://admin:hunter2@example.com/app",
        # Credential-bearing AND wrong-scheme. This is the case branch ordering
        # decides: the scheme branch quotes the whole URL, so if it ran first
        # the password would be in the message.
        "ftp://admin:hunter2@example.com/app",
        "http://admin:hunter2@127.0.0.1/app",
        "http://admin:hunter2@localhost/app",
    ],
)
def test_no_rejection_message_ever_echoes_a_credential(url: str):
    """Rule 12, and the reason the userinfo check is the first branch.

    Since M3.7 this exception's text can be persisted — RunScanUseCase writes a
    failed scanner's exception into ScanResult.failure_reason — so a message
    that quotes a `user:pass@host` URL back puts a credential in the database.
    Every other branch is free to quote the URL only because the userinfo
    branch has already run; this pins that ordering so a later reshuffle fails
    here rather than silently.
    """
    with pytest.raises(UnsafeDastTarget) as exc_info:
        validate_target_url_syntax(url)

    assert "hunter2" not in str(exc_info.value)
    assert url not in str(exc_info.value)


def test_accepts_all_public_resolved_ips():
    validate_resolved_ips_are_public(["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"])


@pytest.mark.parametrize(
    "ips",
    [
        ["127.0.0.1"],
        ["10.0.0.5"],
        ["169.254.169.254"],
        ["93.184.216.34", "192.168.1.1"],
        ["::1"],
        ["fc00::1"],
    ],
)
def test_rejects_any_private_or_loopback_resolved_ip(ips: list[str]):
    with pytest.raises(UnsafeDastTarget):
        validate_resolved_ips_are_public(ips)
