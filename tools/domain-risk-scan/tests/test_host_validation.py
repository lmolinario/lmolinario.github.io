"""Offline unit tests for outbound target validation."""
import socket
from unittest.mock import patch

import pytest

from app.utils.validators import (
    is_valid_domain,
    is_safe_external_domain,
    normalize_domain,
    safe_tls_addresses,
)


def info(ip):
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    return (family, socket.SOCK_STREAM, 6, "", (ip, 443))


@pytest.mark.parametrize("host", ["example.com", "sub.example.org", "xn--bcher-kva.de"])
def test_valid_domains(host):
    assert is_valid_domain(host)


@pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "example.com.evil-", "evil..com", "foo.local"])
def test_invalid_domains(host):
    assert not is_valid_domain(host)


def test_normalize_userinfo_not_accepted():
    assert normalize_domain("https://user:password@example.com/") == ""


def test_normalize_browser_input():
    assert normalize_domain("https://WWW.EXAMPLE.COM/path") == "www.example.com"


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.2", "169.254.169.254", "192.168.1.3", "::1", "fe80::1", "100.64.0.1"])
def test_private_or_reserved_targets_are_blocked(ip):
    with patch("socket.getaddrinfo", return_value=[info(ip)]):
        assert not is_safe_external_domain("example.com")
        with pytest.raises(ValueError):
            safe_tls_addresses("example.com")


def test_mixed_public_private_targets_are_rejected():
    with patch("socket.getaddrinfo", return_value=[info("8.8.8.8"), info("127.0.0.1")]):
        assert not is_safe_external_domain("example.com")


def test_only_public_addresses_pass():
    with patch("socket.getaddrinfo", return_value=[info("8.8.8.8"), info("1.1.1.1")]):
        assert is_safe_external_domain("example.com")
        assert len(safe_tls_addresses("example.com")) == 2
