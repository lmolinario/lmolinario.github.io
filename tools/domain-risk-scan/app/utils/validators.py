"""Host validation for the passive external-domain assessment.

A syntactically valid DNS name is not sufficient for a safe outbound TLS
connection. Public destination checks are repeated at connection time.
"""
import ipaddress
import re
import socket
from urllib.parse import urlsplit


DOMAIN_REGEX = re.compile(
    r"^(?=.{4,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
)


def normalize_domain(domain: str) -> str:
    value = domain.strip()
    if not value:
        return ""
    try:
        url = urlsplit(value if "://" in value else "https://" + value)
        if url.scheme not in {"http", "https"} or url.username or url.password:
            return ""
        hostname = (url.hostname or "").rstrip(".")
        hostname = hostname.encode("idna").decode("ascii").lower()
        return hostname
    except (ValueError, UnicodeError):
        return ""


def is_valid_domain(domain: str) -> bool:
    return bool(DOMAIN_REGEX.fullmatch(domain)) and not domain.endswith((".local", ".localhost", ".internal", ".test", ".invalid", ".lan", ".home.arpa"))


def safe_tls_addresses(domain: str, port: int = 443) -> list[tuple]:
    """Resolve and return only globally routable endpoints.

    Reject the *whole* result if even one private, loopback, link-local,
    reserved or otherwise non-global address was returned. The scanner
    must connect to one of these resolved socket addresses, not resolve
    the hostname a second time after validation.
    """
    addresses = socket.getaddrinfo(domain, port, type=socket.SOCK_STREAM)
    if not addresses:
        raise ValueError("Domain has no routable addresses")
    if any(not ipaddress.ip_address(info[4][0]).is_global for info in addresses):
        raise ValueError("Domain resolves to a non-public address")
    return addresses


def is_safe_external_domain(domain: str) -> bool:
    """An unresolved name is allowed for DNS-quality reporting only."""
    try:
        safe_tls_addresses(domain)
    except socket.gaierror:
        return True
    except (ValueError, OSError):
        return False
    return True
