import socket
import ssl
from datetime import datetime, timezone


def scan_ssl(domain: str) -> list[dict]:
    findings = []

    try:
        context = ssl.create_default_context()

        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        not_after = cert.get("notAfter")
        expires_at = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        remaining_days = (expires_at - datetime.now(timezone.utc)).days

        if remaining_days < 0:
            findings.append({
                "category": "ssl",
                "severity": "critical",
                "title": "SSL certificate expired",
                "description": "The domain's TLS certificate is expired.",
                "evidence_json": {
                    "expires_at": expires_at.isoformat(),
                    "remaining_days": remaining_days,
                    "check_type": "ssl_expired",
                    "scan_quality": "complete",
                },
                "recommendation": "Renew the TLS certificate immediately."
            })
        elif remaining_days <= 15:
            findings.append({
                "category": "ssl",
                "severity": "high",
                "title": "SSL certificate expiring soon",
                "description": "The TLS certificate will expire soon.",
                "evidence_json": {
                    "expires_at": expires_at.isoformat(),
                    "remaining_days": remaining_days,
                    "check_type": "ssl_expiring_soon",
                    "scan_quality": "complete",
                },
                "recommendation": "Schedule the certificate renewal now."
            })

    except ssl.SSLError as e:
        findings.append({
            "category": "ssl",
            "severity": "medium",
            "title": "TLS handshake validation failed",
            "description": "The scan reached the HTTPS service but could not complete a valid TLS handshake.",
            "evidence_json": {
                "error": str(e),
                "check_type": "ssl_handshake_failed",
                "scan_quality": "partial",
            },
            "recommendation": "Verify certificate configuration, hostname binding, and protocol compatibility."
        })

    except (socket.timeout, TimeoutError) as e:
        findings.append({
            "category": "scanner",
            "severity": "info",
            "title": "HTTPS validation timed out",
            "description": "The HTTPS check did not complete within the expected time window.",
            "evidence_json": {
                "error": str(e),
                "check_type": "ssl_timeout",
                "scan_quality": "partial",
            },
            "recommendation": "Repeat the HTTPS validation and verify service reachability."
        })

    except ConnectionRefusedError as e:
        findings.append({
            "category": "ssl",
            "severity": "low",
            "title": "HTTPS service unavailable on port 443",
            "description": "The domain did not accept a TLS connection on port 443 during the scan.",
            "evidence_json": {
                "error": str(e),
                "check_type": "ssl_connection_refused",
                "scan_quality": "partial",
            },
            "recommendation": "If HTTPS is expected, verify that the service is listening on port 443 and exposed correctly."
        })

    except OSError as e:
        findings.append({
            "category": "scanner",
            "severity": "info",
            "title": "HTTPS validation incomplete",
            "description": "The HTTPS check could not be completed due to a network or socket-level error.",
            "evidence_json": {
                "error": str(e),
                "check_type": "ssl_transport_error",
                "scan_quality": "partial",
            },
            "recommendation": "Repeat the scan and verify external reachability of the HTTPS service."
        })

    return findings