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
                "evidence_json": {"expires_at": expires_at.isoformat(), "remaining_days": remaining_days},
                "recommendation": "Renew the TLS certificate immediately."
            })
        elif remaining_days <= 15:
            findings.append({
                "category": "ssl",
                "severity": "high",
                "title": "SSL certificate expiring soon",
                "description": "The TLS certificate will expire soon.",
                "evidence_json": {"expires_at": expires_at.isoformat(), "remaining_days": remaining_days},
                "recommendation": "Schedule the certificate renewal now."
            })

    except Exception as e:
        findings.append({
            "category": "ssl",
            "severity": "high",
            "title": "SSL/TLS validation failed",
            "description": "The scan could not validate the TLS certificate correctly.",
            "evidence_json": {"error": str(e)},
            "recommendation": "Verify that HTTPS is active and correctly configured."
        })

    return findings