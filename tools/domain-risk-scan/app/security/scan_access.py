"""Opaque bearer authorization for a specific scan.

Do not transmit secrets in paths, query strings, analytics or logging.
"""
import hashlib
import hmac
import secrets

from fastapi import Header, HTTPException
from sqlalchemy.orm import Session

from app.models.scan import Scan
from app.models.scan_access import ScanAccess


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def mint_scan_token(db: Session, scan_id: int) -> str:
    """Create and persist one unguessable bearer credential per new scan."""
    token = secrets.token_urlsafe(32)
    db.add(ScanAccess(scan_id=scan_id, token_sha256=_hash_token(token)))
    db.commit()
    return token


def require_owned_scan(
    db: Session, scan_id: int, supplied_token: str | None
) -> Scan:
    """Identical 404 on unknown scan, missing/invalid token or legacy scan."""
    if not supplied_token or len(supplied_token) > 256:
        raise HTTPException(status_code=404, detail="Scan not found")
    access = db.get(ScanAccess, scan_id)
    if access is None or not hmac.compare_digest(
        _hash_token(supplied_token), access.token_sha256
    ):
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


def scan_token_header(
    x_scan_token: str | None = Header(default=None, alias="X-Scan-Token"),
) -> str | None:
    return x_scan_token
