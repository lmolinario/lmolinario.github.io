"""Owner-bound scan access with no live network or payment services."""
import hashlib
from secrets import token_urlsafe

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.models.base import Base
from app.models.scan import Scan
from app.models.scan_access import ScanAccess
from app.security.scan_access import mint_scan_token, require_owned_scan


@pytest.fixture
def session():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        yield db
    engine.dispose()


def make_scan(db):
    scan = Scan(domain="example.com", status="completed")
    db.add(scan)
    db.commit()
    return scan


def test_random_credential_stored_only_as_hash(session):
    scan = make_scan(session)
    token = mint_scan_token(session, scan.id)
    stored = session.get(ScanAccess, scan.id)
    assert len(token) >= 32
    assert stored.token_sha256 == hashlib.sha256(token.encode()).hexdigest()
    assert token not in stored.token_sha256
    assert require_owned_scan(session, scan.id, token).id == scan.id


@pytest.mark.parametrize("bad", [None, "", "invalid", "x" * 300])
def test_missing_or_invalid_credentials_are_rejected(session, bad):
    scan = make_scan(session)
    mint_scan_token(session, scan.id)
    with pytest.raises(HTTPException) as exc:
        require_owned_scan(session, scan.id, bad)
    assert exc.value.status_code == 404


def test_cross_scan_access_is_denied(session):
    a, b = make_scan(session), make_scan(session)
    token_a = mint_scan_token(session, a.id)
    token_b = mint_scan_token(session, b.id)
    assert require_owned_scan(session, b.id, token_b).id == b.id
    with pytest.raises(HTTPException) as exc:
        require_owned_scan(session, b.id, token_a)
    assert exc.value.status_code == 404


def test_legacy_scan_without_credential_is_not_public(session):
    legacy = make_scan(session)
    with pytest.raises(HTTPException) as exc:
        require_owned_scan(session, legacy.id, token_urlsafe(32))
    assert exc.value.status_code == 404
