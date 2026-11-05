"""Durable, hashed per-scan access credentials.

Kept in a separate table so existing SQLite/PostgreSQL `scans` schemas
do not require an ALTER TABLE to introduce owner authorization.
"""
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.sql import func
from app.models.base import Base


class ScanAccess(Base):
    __tablename__ = "scan_access"

    scan_id = Column(
        Integer, ForeignKey("scans.id", ondelete="CASCADE"),
        primary_key=True, nullable=False
    )
    token_sha256 = Column(String(64), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
