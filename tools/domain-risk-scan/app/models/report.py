from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, JSON
from sqlalchemy.sql import func
from app.models.base import Base


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True, unique=True)

    is_paid = Column(Boolean, nullable=False, default=False)
    stripe_session_id = Column(String(255), nullable=True, index=True)
    stripe_payment_status = Column(String(50), nullable=True)

    unlocked_at = Column(DateTime(timezone=True), nullable=True)
    pdf_path = Column(String(500), nullable=True)
    full_report_json = Column(JSON, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)