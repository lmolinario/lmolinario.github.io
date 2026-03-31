from pydantic import BaseModel, Field
from typing import Optional, Any


class ScanCreate(BaseModel):
    domain: str = Field(..., min_length=3, max_length=255)


class ScanCreateResponse(BaseModel):
    scan_id: int
    status: str
    cached: bool = False


class ScanStatusResponse(BaseModel):
    scan_id: int
    domain: str
    status: str
    score: Optional[int] = None
    summary: Optional[Any] = None
    risk_level: Optional[str] = None


class FindingResponse(BaseModel):
    id: int
    category: str
    severity: str
    title: str
    description: str
    evidence_json: Optional[Any] = None
    recommendation: Optional[str] = None


class FindingsListResponse(BaseModel):
    scan_id: int
    domain: str
    findings: list[FindingResponse]