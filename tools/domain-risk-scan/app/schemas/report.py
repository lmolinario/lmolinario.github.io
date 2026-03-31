from pydantic import BaseModel


class CheckoutCreateRequest(BaseModel):
    scan_id: int


class CheckoutCreateResponse(BaseModel):
    checkout_url: str


class ReportResponse(BaseModel):
    scan_id: int
    domain: str
    score: int | None
    is_paid: bool
    is_locked: bool
    summary: dict | None

    risk_level: str | None = None
    severity_breakdown: dict | None = None
    top_issue_title: str | None = None
    priority_actions: list[str] = []
    key_observations: list[str] = []
    scan_completed_at: str | None = None

    ai_top_risk_message: str | None = None
    ai_teaser_summary: str | None = None
    ai_executive_summary: str | None = None
    ai_remediation_plan: str | None = None

    findings: list[dict]
    pdf_url: str | None = None

    immediate_actions: list[str] = []
    important_improvements: list[str] = []
    monitoring_recommendations: list[str] = []
