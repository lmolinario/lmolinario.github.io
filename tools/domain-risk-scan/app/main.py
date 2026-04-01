from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware

from app.core.database import Base, engine
from app.api.routes_scan import router as scan_router
from app.api.routes_billing import router as billing_router
from app.api.routes_reports import router as reports_router
from app.api.routes_pdf import router as pdf_router

from app.models.scan import Scan
from app.models.finding import Finding
from app.models.report import Report
from app.models.analytics_event import AnalyticsEvent
from app.api.routes_analytics import router as analytics_router

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Digital Risk Scanner")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://lmolinario.github.io",
        "http://localhost:5500",
        "http://127.0.0.1:5500",
    ],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

templates = Jinja2Templates(directory="templates")

app.include_router(scan_router)
app.include_router(billing_router)
app.include_router(reports_router)
app.include_router(pdf_router)
app.include_router(analytics_router)

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse(request, "index.html")