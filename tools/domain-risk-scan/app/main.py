from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware

from app.core.database import Base, engine
from app.api.routes_scan import router as scan_router
from app.api.routes_billing import router as billing_router
from app.api.routes_reports import router as reports_router
from app.api.routes_pdf import router as pdf_router
from app.api.routes_analytics import router as analytics_router

from app.models.scan import Scan
from app.models.scan_access import ScanAccess
from app.models.finding import Finding
from app.models.report import Report
from app.models.analytics_event import AnalyticsEvent

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Digital Risk Scanner")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://lmolinario.github.io",
        "http://localhost:5500",
        "http://127.0.0.1:5500",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
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


@app.middleware("http")
async def privacy_response_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store, private"
    return response

@app.get("/health")
def health():
    return {"status": "ok", "cors_debug": "enabled_v2"}

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse(request, "index.html")