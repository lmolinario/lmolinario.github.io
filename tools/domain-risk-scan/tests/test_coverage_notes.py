from types import SimpleNamespace

from app.services.report_service import _build_severity_breakdown, build_report_payload
from app.tasks import scan_tasks


def test_execute_scan_only_coverage_notes(monkeypatch):
    captured = {}
    fake_scan = SimpleNamespace(id=1, domain="example.com", score=None, summary_json=None)

    class FakeDB:
        def rollback(self):
            return None

        def close(self):
            return None

    monkeypatch.setattr(scan_tasks, "SessionLocal", lambda: FakeDB())
    monkeypatch.setattr(scan_tasks, "get_scan", lambda db, scan_id: fake_scan)
    monkeypatch.setattr(scan_tasks, "set_scan_running", lambda db, scan: None)
    monkeypatch.setattr(scan_tasks, "replace_findings", lambda db, scan_id, findings: captured.setdefault("stored_findings", findings))
    monkeypatch.setattr(scan_tasks, "track_event", lambda db, scan_id, event: None)

    monkeypatch.setattr(scan_tasks, "scan_dns", lambda domain: [])
    monkeypatch.setattr(
        scan_tasks,
        "scan_ssl",
        lambda domain: [
            {
                "category": "scanner",
                "severity": "info",
                "finding_type": "coverage",
                "title": "HTTPS validation timed out",
                "description": "Coverage note",
                "evidence_json": {"check_type": "ssl_timeout"},
                "recommendation": "Retry",
            }
        ],
    )
    monkeypatch.setattr(scan_tasks, "scan_subdomains", lambda domain: [])

    def _update_completed(db, scan, score, summary):
        captured["score"] = score
        captured["summary"] = summary

    monkeypatch.setattr(scan_tasks, "update_scan_completed", _update_completed)

    scan_tasks.execute_scan(scan_id=1)

    assert captured["stored_findings"] == []
    assert captured["score"] == 100
    assert captured["summary"]["findings_count"] == 0
    assert captured["summary"]["coverage_notes_count"] == 1
    assert captured["summary"]["top_issues"] == []


def test_report_payload_top_issue_null_with_only_coverage_notes():
    scan = SimpleNamespace(
        id=2,
        domain="example.com",
        score=100,
        updated_at=None,
        summary_json={
            "coverage_notes": [
                {
                    "title": "Passive subdomain enumeration timed out",
                    "severity": "info",
                    "category": "subdomain",
                }
            ]
        },
    )

    class FakeQuery:
        def filter(self, *args, **kwargs):
            return self

        def order_by(self, *args, **kwargs):
            return self

        def all(self):
            return []

        def first(self):
            return None

    class FakeDB:
        def query(self, *args, **kwargs):
            return FakeQuery()

    payload = build_report_payload(db=FakeDB(), scan=scan, is_paid=True)

    assert payload["top_issue_title"] is None
    assert payload["score"] == 100
    assert len(payload["coverage_notes"]) == 1


def test_severity_breakdown_supports_info():
    findings = [
        SimpleNamespace(severity="info"),
        SimpleNamespace(severity="high"),
    ]
    breakdown = _build_severity_breakdown(findings)

    assert breakdown["info"] == 1
    assert breakdown["high"] == 1


def test_frontend_template_supports_info_severity():
    with open("templates/index.html", "r", encoding="utf-8") as f:
        html = f.read()

    assert "sev-info" in html
    assert '["critical", "high", "medium", "low", "info"]' in html
