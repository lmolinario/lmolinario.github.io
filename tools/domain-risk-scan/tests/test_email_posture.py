from types import SimpleNamespace

from app.scanners import dns_scanner
from app.services.scoring_service import calculate_score


def _answer(text, preference=None, exchange=None):
    obj = SimpleNamespace()
    obj.to_text = lambda: text
    if preference is not None:
        obj.preference = preference
    if exchange is not None:
        obj.exchange = SimpleNamespace(to_text=lambda: exchange)
    return obj


def _result(status="ok", answers=None):
    return {
        "status": status,
        "answers": answers or [],
    }


def _install(monkeypatch, mapping):
    monkeypatch.setattr(
        dns_scanner,
        "_resolve_record",
        lambda domain, record_type: mapping.get(
            (domain, record_type),
            _result("no_answer"),
        ),
    )


def test_web_only_undeclared_is_not_scored(monkeypatch):
    domain = "web-only.example"

    mapping = {
        (domain, "A"): _result("ok", [_answer("203.0.113.10")]),
        (domain, "AAAA"): _result("no_answer"),
        (domain, "TXT"): _result("no_answer"),
        (f"_dmarc.{domain}", "TXT"): _result("nxdomain"),
        (domain, "MX"): _result("no_answer"),
    }

    _install(monkeypatch, mapping)

    results = dns_scanner.scan_dns(domain)

    assert len(results) == 1
    assert results[0]["finding_type"] == "coverage"
    assert results[0]["severity"] == "info"
    assert results[0]["evidence_json"]["check_type"] == "mail_intent_undeclared"

    security_findings = [
        item for item in results
        if item.get("finding_type", "security") != "coverage"
    ]

    assert security_findings == []
    assert calculate_score(security_findings) == 100


def test_null_mx_is_explicitly_non_mail(monkeypatch):
    domain = "nonmail.example"

    mx = _answer("0 .", preference=0, exchange=".")

    mapping = {
        (domain, "A"): _result("ok", [_answer("203.0.113.10")]),
        (domain, "AAAA"): _result("no_answer"),
        (domain, "TXT"): _result(
            "ok",
            [_answer('"v=spf1 -all"')],
        ),
        (f"_dmarc.{domain}", "TXT"): _result(
            "ok",
            [_answer('"v=DMARC1; p=reject;"')],
        ),
        (domain, "MX"): _result("ok", [mx]),
    }

    _install(monkeypatch, mapping)

    results = dns_scanner.scan_dns(domain)

    assert len(results) == 1
    assert results[0]["finding_type"] == "coverage"
    assert results[0]["evidence_json"]["email_posture"] == "mail_disabled"
    assert results[0]["evidence_json"]["check_type"] == "mail_explicitly_disabled"


def test_mail_enabled_without_spf_dmarc_gets_findings(monkeypatch):
    domain = "mail.example"

    mx = _answer(
        "10 mail.example.",
        preference=10,
        exchange="mail.example.",
    )

    mapping = {
        (domain, "A"): _result("ok", [_answer("203.0.113.10")]),
        (domain, "AAAA"): _result("no_answer"),
        (domain, "TXT"): _result("no_answer"),
        (f"_dmarc.{domain}", "TXT"): _result("nxdomain"),
        (domain, "MX"): _result("ok", [mx]),
    }

    _install(monkeypatch, mapping)

    results = dns_scanner.scan_dns(domain)

    security = [
        item for item in results
        if item.get("finding_type", "security") != "coverage"
    ]

    check_types = {
        item["evidence_json"]["check_type"]
        for item in security
    }

    assert check_types == {"spf_missing", "dmarc_missing"}
    assert all(item["severity"] == "high" for item in security)
    assert calculate_score(security) == 70


def test_mail_enabled_with_spf_dmarc_is_clean(monkeypatch):
    domain = "healthy-mail.example"

    mx = _answer(
        "10 mail.example.",
        preference=10,
        exchange="mail.example.",
    )

    mapping = {
        (domain, "A"): _result("ok", [_answer("203.0.113.10")]),
        (domain, "AAAA"): _result("no_answer"),
        (domain, "TXT"): _result(
            "ok",
            [_answer('"v=spf1 include:sender.example -all"')],
        ),
        (f"_dmarc.{domain}", "TXT"): _result(
            "ok",
            [_answer('"v=DMARC1; p=reject;"')],
        ),
        (domain, "MX"): _result("ok", [mx]),
    }

    _install(monkeypatch, mapping)

    results = dns_scanner.scan_dns(domain)

    assert results == []
    assert calculate_score([]) == 100
