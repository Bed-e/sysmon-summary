"""Tests for enrich.py. No network: call_portal is replaced with a fake
that returns saved/hand-written answers. Timeouts and 503s cannot be
recorded, so they are SIMULATED here."""

import enrich
from enrich import (
    build_request_url,
    enrich_one,
    load_portal_urls,
    normalize_dns_answer,
    normalize_hash_answer,
    normalize_ip_answer,
)

URLS = {"ip": "http://ip", "hash": "http://hash", "dns": "http://dns"}


def item(ioc_type="ip", value="8.8.8.8", score=30):
    return {"type": ioc_type, "value": value, "score": score, "reasons": ["+30 test"]}


def fake_portal(monkeypatch, status, body, error="", calls=None):
    def fake(url, timeout):
        if calls is not None:
            calls.append(url)
        return status, body, error
    monkeypatch.setattr(enrich, "call_portal", fake)


def test_load_portal_urls_reads_environment(monkeypatch):
    monkeypatch.setenv("IP_PORTAL_URL", "http://localhost:1/")
    monkeypatch.delenv("HASH_PORTAL_URL", raising=False)
    monkeypatch.setenv("DNS_PORTAL_URL", "http://localhost:3")
    urls = load_portal_urls()
    assert urls == {"ip": "http://localhost:1", "hash": "", "dns": "http://localhost:3"}


def test_build_request_url_for_each_type():
    assert build_request_url("ip", "8.8.8.8", URLS) == "http://ip/api/ip/8.8.8.8"
    assert build_request_url("hash", "ab", URLS) == "http://hash/api/v1/hash/ab"
    assert build_request_url("dns", "a.com", URLS) == "http://dns/api/v1/domain/a.com"


def test_build_request_url_unconfigured_is_none():
    assert build_request_url("ip", "8.8.8.8", {"ip": ""}) is None


def test_normalize_ip():
    body = {"verdict": {"score": 80, "level": "malicious", "reasons": ["bad"]}}
    result = normalize_ip_answer(item(), body)
    assert result["score_0_to_100"] == 80
    assert result["label"] == "malicious"
    assert result["reasons"] == ["bad"]
    assert result["status"] == "enriched"
    assert result["local_score"] == 30


def test_normalize_ip_missing_score_is_not_enriched():
    result = normalize_ip_answer(item(), {"verdict": {}})
    assert result["status"] == "not_enriched"
    assert result["score_0_to_100"] is None


def test_normalize_hash_lists_failed_sources():
    body = {"sources": {"virustotal": {"status": "error"},
                        "threatfox": {"status": "not_found"}},
            "verdict": {"score": 50, "label": "suspicious", "reasons": ["clean"],
                        "failed_sources": ["virustotal"]}}
    result = normalize_hash_answer(item("hash", "ab"), body)
    assert result["label"] == "suspicious"
    assert result["status"] == "partial"
    assert "sources that failed: virustotal" in result["reasons"]


def test_normalize_dns_uses_notes_and_failed_sources():
    body = {
        "assessment": {"average": 40, "verdict": "possibly_malware",
                       "verdict_note": "mixed", "sources_used": 1, "sources_total": 2},
        "sources": {"rdap": {"status": "ok", "score": 40, "score_reason": "new"},
                    "crtsh": {"status": "error", "score": None}},
    }
    result = normalize_dns_answer(item("dns", "a.com"), body)
    assert result["score_0_to_100"] == 40
    assert result["label"] == "possibly_malware"
    assert "mixed" in result["reasons"]
    assert "rdap: new" in result["reasons"]
    assert "sources that failed: crtsh" in result["reasons"]
    assert result["status"] == "partial"


def test_normalize_dns_null_average_is_not_enriched():
    body = {"assessment": {"average": None, "verdict": "not_graded"}}
    result = normalize_dns_answer(item("dns", "a.com"), body)
    assert result["status"] == "not_enriched"
    assert result["score_0_to_100"] is None


def test_enrich_one_ok(monkeypatch):
    fake_portal(monkeypatch, 200, {"verdict": {"score": 5, "level": "no_known_bad"}})
    result = enrich_one(item(), URLS)
    assert result["status"] == "enriched"
    assert result["label"] == "no_known_bad"


def test_enrich_one_failures_are_not_enriched(monkeypatch):
    cases = [
        ((503, {}, ""), "503"),
        ((400, {}, ""), "portal_rejected_input"),
        ((500, {}, ""), "HTTP 500"),
        ((None, None, "timed out after 30 s"), "timed out"),  # simulated
        ((200, None, ""), "not JSON"),
    ]
    for (status, body, error), expected in cases:
        fake_portal(monkeypatch, status, body, error)
        result = enrich_one(item(), URLS)
        assert result["status"] == "not_enriched"
        assert result["score_0_to_100"] is None
        assert expected in result["reasons"][0]


def test_enrich_one_unconfigured_portal_makes_no_call(monkeypatch):
    calls = []
    fake_portal(monkeypatch, 200, {}, calls=calls)
    result = enrich_one(item(), {"ip": "", "hash": "", "dns": ""})
    assert result["status"] == "not_enriched"
    assert "not configured" in result["reasons"][0]
    assert calls == []


def test_enrich_one_never_sends_a_not_enrichable_ioc(monkeypatch):
    calls = []
    fake_portal(monkeypatch, 200, {"verdict": {"score": 1, "level": "x"}}, calls=calls)
    blocked = item("dns", "dc1.corp.local")
    blocked["not_enrichable"] = "dns_internal"
    result = enrich_one(blocked, URLS)
    assert result["status"] == "not_enriched"
    assert result["reasons"] == ["not sent: dns_internal"]
    assert calls == []


def test_normalize_ip_not_applicable_is_not_enriched():
    # score 0 here means "not judged", never safe
    body = {"verdict": {"level": "not_applicable", "score": 0, "reasons": []}}
    result = normalize_ip_answer(item(), body)
    assert result["status"] == "not_enriched"
    assert result["score_0_to_100"] is None


def test_normalize_ip_failed_source_makes_partial():
    body = {"verdict": {"level": "suspicious", "score": 30, "reasons": ["r"]},
            "sources": [{"name": "internetdb", "status": "ok"},
                        {"name": "rdap", "status": "error"},
                        {"name": "abuseipdb", "status": "not_configured"}]}
    result = normalize_ip_answer(item(), body)
    assert result["status"] == "partial"
    assert "sources that failed: rdap" in result["reasons"]


def test_normalize_hash_every_source_failed_is_not_enriched():
    body = {"sources": {"virustotal": {"status": "error"},
                        "malwarebazaar": {"status": "error"}},
            "verdict": {"score": 50, "label": "suspicious", "reasons": [],
                        "failed_sources": ["virustotal", "malwarebazaar"]}}
    result = normalize_hash_answer(item("hash", "ab"), body)
    assert result["status"] == "not_enriched"
    assert result["score_0_to_100"] is None


def test_normalize_dns_all_sources_scored_is_enriched():
    body = {"assessment": {"average": 10, "verdict": "definitely_safe",
                           "verdict_note": None, "sources_used": 3, "sources_total": 3},
            "sources": {"dns": {"status": "ok", "score": 10, "score_reason": "ok"}}}
    result = normalize_dns_answer(item("dns", "a.com"), body)
    assert result["status"] == "enriched"
