"""Tests for enrich.py. No network: call_portal is replaced with a fake
that returns saved/hand-written answers. Timeouts and 503s cannot be
recorded, so they are SIMULATED here."""

import enrich
from enrich import (
    build_request_url,
    enrich_one,
    enrich_ranked,
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
    assert result["status"] == "ok"
    assert result["local_score"] == 30


def test_normalize_ip_missing_score_is_not_enriched():
    result = normalize_ip_answer(item(), {"verdict": {}})
    assert result["status"] == "not_enriched"
    assert result["score_0_to_100"] is None


def test_normalize_hash_lists_failed_sources():
    body = {"verdict": {"score": 0, "label": "safe", "reasons": ["clean"],
                        "failed_sources": ["virustotal"]}}
    result = normalize_hash_answer(item("hash", "ab"), body)
    assert result["label"] == "safe"
    assert result["status"] == "ok"
    assert "sources that failed: virustotal" in result["reasons"]


def test_normalize_dns_uses_notes_and_failed_sources():
    body = {
        "assessment": {"average": 40, "verdict": "possibly_malware",
                       "verdict_note": "mixed"},
        "sources": {"rdap": {"status": "ok", "score": 40, "score_reason": "new"},
                    "crtsh": {"status": "error", "score": None}},
    }
    result = normalize_dns_answer(item("dns", "a.com"), body)
    assert result["score_0_to_100"] == 40
    assert result["label"] == "possibly_malware"
    assert "mixed" in result["reasons"]
    assert "rdap: new" in result["reasons"]
    assert "sources that failed: crtsh" in result["reasons"]


def test_normalize_dns_null_average_is_not_enriched():
    body = {"assessment": {"average": None, "verdict": "not_graded"}}
    result = normalize_dns_answer(item("dns", "a.com"), body)
    assert result["status"] == "not_enriched"
    assert result["score_0_to_100"] is None


def test_enrich_one_ok(monkeypatch):
    fake_portal(monkeypatch, 200, {"verdict": {"score": 5, "level": "no_known_bad"}})
    result = enrich_one(item(), URLS)
    assert result["status"] == "ok"
    assert result["label"] == "no_known_bad"


def test_enrich_one_failures_are_not_enriched(monkeypatch):
    cases = [
        ((503, {}, ""), "503"),
        ((400, {}, ""), "400"),
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


def test_enrich_ranked_respects_cap_and_order(monkeypatch):
    calls = []
    fake_portal(monkeypatch, 200, {"verdict": {"score": 1, "level": "x"}}, calls=calls)
    ranked = [item(value="1.1.1.%d" % n) for n in range(4)]
    results = enrich_ranked(ranked, URLS, cap=2)
    assert [r["value"] for r in results] == [r["value"] for r in ranked]
    assert [r["status"] for r in results] == ["ok", "ok", "not_enriched", "not_enriched"]
    assert "over the cap of 2" in results[2]["reasons"][0]
    assert len(calls) == 2
    assert calls[0].endswith("1.1.1.0")
