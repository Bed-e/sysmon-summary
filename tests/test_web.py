"""Tests for web/app.py. No network: call_portal is faked, uploads are tiny."""

import io
import threading

from starlette.datastructures import UploadFile

import enrich
from web import app as web


def ioc(kind, value, score=10):
    return {"type": kind, "value": value, "score": score, "reasons": ["+%d t" % score],
            "record": {"process_guids": [], "count": 1}}


def fresh_state(ranked):
    return {"name": "x.evtx", "events": [], "iocs": {"ip": {}, "dns": {}, "hash": {}},
            "skipped": [], "ranked": ranked, "results": [], "run": "idle",
            "error": "", "n": 0}


def fake_portal(monkeypatch, calls):
    def fake(url, timeout):
        calls.append(url)
        return 200, {"verdict": {"score": 5, "level": "no_known_bad", "reasons": []},
                     "sources": []}, ""
    monkeypatch.setattr(enrich, "call_portal", fake)


URLS = {"ip": "http://ip", "hash": "http://h", "dns": "http://d"}
LIMITS = {"hash_per_minute": 4, "hash_per_day": 500}


def test_load_limits_defaults_and_values(tmp_path):
    assert web.load_limits(str(tmp_path / "none.txt")) == LIMITS
    f = tmp_path / "l.txt"
    f.write_text("# c\nhash_per_minute=10\nhash_per_day=abc\n")
    assert web.load_limits(str(f)) == {"hash_per_minute": 10, "hash_per_day": 500}


def test_daily_count_persists_and_resets_on_new_day(tmp_path):
    p = str(tmp_path / "u.txt")
    assert web.read_daily_count(p, "2026-01-01") == 0
    web.add_daily_count(p, "2026-01-01")
    assert web.add_daily_count(p, "2026-01-01") == 2
    assert web.read_daily_count(p, "2026-01-01") == 2
    assert web.read_daily_count(p, "2026-01-02") == 0


def test_needs_warning():
    ranked = [ioc("hash", "a" * 64) for _ in range(6)] + [ioc("ip", "8.8.8.8")]
    assert web.needs_warning(ranked, 3, LIMITS, 0) == []
    assert "6 hash lookups" in web.needs_warning(ranked, 7, LIMITS, 0)[0]
    assert "Daily budget" in web.needs_warning(ranked, 7, LIMITS, 499)[-1]
    assert web.needs_warning([ioc("ip", "1.1.1.1")], 1, LIMITS, 999) == []


def test_seconds_to_wait():
    assert web.seconds_to_wait(100.0, 110.0, 15.0) == 5.0
    assert web.seconds_to_wait(100.0, 200.0, 15.0) == 0


def test_run_enrichment_only_top_n_in_order_and_paces_hashes(monkeypatch, tmp_path):
    calls, pauses = [], []
    fake_portal(monkeypatch, calls)
    monkeypatch.setitem(web.LAST_HASH, "time", 0.0)
    ranked = [ioc("hash", "a" * 64), ioc("ip", "8.8.8.8"), ioc("hash", "b" * 64),
              ioc("dns", "never.example")]
    state = fresh_state(ranked)
    web.run_enrichment(state, 3, URLS, LIMITS, str(tmp_path / "u.txt"),
                       pause=pauses.append, clock=lambda: 1000.0)
    assert state["run"] == "done"
    assert [r["value"] for r in state["results"]] == ["a" * 64, "8.8.8.8", "b" * 64]
    assert len(calls) == 3 and not any("never" in c for c in calls)
    assert pauses == [15.0]  # second hash waits the full spacing; first is free
    assert web.read_daily_count(str(tmp_path / "u.txt")) == 2


def test_daily_budget_is_a_hard_stop(monkeypatch, tmp_path):
    calls = []
    fake_portal(monkeypatch, calls)
    usage = str(tmp_path / "u.txt")
    web.add_daily_count(usage)
    state = fresh_state([ioc("hash", "a" * 64), ioc("ip", "8.8.8.8")])
    web.run_enrichment(state, 2, URLS, {"hash_per_minute": 4, "hash_per_day": 1},
                       usage, pause=lambda s: None, clock=lambda: 1.0)
    first, second = state["results"]
    assert first["status"] == "not_enriched" and web.BUDGET_REASON in first["reasons"][0]
    assert second["status"] == "enriched"
    assert len(calls) == 1  # only the IP reached a portal


def test_thread_crash_sets_failed(monkeypatch, tmp_path):
    def boom(item, urls):
        raise RuntimeError("kaboom")
    monkeypatch.setattr(web, "enrich_one", boom)
    state = fresh_state([ioc("ip", "8.8.8.8")])
    web.run_enrichment(state, 1, URLS, LIMITS, str(tmp_path / "u.txt"))
    assert state["run"] == "failed" and "kaboom" in state["error"]


def test_start_refused_while_running():
    state = fresh_state([ioc("ip", "8.8.8.8")])
    state["run"] = "running"
    assert web.start_enrichment(state, 1, URLS, LIMITS) is False
    assert state["results"] == []


def test_start_runs_thread_to_done(monkeypatch, tmp_path):
    calls = []
    fake_portal(monkeypatch, calls)
    state = fresh_state([ioc("ip", "8.8.8.8")])
    assert web.start_enrichment(state, 1, URLS, LIMITS) is True
    for t in threading.enumerate():
        if t is not threading.current_thread() and t.daemon:
            t.join(5)
    assert state["run"] == "done" and len(state["results"]) == 1


def test_choose_n():
    ranked = [ioc("ip", "1.1.1.1")] * 3
    assert web.choose_n("10", ranked) == 3
    assert web.choose_n("all", ranked) == 3
    assert web.choose_n("5; drop", ranked) is None


def test_portal_text_never_shows_a_failure_as_a_score():
    assert web.portal_text("not requested") == "not requested"
    failed = enrich.not_enriched(ioc("ip", "1.1.1.1"), "timed out")
    assert web.portal_text(failed) == "NOT ENRICHED: timed out"
    ok = {"status": "partial", "score_0_to_100": 50, "label": "suspicious", "reasons": []}
    assert web.portal_text(ok) == "portal 50 (suspicious) [partial: some sources failed]"


def test_make_ioc_rows_keeps_rank_order_and_marks_unrequested():
    ranked = [ioc("ip", "1.1.1.1", 30), ioc("dns", "a.example", 20)]
    answer = {"type": "dns", "value": "a.example", "status": "enriched",
              "score_0_to_100": 10, "label": "likely_safe", "reasons": []}
    rows = web.make_ioc_rows(ranked, [answer])
    assert [r["rank"] for r in rows] == [1, 2]
    assert rows[0]["portal"] == "not requested"
    assert rows[1]["portal"] == "portal 10 (likely_safe)"
    assert rows[0]["why"] == "+30 t"


def test_make_skipped_rows_sorted():
    skipped = [{"type": "dns", "value": "b", "reason": "z", "record": {"count": 2}},
               {"type": "ip", "value": "a", "reason": "a", "record": {"count": 1}}]
    rows = web.make_skipped_rows(skipped)
    assert [r["reason"] for r in rows] == ["a", "z"] and rows[0]["count"] == 1


def test_counts_and_status():
    state = fresh_state([ioc("ip", "1.1.1.1"), ioc("ip", "2.2.2.2")])
    state["iocs"] = {"ip": {"1.1.1.1": {}, "2.2.2.2": {}}, "dns": {}, "hash": {}}
    ok = {"status": "enriched"}
    bad = {"status": "not_enriched"}
    rows = {r["item"]: r["value"] for r in web.make_counts_rows(state, [ok, bad])}
    assert rows["Looked up on the portals"] == "1"
    assert rows["Lookup failed (not enriched)"] == "1"
    assert rows["Not requested"] == "0"
    assert web.status_text(state) == "No portal has been called yet."
    state.update(run="running", n=5)
    state["results"] = [ok]
    assert web.status_text(state) == "Running: 1 of 2 done."
    state.update(run="failed", error="boom")
    assert web.status_text(state) == "Run failed: boom"


def test_choose_n():
    ranked = [ioc("ip", "1.1.1.1")] * 3
    assert web.choose_n("10", ranked) == 3
    assert web.choose_n("all", ranked) == 3
    assert web.choose_n("5; drop", ranked) is None


def post(name, data):
    """Call the upload endpoint directly with a fake uploaded file."""
    return web.upload_endpoint(UploadFile(io.BytesIO(data), filename=name))


def test_upload_endpoint_rejects_bad_input_with_fixed_codes(tmp_path, monkeypatch):
    monkeypatch.setattr(web, "UPLOAD_DIR", str(tmp_path))
    assert web.upload_endpoint(None).headers["location"] == "/?error=none"
    assert post("a.txt", b"hi").headers["location"] == "/?error=type"
    assert post("a.evtx", b"not evtx").headers["location"] == "/?error=magic"
    monkeypatch.setattr(web, "MAX_UPLOAD_BYTES", 4)
    assert post("a.evtx", b"ElfFile\x00xxxx").headers["location"] == "/?error=size"
    assert list(tmp_path.iterdir()) == []  # temp files always removed


def test_upload_endpoint_success_stores_state_without_calling_portals(monkeypatch, tmp_path):
    monkeypatch.setattr(web, "UPLOAD_DIR", str(tmp_path))
    parsed = {"events": [], "dropped_counts": {}, "error_count": 0, "total": 0}
    monkeypatch.setattr(web, "read_events", lambda path: parsed)
    def no_network(url, timeout):
        raise AssertionError("upload must not call a portal")
    monkeypatch.setattr(enrich, "call_portal", no_network)
    response = post("../../evil name.evtx", b"ElfFile\x00 body")
    location = response.headers["location"]
    assert location.startswith("/report/")
    state = web.UPLOADS[location.rsplit("/", 1)[1]]
    assert state["name"] == "evil name.evtx" and state["run"] == "idle"
    assert state["results"] == [] and list(tmp_path.iterdir()) == []
