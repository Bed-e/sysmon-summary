"""Tests for web/app.py. No network: call_portal is faked, uploads are tiny."""

import io
import threading

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


def test_report_refresh_tag_only_while_running_and_escapes():
    state = fresh_state([ioc("ip", "8.8.8.8")])
    state["name"] = "<script>x</script>.evtx"
    web.UPLOADS["t1"] = state
    html = web.render_report("t1")
    assert "http-equiv" not in html and "<script>" not in html
    assert "not requested" in html
    state["run"] = "running"
    state["n"] = 1
    assert 'http-equiv="refresh"' in web.render_report("t1")
    state["run"] = "failed"
    state["error"] = "<b>bad</b>"
    html = web.render_report("t1")
    assert "http-equiv" not in html and "<b>bad</b>" not in html


def test_routes_reject_bad_input_and_unknown_ids():
    client = web.app.test_client()
    assert client.get("/").status_code == 200
    assert client.get("/report/nope").status_code == 404
    assert client.post("/enrich/nope", data={"n": "5"}).status_code == 404
    r = client.post("/upload", data={"dump": (io.BytesIO(b"hi"), "a.txt")})
    assert r.status_code == 400
    r = client.post("/upload", data={"dump": (io.BytesIO(b"not evtx"), "a.evtx")})
    assert r.status_code == 400 and b"not a Windows" in r.data


def test_enrich_route_confirm_page_then_start(monkeypatch, tmp_path):
    started = []
    monkeypatch.setattr(web, "start_enrichment", lambda *a: started.append(a) or True)
    monkeypatch.setattr(web, "load_limits", lambda: LIMITS)
    monkeypatch.setattr(web, "read_daily_count", lambda: 0)
    web.UPLOADS["t2"] = fresh_state([ioc("hash", "a" * 64) for _ in range(6)])
    client = web.app.test_client()
    r = client.post("/enrich/t2", data={"n": "all"})
    assert b"Send anyway" in r.data and started == []
    r = client.post("/enrich/t2", data={"n": "all", "confirm": "yes"})
    assert r.status_code == 302 and len(started) == 1
    r = client.post("/enrich/t2", data={"n": "5; evil"})
    assert r.status_code == 400
