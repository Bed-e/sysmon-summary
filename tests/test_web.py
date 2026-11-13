"""Tests for the web package (the non-UI modules and the upload endpoint).

No network: call_portal is faked, uploads are tiny.
"""

import io
import threading

from starlette.datastructures import UploadFile

import enrich
from web import (config, enrich_jobs, limits, reasons, rows, runtime,
                 storyline_summary, timeline_chart, timeline_data, upload)


def ioc(kind, value, score=10):
    return {"type": kind, "value": value, "score": score, "reasons": ["+%d t" % score],
            "record": {"process_guids": [], "count": 1}}


def fresh_state(ranked):
    return {"name": "x.evtx", "events": [], "iocs": {"ip": {}, "dns": {}, "hash": {}},
            "skipped": [], "ranked": ranked, "results": [], "run": "idle",
            "error": "", "run_size": 0, "run_done": 0, "version": 0}


def fake_portal(monkeypatch, calls):
    def fake(url, timeout):
        calls.append(url)
        return 200, {"verdict": {"score": 5, "level": "no_known_bad", "reasons": []},
                     "sources": []}, ""
    monkeypatch.setattr(enrich, "call_portal", fake)


URLS = {"ip": "http://ip", "hash": "http://h", "dns": "http://d"}
LIMITS = {"hash_per_minute": 4, "hash_per_day": 500}


def test_load_limits_defaults_and_values(tmp_path):
    assert limits.load_limits(str(tmp_path / "none.txt")) == LIMITS
    f = tmp_path / "l.txt"
    f.write_text("# c\nhash_per_minute=10\nhash_per_day=abc\n")
    assert limits.load_limits(str(f)) == {"hash_per_minute": 10, "hash_per_day": 500}


def test_daily_count_persists_and_resets_on_new_day(tmp_path):
    p = str(tmp_path / "u.txt")
    assert limits.read_daily_count(p, "2026-01-01") == 0
    limits.add_daily_count(p, "2026-01-01")
    assert limits.add_daily_count(p, "2026-01-01") == 2
    assert limits.read_daily_count(p, "2026-01-01") == 2
    assert limits.read_daily_count(p, "2026-01-02") == 0


def test_needs_warning():
    ranked = [ioc("hash", "a" * 64) for _ in range(6)] + [ioc("ip", "8.8.8.8")]
    assert limits.needs_warning(ranked[:3], LIMITS, 0) == []
    assert "6 hash lookups" in limits.needs_warning(ranked, LIMITS, 0)[0]
    assert "Daily budget" in limits.needs_warning(ranked, LIMITS, 499)[-1]
    assert limits.needs_warning([ioc("ip", "1.1.1.1")], LIMITS, 999) == []


def test_seconds_to_wait():
    assert limits.seconds_to_wait(100.0, 110.0, 15.0) == 5.0
    assert limits.seconds_to_wait(100.0, 200.0, 15.0) == 0


def test_run_enrichment_only_given_items_in_order_and_paces_hashes(monkeypatch, tmp_path):
    calls, pauses = [], []
    fake_portal(monkeypatch, calls)
    monkeypatch.setitem(runtime.LAST_HASH, "time", 0.0)
    ranked = [ioc("hash", "a" * 64), ioc("ip", "8.8.8.8"), ioc("hash", "b" * 64),
              ioc("dns", "never.example")]
    state = fresh_state(ranked)
    enrich_jobs.run_enrichment(state, ranked[:3], URLS, LIMITS, str(tmp_path / "u.txt"),
                       pause=pauses.append, clock=lambda: 1000.0)
    assert state["run"] == "done" and state["run_done"] == 3 and state["version"] == 3
    assert [r["value"] for r in state["results"]] == ["a" * 64, "8.8.8.8", "b" * 64]
    assert len(calls) == 3 and not any("never" in c for c in calls)
    assert pauses == [15.0]  # second hash waits the full spacing; first is free
    assert limits.read_daily_count(str(tmp_path / "u.txt")) == 2


def test_daily_budget_is_a_hard_stop(monkeypatch, tmp_path):
    calls = []
    fake_portal(monkeypatch, calls)
    usage = str(tmp_path / "u.txt")
    limits.add_daily_count(usage)
    state = fresh_state([ioc("hash", "a" * 64), ioc("ip", "8.8.8.8")])
    enrich_jobs.run_enrichment(state, state["ranked"], URLS, {"hash_per_minute": 4, "hash_per_day": 1},
                       usage, pause=lambda s: None, clock=lambda: 1.0)
    first, second = state["results"]
    assert first["status"] == "not_enriched" and config.BUDGET_REASON in first["reasons"][0]
    assert second["status"] == "enriched"
    assert len(calls) == 1  # only the IP reached a portal


def test_thread_crash_sets_failed(monkeypatch, tmp_path):
    def boom(item, urls):
        raise RuntimeError("kaboom")
    monkeypatch.setattr(enrich_jobs, "enrich_one", boom)
    state = fresh_state([ioc("ip", "8.8.8.8")])
    enrich_jobs.run_enrichment(state, state["ranked"], URLS, LIMITS, str(tmp_path / "u.txt"))
    assert state["run"] == "failed" and "kaboom" in state["error"]


def test_start_refused_while_running():
    state = fresh_state([ioc("ip", "8.8.8.8")])
    state["run"] = "running"
    assert enrich_jobs.start_enrichment(state, state["ranked"], URLS, LIMITS) is False
    assert state["results"] == []


def test_start_runs_thread_to_done(monkeypatch, tmp_path):
    calls = []
    fake_portal(monkeypatch, calls)
    state = fresh_state([ioc("ip", "8.8.8.8")])
    state["results"] = [{"type": "dns", "value": "kept.example", "status": "enriched"}]
    assert enrich_jobs.start_enrichment(state, state["ranked"], URLS, LIMITS) is True
    for t in threading.enumerate():
        if t is not threading.current_thread() and t.daemon:
            t.join(5)
    assert state["run"] == "done" and len(state["results"]) == 2  # earlier kept


def test_choose_n():
    ranked = [ioc("ip", "1.1.1.1")] * 3
    assert rows.choose_n("10", ranked) == 3
    assert rows.choose_n("all", ranked) == 3
    assert rows.choose_n("5; drop", ranked) is None


def test_portal_text_never_shows_a_failure_as_a_score():
    assert reasons.portal_text("not requested") == "not requested"
    failed = enrich.not_enriched(ioc("ip", "1.1.1.1"), "timed out")
    assert reasons.portal_text(failed) == "NOT ENRICHED: timed out"
    ok = {"status": "partial", "score_0_to_100": 50, "label": "suspicious", "reasons": []}
    assert reasons.portal_text(ok) == "portal 50 (suspicious) [partial: some sources failed]"


def test_make_ioc_rows_keeps_rank_order_and_marks_unrequested():
    ranked = [ioc("ip", "1.1.1.1", 30), ioc("dns", "a.example", 20)]
    answer = {"type": "dns", "value": "a.example", "status": "enriched",
              "score_0_to_100": 10, "label": "likely_safe", "reasons": []}
    shown = rows.make_ioc_rows(ranked, [answer])
    assert [r["rank"] for r in shown] == [1, 2]
    assert shown[0]["portal"] == "not requested"
    assert shown[1]["portal"] == "portal 10 (likely_safe)"
    assert shown[0]["why"] == "t" and shown[0]["full_why"] == "+30 t"
    assert shown[0]["action"] == "Look up" and shown[1]["action"] == ""
    failed = enrich.not_enriched(ranked[0], "timed out")
    assert rows.make_ioc_rows(ranked, [failed])[0]["action"] == "Retry"


def test_make_skipped_rows_sorted():
    skipped = [{"type": "dns", "value": "b", "reason": "z", "record": {"count": 2}},
               {"type": "ip", "value": "a", "reason": "a", "record": {"count": 1}}]
    shown = rows.make_skipped_rows(skipped)
    assert [r["reason"] for r in shown] == ["a", "z"] and shown[0]["count"] == 1


def test_counts_and_status():
    state = fresh_state([ioc("ip", "1.1.1.1"), ioc("ip", "2.2.2.2")])
    state["iocs"] = {"ip": {"1.1.1.1": {}, "2.2.2.2": {}}, "dns": {}, "hash": {}}
    ok = {"status": "enriched"}
    bad = {"status": "not_enriched"}
    shown = {r["item"]: r["value"] for r in rows.make_counts_rows(state, [ok, bad])}
    assert shown["Looked up on the portals"] == "1"
    assert shown["Lookup failed (not enriched)"] == "1"
    assert shown["Not requested"] == "0"
    assert enrich_jobs.status_text(state) == "No portal has been called yet."
    state.update(run="running", run_size=5, run_done=1)
    state["results"] = [ok]
    assert enrich_jobs.status_text(state) == "Running: 1 of 5 done."
    state.update(run="done")
    assert enrich_jobs.status_text(state) == ("Last run finished: 1 looked up. "
                                      "1 of 2 ranked IOCs tried so far.")
    state.update(run="failed", error="boom")
    assert enrich_jobs.status_text(state).startswith("Run failed: boom.")


def post(name, data):
    """Call the upload endpoint directly with a fake uploaded file."""
    return upload.upload_endpoint(UploadFile(io.BytesIO(data), filename=name))


def test_upload_endpoint_rejects_bad_input_with_fixed_codes(tmp_path, monkeypatch):
    monkeypatch.setattr(upload, "UPLOAD_DIR", str(tmp_path))
    assert upload.upload_endpoint(None).headers["location"] == "/?error=none"
    assert post("a.txt", b"hi").headers["location"] == "/?error=type"
    assert post("a.evtx", b"not evtx").headers["location"] == "/?error=magic"
    monkeypatch.setattr(upload, "MAX_UPLOAD_BYTES", 4)
    assert post("a.evtx", b"ElfFile\x00xxxx").headers["location"] == "/?error=size"
    assert list(tmp_path.iterdir()) == []  # temp files always removed


def test_upload_endpoint_success_stores_state_without_calling_portals(monkeypatch, tmp_path):
    monkeypatch.setattr(upload, "UPLOAD_DIR", str(tmp_path))
    parsed = {"events": [], "dropped_counts": {}, "error_count": 0, "total": 0}
    monkeypatch.setattr(upload, "read_events", lambda path: parsed)
    def no_network(url, timeout):
        raise AssertionError("upload must not call a portal")
    monkeypatch.setattr(enrich, "call_portal", no_network)
    response = post("../../evil name.evtx", b"ElfFile\x00 body")
    location = response.headers["location"]
    assert location.startswith("/report/")
    state = runtime.UPLOADS[location.rsplit("/", 1)[1]]
    assert state["name"] == "evil name.evtx" and state["run"] == "idle"
    assert state["results"] == [] and list(tmp_path.iterdir()) == []


def test_next_items_skips_tried_including_failures():
    ranked = [ioc("ip", "1.1.1.%d" % i) for i in range(1, 13)]
    state = fresh_state(ranked)
    assert [i["value"] for i in enrich_jobs.next_items(state, 5)] == ["1.1.1.%d" % i for i in range(1, 6)]
    for item in ranked[:4]:
        enrich_jobs.store_result(state, {"type": "ip", "value": item["value"], "status": "enriched"})
    enrich_jobs.store_result(state, enrich.not_enriched(ranked[4], "timed out"))
    assert [i["value"] for i in enrich_jobs.next_items(state, 5)] == ["1.1.1.%d" % i for i in range(6, 11)]
    assert len(enrich_jobs.next_items(state, 100)) == 7


def test_store_result_replaces_a_retry():
    state = fresh_state([ioc("ip", "8.8.8.8")])
    enrich_jobs.store_result(state, enrich.not_enriched(state["ranked"][0], "timed out"))
    enrich_jobs.store_result(state, {"type": "ip", "value": "8.8.8.8", "status": "enriched"})
    assert len(state["results"]) == 1 and state["results"][0]["status"] == "enriched"
    assert state["version"] == 2


def test_short_reason_covers_every_scoring_phrase():
    from scoring import domains, paths, processes, ranking
    p = r"C:\Users\bob\AppData\Local\Temp\a.pdf.exe"
    cases = {
        "+20 process a.exe: file runs from a user-writable path (%s)" % p: "a.exe runs from a user folder",
        "+50 process a.exe: double extension (.pdf.exe)": "a.exe has a double extension (.pdf.exe)",
        "+25 process b.exe: document app started a program (winword.exe -> b.exe)":
            "b.exe was started by a document app (winword.exe -> b.exe)",
        "+25 process c.exe: explorer started a program from Temp (explorer.exe -> c.exe)":
            "c.exe was started by explorer from Temp",
        "+25 process d.exe: service started a program from a user-writable path (x)":
            "d.exe was started by a service from a user folder",
        r"+40 process e.exe: writes an autorun registry key (HKU\x\Run\y)": "e.exe sets an autorun registry key",
        "+15 process f.exe: 7 failed DNS lookups from one process": "f.exe made 7 failed DNS lookups",
        "+20 connection from an unexpected process (%s)" % p: "contacted by an unexpected program",
        "+10 unusual destination port (8080)": "unusual port (8080)",
        "+25 regular timing: 6 connections about 60 s apart": "possible beaconing (6 connections about 60 s apart)",
        "+20 very long label (40 characters)": "very long DNS label",
        "+20 high-entropy label (x7f9q2kz0pl3)": "random-looking DNS label",
        "+30 looks like microsoft.com": "looks like microsoft.com",
        "+40 registry references this file's path (%s)" % p: "an autorun key points to this file",
        "-15 all copies run from protected system paths (weak evidence)":
            "only seen in system folders (lowers the score)",
        "+5 something new (detail)": "something new",
    }
    for text, short in cases.items():
        assert reasons.short_reason(text) == short, text
    # The real scoring code still writes these phrases (guards against drift).
    assert paths.path_signals(p)[0][1].startswith("file runs from a user-writable path")
    assert paths.path_signals(p)[1][1].startswith("double extension")
    assert processes.failed_lookup_signal(9)[0][1].endswith("failed DNS lookups from one process")
    assert domains.dns_signals("x" * 40 + ".com", [])[0][1].startswith("very long label")
    assert ranking.trusted_path_adjustment([r"c:\windows\a.exe"], [r"c:\windows"])[0][1] \
        .startswith("all copies run from protected system paths")
    assert reasons.short_why(["+20 t (x)", "+20 t (y)", "+10 u"]) == "t · u"
    assert reasons.short_why([
        "+20 connection from an unexpected process (x)",
        "+20 process a.exe: file runs from a user-writable path (x)",
        "+40 process a.exe: writes an autorun registry key (k)",
        "+20 process b.exe: file runs from a user-writable path (y)",
    ]) == ("contacted by an unexpected program · a.exe runs from a user folder "
           "and sets an autorun registry key · b.exe runs from a user folder")


def process_entry(image, time="2023-12-14 03:42:00", **lists):
    entry = {"image": image, "time": time, "ips": [], "dns": [], "files": [],
             "registry": [], "iocs": []}
    entry.update(lists)
    return entry


def test_summarize_storyline_and_caption():
    hit = {"status": "enriched", "label": "malicious", "score_0_to_100": 90, "reasons": []}
    table = {
        "A": process_entry(r"C:\x\a.exe", ips=["1.2.3.4:443"], files=["f1", "f2"]),
        "B": process_entry(r"C:\x\b.exe", "2023-12-14 04:10:00", dns=["e.example"],
                           registry=["k"], iocs=[{"type": "ip", "value": "1.2.3.4", "portal": hit}]),
    }
    scores = {"B": {"image": r"C:\x\b.exe", "score": 40,
                    "signals": [(40, "writes an autorun registry key (k)")]},
              "A": {"image": r"C:\x\a.exe", "score": 0, "signals": []}}
    summary = storyline_summary.summarize_storyline(table, {"guids": ["A", "B"]}, scores)
    assert summary["flagged"] == [{"name": "b.exe", "score": 40, "why": "sets an autorun registry key"}]
    assert summary["portal_hits"] == ["ip 1.2.3.4: portal 90 (malicious)"]
    assert storyline_summary.summary_caption(summary) == (
        "2 processes · 1 flagged · 1 portal hit · 1 remote address · 1 DNS name · "
        "2 files · 1 registry write · 03:42–04:10")


TL_EVENTS = [
    {"event_id": 1, "time": "2023-12-14 03:42:39.407084+00:00", "ProcessGuid": "P",
     "Image": r"C:\x\parent.exe", "CommandLine": "parent.exe"},
    {"event_id": 1, "time": "2023-12-14 03:43:00.000000+00:00", "ProcessGuid": "C",
     "Image": r"C:\x\child.exe", "CommandLine": "child.exe /go"},
    {"event_id": 3, "time": "2023-12-14 03:44:00.000000+00:00", "ProcessGuid": "C",
     "Image": r"C:\x\child.exe", "DestinationIp": "1.2.3.4", "DestinationPort": "443"},
    {"event_id": 13, "time": "2023-12-14 03:45:00.000000+00:00", "ProcessGuid": "C",
     "Image": r"C:\x\child.exe", "TargetObject": "HKU\\Run\\x"},
    {"event_id": 1, "time": "2023-12-14 03:46:00.000000+00:00", "ProcessGuid": "Q",
     "Image": r"C:\x\other.exe", "CommandLine": "other.exe"},
    {"event_id": 22, "time": "bad time", "ProcessGuid": "Q", "Image": "", "QueryName": "q"},
]


def tl_table():
    def entry(image, parent, time, children):
        return {"image": image, "parent_guid": parent, "time": time,
                "children": children}
    return {
        "P": entry(r"C:\x\parent.exe", "", "2023-12-14 03:42:39", ["C"]),
        "C": entry(r"C:\x\child.exe", "P", "2023-12-14 03:43:00", []),
        "Q": entry(r"C:\x\other.exe", "", "2023-12-14 03:46:00", []),
        "G": entry(r"C:\x\gone.exe", "C", "2023-12-14 03:47:00", []),
    }


TL_SCORES = {"C": {"image": r"C:\x\child.exe", "score": 45, "signals": [(45, "x")]},
             "P": {"image": r"C:\x\parent.exe", "score": 0, "signals": []}}


def test_process_spans_first_and_last():
    spans = timeline_data.process_spans(TL_EVENTS)
    assert spans["C"]["first_text"] == "03:43:00" and spans["C"]["last_text"] == "03:45:00"
    assert spans["P"]["first"] == spans["P"]["last"] == 1702525359407
    assert spans["Q"]["first_text"] == "03:46:00"  # the bad-time event is skipped


def test_flagged_slice_includes_parents_only_of_flagged():
    assert timeline_data.flagged_slice(tl_table(), TL_SCORES) == {"C", "P"}


def test_order_rows_tree_order_and_depth():
    table = tl_table()
    table["P"]["children"] = ["G", "C"]
    rows = timeline_data.order_rows(table, {"P", "C", "Q", "G", "missing"})
    assert rows == [("P", 0), ("C", 1), ("G", 1), ("Q", 0)]
    # A child whose parent is not chosen becomes a root.
    assert timeline_data.order_rows(table, {"C", "Q"}) == [("C", 0), ("Q", 0)]


def test_row_label_indents_and_shows_score():
    table = tl_table()
    assert timeline_data.row_label(table, "P", 0, TL_SCORES) == "parent.exe"
    assert timeline_data.row_label(table, "C", 1, TL_SCORES) == config.INDENT + "└ child.exe  (45)"


def test_make_process_timeline_rows_bars_links_dots():
    table = tl_table()
    rows = timeline_data.order_rows(table, {"P", "C", "Q"})
    option = timeline_chart.make_process_timeline(table, rows, timeline_data.process_spans(TL_EVENTS),
                                       TL_EVENTS, TL_SCORES)
    assert option["yAxis"]["data"] == ["parent.exe", config.INDENT + "└ child.exe  (45)",
                                       "other.exe"]
    series = {s["name"]: s for s in option["series"]}
    high = series["Process, score %d+" % config.HIGH_SCORE]["data"]
    assert high == [{"coords": [[1702525380000, 1], [1702525500000, 1]],
                     "name": "child.exe  03:43:00 to 03:45:00  (score 45)"}]
    assert len(series["Process, score 0"]["data"]) == 2
    link = series["Parent → child"]["data"]
    assert link == [{"coords": [[1702525380000, 0], [1702525380000, 1]],
                     "name": "03:43:00 parent.exe started child.exe"}]
    assert len(series["Process start"]["data"]) == 3
    assert series["Network"]["data"][0]["value"] == [1702525440000, 1]
    assert len(series["Registry"]["data"]) == 1 and series["DNS"]["data"] == []
    assert len(option["dataZoom"]) == 2  # no row slider for 3 rows


def test_row_slider_only_for_many_rows():
    table = {}
    for i in range(config.ROWS_VISIBLE + 1):
        table["g%d" % i] = {"image": "a.exe", "parent_guid": "", "time": "%03d" % i,
                            "children": []}
    option = timeline_chart.make_process_timeline(table, timeline_data.order_rows(table, set(table)), {},
                                       [], {})
    assert option["dataZoom"][-1]["yAxisIndex"] == 0


def test_slice_choices_and_guids():
    table = tl_table()
    stories = {"table": table,
               "storylines": [{"root": "P", "size": 2, "guids": ["P", "C"]},
                              {"root": "Q", "size": 1, "guids": ["Q"]}]}
    choices = timeline_data.slice_choices(stories)
    assert list(choices) == ["flagged", "story:1", "story:2", "all"]
    assert choices["story:1"] == "Storyline #1: parent.exe (2 processes)"
    view = {"stories": stories, "process_scores": TL_SCORES}
    assert timeline_data.slice_guids(view, "story:2") == {"Q"}
    assert timeline_data.slice_guids(view, "all") == set(table)
    assert timeline_data.slice_guids(view, "story:99") == {"C", "P"}  # unknown -> flagged
    assert timeline_data.slice_guids(view, "nonsense") == {"C", "P"}


def test_event_detail_is_short():
    event = {"event_id": 11, "Image": r"C:\x\a.exe", "TargetFilename": "C:\\" + "y" * 300}
    text = timeline_data.event_detail(event)
    assert text.startswith("a.exe wrote") and len(text) == config.DETAIL_LENGTH


def test_storyline_why_is_short():
    lines = ["ip 1.2.3.4: +20 connection from an unexpected process (x)",
               "ip 1.2.3.4: +40 process a.exe: writes an autorun registry key (k)",
               "highest of 28 scored items in this tree"]
    assert reasons.storyline_why(lines) == (
        "ip 1.2.3.4: contacted by an unexpected program · a.exe sets an autorun registry key")
    assert reasons.storyline_why(["process b.exe: +20 file runs from a user-writable path (p)"]) \
        == "b.exe runs from a user folder"


def test_timeline_dark_option_uses_light_text():
    table = tl_table()
    rows = timeline_data.order_rows(table, set(table))
    light = timeline_chart.make_process_timeline(table, rows, {}, [], {})
    dark = timeline_chart.make_process_timeline(table, rows, {}, [], {}, dark=True)
    assert light["textStyle"]["color"] != dark["textStyle"]["color"]
    assert dark["legend"]["textStyle"]["color"] == dark["textStyle"]["color"]
    assert dark["yAxis"]["axisLabel"]["color"] == dark["textStyle"]["color"]


def test_resolve_dark():
    from web.theme import resolve_dark
    assert resolve_dark("dark", False) is True
    assert resolve_dark("light", True) is False
    assert resolve_dark("system", True) is True
    assert resolve_dark("system", False) is False
    assert resolve_dark("junk", True) is True


def test_score_level_groups_for_badges():
    assert timeline_data.score_level(0) == "normal"
    assert timeline_data.score_level(1) == "flagged"
    assert timeline_data.score_level(config.HIGH_SCORE - 1) == "flagged"
    assert timeline_data.score_level(config.HIGH_SCORE) == "high"
