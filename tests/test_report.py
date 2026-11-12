"""Tests for report.py. Hand-made data only: no network, no .evtx file."""

from report import (
    NOT_A_VERDICT,
    build_counts_section,
    build_report,
    build_skipped_table,
    describe_portal,
    escape_text,
    write_report,
)
from storylines import build_storylines


def event_1(guid, parent, image, command_line="x"):
    return {"event_id": 1, "time": "2024-01-01T00:00:01", "ProcessGuid": guid,
            "ParentProcessGuid": parent, "Image": image,
            "CommandLine": command_line, "ParentImage": "", "ParentCommandLine": "",
            "User": "PC\\bob"}


def ioc_item(value, score=30):
    return {"type": "ip", "value": value, "score": score, "reasons": ["+30 test"],
            "record": {"process_guids": ["{A}"], "count": 2}}


def make_report(command_line="cmd /c x", results=None, skipped=None):
    events = [event_1("{A}", "", "C:\\x\\a.exe", command_line)]
    ranked = [ioc_item("1.2.3.4")]
    iocs = {"ip": {"1.2.3.4": {}}, "dns": {}, "hash": {}}
    skipped = skipped if skipped is not None else []
    stories = build_storylines(events, ranked, results or [])
    return build_report("dump.evtx", iocs, skipped, ranked, results or [], 25, stories)


def test_escape_text_handles_none_and_markup():
    assert escape_text(None) == ""
    assert escape_text("<b>&") == "&lt;b&gt;&amp;"
    assert escape_text(5) == "5"


def test_report_has_the_not_a_verdict_note():
    assert escape_text(NOT_A_VERDICT) in make_report()


def test_hostile_command_line_is_escaped():
    page = make_report(command_line="<script>alert(1)</script>")
    assert "<script>" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page


def test_counts_split_looked_up_failed_and_over_cap():
    results = [
        {"status": "enriched", "reasons": []},
        {"status": "partial", "reasons": []},
        {"status": "not_enriched", "reasons": ["portal returned 503"]},
        {"status": "not_enriched", "reasons": ["over the cap of 2 lookups"]},
    ]
    text = build_counts_section({"ip": 2, "dns": 1, "hash": 1}, [1, 2, 3, 4],
                                [], results, 2)
    assert "<th>IOCs found</th><td>4 (IPs 2, DNS names 1, hashes 1)</td>" in text
    assert "<th>Looked up on the portals</th><td>2</td>" in text
    assert "<th>Lookup failed (not enriched)</th><td>1</td>" in text
    assert "<th>Not looked up: over the cap of 2</th><td>1</td>" in text


def test_counts_say_not_requested_without_results():
    text = build_counts_section({"ip": 0, "dns": 0, "hash": 0}, [], [], [], 25)
    assert "not requested" in text


def test_skipped_table_shows_reason_code_and_none_case():
    skipped = [{"type": "ip", "value": "10.0.0.1", "reason": "ip_not_public",
                "record": {"count": 3}}]
    table = build_skipped_table(skipped)
    assert "ip_not_public" in table and "10.0.0.1" in table
    assert "none" in build_skipped_table([])


def test_not_enriched_shows_reason_not_a_score():
    portal = {"status": "not_enriched", "reasons": ["portal returned 503"],
              "score_0_to_100": None, "label": None}
    text = describe_portal(portal)
    assert "NOT ENRICHED: portal returned 503" in text
    assert "None" not in text


def test_enriched_and_partial_show_score_and_label():
    portal = {"status": "partial", "reasons": [], "score_0_to_100": 80,
              "label": "bad"}
    text = describe_portal(portal)
    assert "portal 80 (bad)" in text and "partial" in text
    assert "not requested" in describe_portal("not requested")


def test_zero_score_storyline_starts_collapsed():
    events = [event_1("{A}", "", "C:\\Windows\\System32\\svchost.exe")]
    stories = build_storylines(events, [], [])
    page = build_report("d.evtx", {"ip": {}, "dns": {}, "hash": {}}, [], [], [],
                        25, stories)
    assert stories["storylines"][0]["score"] == 0
    assert "<details>" in page and "<details open>" not in page


def test_write_report_saves_utf8(tmp_path):
    out = tmp_path / "r.html"
    assert write_report("héllo", str(out)) == str(out)
    assert out.read_text(encoding="utf-8") == "héllo"
