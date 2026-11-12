"""Tests for storylines.py. Hand-made event lists only: no network, no
.evtx file. Event dicts carry just the fields storylines.py reads."""

from storylines import (
    NOT_REQUESTED,
    attach_activity,
    attach_ioc_results,
    build_process_table,
    build_storylines,
    link_children,
    score_storyline,
    walk_tree,
)

A, B, C, D = "{A}", "{B}", "{C}", "{D}"


def proc(guid, parent, image, time, parent_image=""):
    return {"event_id": 1, "time": time, "ProcessGuid": guid,
            "ParentProcessGuid": parent, "Image": image,
            "CommandLine": image + " /x", "ParentImage": parent_image,
            "ParentCommandLine": "", "User": "PC\\bob"}


def net(guid, ip, port, time="2024-01-01T00:00:05"):
    return {"event_id": 3, "time": time, "ProcessGuid": guid, "Image": "",
            "DestinationIp": ip, "DestinationPort": port}


def dns(guid, name):
    return {"event_id": 22, "time": "2024-01-01T00:00:06", "ProcessGuid": guid,
            "Image": "", "QueryName": name, "QueryStatus": "0"}


EVENTS = [
    proc(A, "{GONE}", "C:\\Windows\\explorer.exe", "2024-01-01T00:00:01"),
    proc(B, A, "C:\\Users\\bob\\Downloads\\invoice.pdf.exe",
         "2024-01-01T00:00:02", "C:\\Windows\\explorer.exe"),
    proc(C, B, "C:\\Windows\\System32\\cmd.exe", "2024-01-01T00:00:03"),
    proc(D, "", "C:\\Windows\\System32\\svchost.exe", "2024-01-01T00:00:04"),
]


def make_table(events):
    table = build_process_table(events)
    attach_activity(table, events)
    return table


def test_build_process_table_reads_event_1_only():
    table = build_process_table(EVENTS + [net(A, "1.2.3.4", "443")])
    assert sorted(table) == [A, B, C, D]
    assert table[B]["parent_guid"] == A
    assert table[B]["command_line"].endswith("/x")


def test_attach_activity_adds_ip_dns_and_dedupes():
    events = EVENTS + [net(B, "1.2.3.4", "443"), net(B, "1.2.3.4", "443"),
                       dns(B, "evil.example")]
    table = build_process_table(events)
    skipped = attach_activity(table, events)
    assert table[B]["ips"] == ["1.2.3.4:443"]
    assert table[B]["dns"] == ["evil.example"]
    assert skipped == 0


def test_attach_activity_makes_stub_and_counts_missing_guid():
    events = EVENTS + [net("{OLD}", "9.9.9.9", "80"), net("", "9.9.9.9", "80")]
    table = build_process_table(events)
    skipped = attach_activity(table, events)
    assert "{OLD}" in table and table["{OLD}"]["ips"] == ["9.9.9.9:80"]
    assert skipped == 1


def test_link_children_finds_roots_and_orders_children():
    table = make_table(EVENTS)
    roots = link_children(table)
    assert roots == [A, D]  # A's parent is not in the dump; D has none
    assert table[A]["children"] == [B]
    assert table[B]["children"] == [C]


def test_walk_tree_is_parent_first_and_survives_a_loop():
    table = make_table(EVENTS)
    link_children(table)
    assert walk_tree(table, A) == [A, B, C]
    table[C]["children"].append(A)  # corrupt data: a loop
    assert walk_tree(table, A) == [A, B, C]


def ranked_item(ioc_type, value, score, guids):
    return {"type": ioc_type, "value": value, "score": score,
            "reasons": ["+%d test" % score],
            "record": {"process_guids": guids}}


def test_attach_ioc_results_pairs_portal_answer_or_not_requested():
    table = make_table(EVENTS)
    ranked = [ranked_item("ip", "1.2.3.4", 30, [B]),
              ranked_item("dns", "evil.example", 20, [B, "{UNKNOWN}"])]
    results = [{"type": "ip", "value": "1.2.3.4", "status": "enriched",
                "score_0_to_100": 80, "label": "bad", "reasons": []}]
    attach_ioc_results(table, ranked, results)
    by_value = {i["value"]: i for i in table[B]["iocs"]}
    assert by_value["1.2.3.4"]["portal"]["score_0_to_100"] == 80
    assert by_value["evil.example"]["portal"] == NOT_REQUESTED
    assert by_value["1.2.3.4"]["local_score"] == 30


def test_score_storyline_uses_highest_item_not_a_sum():
    table = make_table(EVENTS)
    link_children(table)
    attach_ioc_results(table, [ranked_item("ip", "1.2.3.4", 30, [C]),
                               ranked_item("ip", "5.6.7.8", 10, [A])], [])
    process_scores = {A: {"score": 5, "signals": [(5, "small")]},
                      B: {"score": 50, "signals": [(50, "double extension")]}}
    score, reasons = score_storyline(table, A, process_scores)
    assert score == 50
    assert "process C:\\Users\\bob\\Downloads\\invoice.pdf.exe: +50 double extension" in reasons
    assert reasons[-1] == "highest of 4 scored items in this tree"


def test_score_storyline_with_nothing_scored_is_zero():
    table = make_table([proc(D, "", "C:\\x.exe", "t")])
    link_children(table)
    assert score_storyline(table, D, {}) == (0, [])


def test_build_storylines_sorts_highest_score_first():
    ranked = [ranked_item("ip", "1.2.3.4", 99, [D])]
    result = build_storylines(EVENTS, ranked, [])
    assert [s["root"] for s in result["storylines"]][0] == D
    assert result["storylines"][0]["score"] == 99
    assert result["storylines"][1]["size"] == 3
    assert result["events_without_guid"] == 0
