"""Tests for chains.py. Hand-made event lists only: no network, no
.evtx file. Event dicts carry just the fields chains.py reads."""

from chains import (
    attach_activity,
    attach_iocs,
    build_chains,
    build_process_table,
    find_dropped_by,
    link_children,
    strongest_finding,
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


# ---- attach_iocs ----

def test_attach_iocs_lists_type_and_value_per_process():
    table = make_table(EVENTS)
    iocs = {"ip": {"1.2.3.4": {"process_guids": [B, "{UNKNOWN}"]}},
            "dns": {"evil.example": {"process_guids": [B, C]}},
            "hash": {}}
    attach_iocs(table, iocs)
    assert table[B]["iocs"] == [("ip", "1.2.3.4"), ("dns", "evil.example")]
    assert table[C]["iocs"] == [("dns", "evil.example")]
    assert table[A]["iocs"] == []


# ---- find_dropped_by ----

def written(guid, path, time, image="C:\\Program Files\\Google\\chrome.exe"):
    return {"event_id": 11, "time": time, "ProcessGuid": guid, "Image": image,
            "TargetFilename": path}


def test_dropped_by_finds_the_earliest_other_writer():
    events = EVENTS + [
        proc("{CH}", "", "C:\\Program Files\\Google\\chrome.exe", "2024-01-01T00:00:00"),
        written("{CH}", "c:\\users\\bob\\downloads\\INVOICE.PDF.EXE", "2024-01-01T00:00:01"),
        written("{X}", "C:\\Users\\bob\\Downloads\\invoice.pdf.exe", "2024-01-01T00:00:01.5",
                image="C:\\x\\other.exe"),
    ]
    table = make_table(events)
    find_dropped_by(table, events)
    assert table[B]["dropped_by"] == {"guid": "{CH}",
                                      "image": "C:\\Program Files\\Google\\chrome.exe",
                                      "time": "2024-01-01T00:00:01"}
    assert table[A]["dropped_by"] is None


def test_dropped_by_ignores_a_process_writing_its_own_file():
    events = EVENTS + [written(B, "C:\\Users\\bob\\Downloads\\invoice.pdf.exe",
                               "2024-01-01T00:00:03")]
    table = make_table(events)
    find_dropped_by(table, events)
    assert table[B]["dropped_by"] is None


# ---- strongest_finding / build_chains ----

def finding(guid, points, reason, subject=None):
    return {"guid": guid, "points": points, "reason": reason,
            "kind": "process" if subject is None else "subject", "subject": subject}


def scores(**by_guid):
    table = {}
    for guid, findings in by_guid.items():
        table["{%s}" % guid] = {"image": "", "findings": findings,
                                "score": sum(f["points"] for f in findings)}
    return table


def test_strongest_finding_is_highest_points_then_earliest():
    process_scores = scores(A=[finding(A, 20, "user path")],
                            B=[finding(B, 50, "double extension"),
                               finding(B, 20, "user path")],
                            C=[finding(C, 50, "late tie")])
    assert strongest_finding([A, B, C], process_scores)["reason"] == "double extension"
    assert strongest_finding([D], process_scores) is None


def test_build_chains_keeps_only_flagged_trees_and_ranks_them():
    iocs = {"ip": {}, "dns": {}, "hash": {}}
    process_scores = scores(B=[finding(B, 50, "double extension")],
                            C=[finding(C, 20, "c2", ("ip", "1.2.3.4"))])
    result = build_chains(EVENTS, iocs, process_scores)
    assert [c["root"] for c in result["chains"]] == [A]
    chain = result["chains"][0]
    assert chain["score"] == 50
    assert chain["guids"] == [A, B, C]
    assert chain["flagged"] == [B, C]
    assert chain["title_finding"]["reason"] == "double extension"
    assert result["other"] == [D]
    assert result["events_without_guid"] == 0


def test_build_chains_sorts_by_score_then_size():
    iocs = {"ip": {}, "dns": {}, "hash": {}}
    process_scores = scores(C=[finding(C, 10, "small")], D=[finding(D, 40, "big")])
    result = build_chains(EVENTS, iocs, process_scores)
    assert [c["root"] for c in result["chains"]] == [D, A]
    assert result["other"] == []


