"""Tests for scoring/. Events are hand-built dicts, so the rules are checked
against the Sysmon schema and not against any sample dump.
"""

from iocs import collect_iocs
from parse import WANTED_FIELDS
from scoring.config import (WEIGHT_BEACONING, WEIGHT_DOUBLE_EXTENSION,
    WEIGHT_ENUMERATION, WEIGHT_LOOKALIKE, WEIGHT_ODD_PARENT,
    WEIGHT_REGISTRY_AUTORUN, WEIGHT_REGISTRY_REFERENCE,
    WEIGHT_RARE_NETWORK_PROCESS, WEIGHT_UNUSUAL_PORT, WEIGHT_USER_WRITABLE_PATH)
from scoring.domains import dns_signals, entropy, levenshtein
from scoring.findings import (dns_findings, enumeration_findings,
    find_findings, hash_persistence_signal, make_finding, network_findings)
from scoring.network import beaconing_signal, network_signals
from scoring.paths import parent_child_signal, path_signals
from scoring.processes import (build_process_scores, failed_lookup_signal,
    registry_persistence_signal)
from scoring.ranking import rank_iocs

CONFIG = {
    "ranges": [],
    "ad_domains": [],
    "well_known": ["google.com", "paypal.com", "microsoft.com"],
}
TEMP_EXE = "C:\\Users\\bob\\AppData\\Local\\Temp\\evil.exe"


def make_event(event_id, time="2024-05-01 10:00:00", computer="PC1", **fields):
    """A full event dict: every wanted field is "" unless given."""
    event = {"event_id": event_id, "time": time, "computer": computer}
    for name in WANTED_FIELDS[event_id]:
        event[name] = fields.get(name, "")
    return event


def points(signals):
    return [p for p, reason in signals]


# ---- path_signals ----

def test_user_writable_paths_fire():
    for path in ["C:\\Users\\bob\\x.exe", "C:\\Temp\\x.exe", "D:\\Downloads\\x.exe"]:
        assert points(path_signals(path)) == [WEIGHT_USER_WRITABLE_PATH]


def test_system_path_does_not_fire():
    assert path_signals("C:\\Windows\\System32\\cmd.exe") == []


def test_empty_path_is_unknown():
    assert path_signals("") == []


def test_double_extension_fires():
    assert points(path_signals("C:\\Windows\\movie.mp4.exe")) == [WEIGHT_DOUBLE_EXTENSION]


def test_single_extension_and_version_dots_do_not_fire():
    assert path_signals("C:\\Windows\\setup.exe") == []
    assert path_signals("C:\\Windows\\app.v2.exe") == []


# ---- parent_child_signal: the three rules ----

def test_rule1_document_app_starts_exe_or_script_host():
    assert points(parent_child_signal("C:\\Office\\WINWORD.EXE", "C:\\x\\a.exe")) == [WEIGHT_ODD_PARENT]
    assert points(parent_child_signal("C:\\A\\AcroRd32.exe", "C:\\Windows\\System32\\cmd.exe")) == [WEIGHT_ODD_PARENT]
    assert points(parent_child_signal("C:\\Office\\outlook.exe", "wscript")) == [WEIGHT_ODD_PARENT]


def test_rule1_document_app_starting_non_exe_does_not_fire():
    assert parent_child_signal("C:\\Office\\winword.exe", "C:\\x\\readme.txt") == []


def test_rule2_explorer_starts_from_temp():
    assert points(parent_child_signal("C:\\Windows\\explorer.exe", TEMP_EXE)) == [WEIGHT_ODD_PARENT]


def test_rule2_explorer_starting_normal_program_does_not_fire():
    assert parent_child_signal("C:\\Windows\\explorer.exe", "C:\\Windows\\notepad.exe") == []


def test_rule3_services_starts_from_user_writable_path():
    for child in [TEMP_EXE, "C:\\Users\\bob\\Downloads\\a.exe", "C:\\Users\\bob\\a.exe"]:
        assert points(parent_child_signal("C:\\Windows\\System32\\services.exe", child)) == [WEIGHT_ODD_PARENT]


def test_rule3_services_starting_system_program_does_not_fire():
    assert parent_child_signal("C:\\Windows\\System32\\services.exe",
                               "C:\\Windows\\System32\\svchost.exe") == []


def test_rule3_stacks_with_path_signals():
    child = TEMP_EXE
    total = (points(path_signals(child))
             + points(parent_child_signal("C:\\Windows\\System32\\services.exe", child)))
    assert total == [WEIGHT_USER_WRITABLE_PATH, WEIGHT_ODD_PARENT]


def test_parent_child_empty_parent_fires_nothing():
    assert parent_child_signal("", TEMP_EXE) == []


# ---- registry persistence ----

def test_registry_run_key_write_fires():
    event = make_event(13, EventType="SetValue",
                       TargetObject="HKU\\S-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater")
    assert points(registry_persistence_signal(event)) == [WEIGHT_REGISTRY_AUTORUN]


def test_registry_other_key_and_delete_do_not_fire():
    other = make_event(13, EventType="SetValue", TargetObject="HKLM\\Software\\Vendor\\Setting")
    deleted = make_event(12, EventType="DeleteKey",
                         TargetObject="HKU\\x\\CurrentVersion\\Run\\Updater")
    assert registry_persistence_signal(other) == []
    assert registry_persistence_signal(deleted) == []


def test_registry_signal_ignores_non_registry_events():
    assert registry_persistence_signal(make_event(1, Image=TEMP_EXE)) == []


# ---- failed lookups ----

def test_failed_lookup_threshold():
    assert failed_lookup_signal(5) != []
    assert failed_lookup_signal(4) == []


# ---- network_signals ----

POWERSHELL = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"


def test_rare_network_program_and_unusual_port():
    event = make_event(3, Image=POWERSHELL, Initiated="true",
                       DestinationIp="8.8.8.8", DestinationPort="4444")
    assert points(network_signals([event])) == [WEIGHT_RARE_NETWORK_PROCESS,
                                                 WEIGHT_UNUSUAL_PORT]


def test_normal_programs_on_normal_ports_fire_nothing():
    for image in ["C:\\Program Files\\Google\\chrome.exe",
                  "C:\\Users\\bob\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe",
                  "C:\\Windows\\System32\\svchost.exe", "C:\\x\\tool.exe"]:
        event = make_event(3, Image=image, Initiated="true", DestinationPort="443")
        assert network_signals([event]) == [], image


def test_inbound_connection_is_ignored_and_missing_fields_are_unknown():
    inbound = make_event(3, Image=POWERSHELL, Initiated="false", DestinationPort="4444")
    unknown = make_event(3, Initiated="true")
    assert network_signals([inbound, unknown]) == []


# ---- beaconing ----

def times_every(seconds, count):
    return ["2024-05-01 10:%02d:%02d.000000" % divmod(i * seconds, 60) for i in range(count)]


def test_regular_gaps_fire_beaconing():
    assert points(beaconing_signal(times_every(30, 6))) == [WEIGHT_BEACONING]


def test_irregular_gaps_do_not_fire():
    times = ["2024-05-01 10:00:%02d" % s for s in [0, 3, 40, 41, 58]]
    assert beaconing_signal(times) == []


def test_too_few_connections_or_too_fast_or_unreadable_times():
    assert beaconing_signal(times_every(30, 4)) == []
    assert beaconing_signal(["2024-05-01 10:00:00"] * 8) == []
    assert beaconing_signal(["", "garbage"] * 5) == []


# ---- entropy / levenshtein ----

def test_entropy_values():
    assert entropy("") == 0.0
    assert entropy("aaaa") == 0.0
    assert abs(entropy("abcd") - 2.0) < 1e-9


def test_levenshtein_values():
    assert levenshtein("paypal.com", "paypal.com") == 0
    assert levenshtein("paypal.com", "paypa1.com") == 1
    assert levenshtein("google.com", "gooogle.com") == 1
    assert levenshtein("", "abc") == 3
    assert levenshtein("google.com", "github.com") > 2


# ---- dns_signals ----

def test_long_label_fires():
    name = "a" * 35 + ".example.net"
    assert points(dns_signals(name, [])) == [20]


def test_high_entropy_label_fires_but_plain_word_does_not():
    assert points(dns_signals("x8k2jq9zv4mw7p.example.net", [])) == [20]
    assert dns_signals("downloads.example.net", []) == []


def test_lookalike_fires():
    signals = dns_signals("paypa1.com", CONFIG["well_known"])
    assert points(signals) == [30]


def test_real_name_and_its_subdomain_are_not_lookalikes():
    assert dns_signals("google.com", CONFIG["well_known"]) == []
    assert dns_signals("mail.google.com", CONFIG["well_known"]) == []


# ---- fixes: IFEO value and double counting ----

IFEO = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\"


def test_ifeo_debugger_value_fires_but_other_values_do_not():
    hijack = make_event(13, EventType="SetValue", TargetObject=IFEO + "notepad.exe\\Debugger")
    audit = make_event(13, EventType="SetValue", TargetObject=IFEO + "LSASS.exe\\AuditLevel")
    assert points(registry_persistence_signal(hijack)) == [WEIGHT_REGISTRY_AUTORUN]
    assert registry_persistence_signal(audit) == []


# ---- findings ----

def scores_for(events):
    """Run steps 2-4 on hand-built events: findings, then process scores."""
    iocs = collect_iocs(events)
    return build_process_scores(events, find_findings(events, iocs, CONFIG))


def test_make_finding_kind_follows_subject():
    assert make_finding("{A}", (5, "x"))["kind"] == "process"
    finding = make_finding("{A}", (5, "x"), ("ip", "1.2.3.4"))
    assert finding["kind"] == "subject" and finding["subject"] == ("ip", "1.2.3.4")


def test_process_scores_path_and_parent():
    events = [
        make_event(1, ProcessGuid="{A}", Image=TEMP_EXE,
                   ParentImage="C:\\Office\\winword.exe"),
        make_event(1, ProcessGuid="{B}", Image="C:\\Windows\\System32\\svchost.exe",
                   ParentImage="C:\\Windows\\System32\\services.exe"),
    ]
    scores = scores_for(events)
    assert scores["{A}"]["score"] == WEIGHT_USER_WRITABLE_PATH + WEIGHT_ODD_PARENT
    assert all(f["kind"] == "process" for f in scores["{A}"]["findings"])
    assert scores["{B}"] == {"image": "C:\\Windows\\System32\\svchost.exe",
                             "score": 0, "findings": []}


def test_process_signal_counted_once_per_process():
    key = "HKU\\x\\CurrentVersion\\Run\\a"
    events = [make_event(13, ProcessGuid="{A}", Image="C:\\Windows\\x.exe",
                         EventType="SetValue", TargetObject=key)] * 3
    assert scores_for(events)["{A}"]["score"] == WEIGHT_REGISTRY_AUTORUN


def test_failed_lookups_counted_per_process_across_names():
    events = [make_event(22, ProcessGuid="{A}", Image="C:\\Windows\\x.exe",
                         QueryName="n%d.example.com" % i, QueryStatus="9003")
              for i in range(5)]
    events.append(make_event(22, ProcessGuid="{B}", Image="C:\\Windows\\y.exe",
                             QueryName="z.example.com", QueryStatus="9003"))
    events.append(make_event(22, ProcessGuid="{B}", Image="C:\\Windows\\y.exe",
                             QueryName="ok.example.com", QueryStatus="0"))
    scores = scores_for(events)
    assert scores["{A}"]["score"] == 15
    assert scores["{B}"]["score"] == 0


def test_empty_query_status_is_not_a_failure():
    events = [make_event(22, ProcessGuid="{A}", Image="C:\\Windows\\x.exe",
                         QueryName="n%d.example.com" % i, QueryStatus="")
              for i in range(6)]
    assert scores_for(events)["{A}"]["score"] == 0


def test_network_findings_are_per_process_and_ip():
    events = [
        make_event(3, ProcessGuid="{T}", Image=POWERSHELL, Initiated="true",
                   DestinationIp="8.8.8.8", DestinationPort="4444"),
        make_event(3, ProcessGuid="{C}", Image="C:\\Program Files\\chrome.exe",
                   Initiated="true", DestinationIp="8.8.8.8", DestinationPort="443"),
    ]
    found = network_findings(events)
    assert [(f["guid"], f["points"]) for f in found] == [
        ("{T}", WEIGHT_RARE_NETWORK_PROCESS), ("{T}", WEIGHT_UNUSUAL_PORT)]
    assert all(f["subject"] == ("ip", "8.8.8.8") for f in found)


def test_dns_findings_go_to_every_process_that_asked():
    events = [make_event(22, ProcessGuid=guid, QueryName="PayPa1.com.")
              for guid in ["{A}", "{B}", "{A}"]]
    found = dns_findings(events, CONFIG["well_known"])
    assert [f["guid"] for f in found] == ["{A}", "{B}"]
    assert found[0]["subject"] == ("dns", "paypa1.com")
    assert found[0]["points"] == WEIGHT_LOOKALIKE


# ---- hash findings ----

def test_registry_reference_matches_full_path_only():
    key_event = make_event(13, EventType="SetValue",
                           TargetObject="HKU\\x\\CurrentVersion\\Run\\a",
                           Details=TEMP_EXE.upper())
    assert points(hash_persistence_signal([TEMP_EXE], [key_event])) == [40]
    # a bare filename never matches
    bare = make_event(13, EventType="SetValue", TargetObject="x", Details="evil.exe")
    assert hash_persistence_signal([TEMP_EXE], [bare]) == []


def test_registry_reference_via_target_object():
    event = make_event(12, EventType="CreateKey",
                       TargetObject="HKU\\x\\CurrentVersion\\Run\\" + TEMP_EXE)
    assert hash_persistence_signal([TEMP_EXE], [event]) != []


def test_registry_reference_outside_autorun_keys_is_ignored():
    inventory = make_event(13, EventType="SetValue",
                           TargetObject="HKLM\\x\\InventoryApplicationFile\\evil.exe|123\\LowerCaseLongPath",
                           Details=TEMP_EXE.lower())
    assert hash_persistence_signal([TEMP_EXE], [inventory]) == []


def test_hash_reference_ignores_writes_by_its_own_process():
    own_write = make_event(13, ProcessGuid="{A}", EventType="SetValue",
                           TargetObject="HKU\\x\\CurrentVersion\\Run\\a", Details=TEMP_EXE)
    assert hash_persistence_signal([TEMP_EXE], [own_write], ["{A}"]) == []
    assert points(hash_persistence_signal([TEMP_EXE], [own_write], ["{OTHER}"])) == [40]


HASH = "a" * 64


def test_hash_finding_lands_on_the_process_that_ran_the_file():
    events = [
        make_event(1, ProcessGuid="{A}", Image=TEMP_EXE, ParentImage="C:\\x\\p.exe",
                   Hashes="SHA256=" + HASH.upper()),
        make_event(13, ProcessGuid="{W}", Image="C:\\Windows\\reg.exe", EventType="SetValue",
                   TargetObject="HKU\\x\\CurrentVersion\\Run\\a", Details=TEMP_EXE),
    ]
    scores = scores_for(events)
    subject = [f for f in scores["{A}"]["findings"] if f["kind"] == "subject"]
    assert [(f["points"], f["subject"]) for f in subject] == [
        (WEIGHT_REGISTRY_REFERENCE, ("hash", HASH))]
    # the writer gets its own autorun finding, not the hash one
    assert scores["{W}"]["score"] == WEIGHT_REGISTRY_AUTORUN


# ---- enumeration burst ----

def child(name, second, parent="{SH}"):
    return make_event(1, time="2024-05-01 10:00:%02d" % second,
                      ProcessGuid="{%s%d}" % (name, second),
                      Image="C:\\Windows\\System32\\%s.exe" % name,
                      ParentProcessGuid=parent)


def test_enumeration_burst_goes_to_the_parent():
    events = [child("whoami", 0), child("ipconfig", 10), child("net", 20)]
    found = enumeration_findings(events)
    assert len(found) == 1
    assert found[0]["guid"] == "{SH}" and found[0]["points"] == WEIGHT_ENUMERATION
    assert "whoami, ipconfig, net" in found[0]["reason"]


def test_enumeration_needs_enough_commands_in_the_window():
    assert enumeration_findings([child("whoami", 0), child("net", 10)]) == []
    spread = [child("whoami", 0),
              make_event(1, time="2024-05-01 10:10:00", ProcessGuid="{N}",
                         Image="C:\\Windows\\System32\\net.exe", ParentProcessGuid="{SH}"),
              make_event(1, time="2024-05-01 10:20:00", ProcessGuid="{I}",
                         Image="C:\\Windows\\System32\\ipconfig.exe", ParentProcessGuid="{SH}")]
    assert enumeration_findings(spread) == []


def test_enumeration_is_counted_per_parent_and_ignores_other_programs():
    events = [child("whoami", 0, "{X}"), child("net", 5, "{Y}"),
              child("ipconfig", 9, "{X}"), child("notepad", 12, "{X}")]
    assert enumeration_findings(events) == []


def test_process_with_findings_but_no_event_gets_an_entry():
    events = [child("whoami", 0), child("ipconfig", 10), child("net", 20)]
    scores = scores_for(events)
    assert scores["{SH}"]["image"] == "" and scores["{SH}"]["score"] == WEIGHT_ENUMERATION


# ---- rank_iocs: split inheritance ----

def item(ioc_type, value, guids, count=1, first_seen=""):
    return {"type": ioc_type, "value": value,
            "record": {"count": count, "first_seen": first_seen, "process_guids": guids}}


def test_ioc_inherits_process_findings_of_the_strongest_process_only():
    events = [
        make_event(1, ProcessGuid="{BAD}", Image=TEMP_EXE, ParentImage="C:\\Office\\winword.exe"),
        make_event(1, ProcessGuid="{OK}", Image="C:\\Windows\\System32\\svchost.exe",
                   ParentImage="C:\\Windows\\System32\\services.exe"),
        make_event(3, ProcessGuid="{BAD}", Image=TEMP_EXE, Initiated="true",
                   DestinationIp="8.8.8.8", DestinationPort="4444"),
        make_event(3, ProcessGuid="{OK}", Image="C:\\Windows\\System32\\svchost.exe",
                   Initiated="true", DestinationIp="8.8.8.8", DestinationPort="4444"),
    ]
    ranked = rank_iocs([item("ip", "8.8.8.8", ["{OK}", "{BAD}"])], scores_for(events))
    # the unusual-port reason is the same text from both processes, so it
    # counts once; plus {BAD}'s process findings once ({OK} has none)
    assert ranked[0]["score"] == (WEIGHT_UNUSUAL_PORT
                                  + WEIGHT_USER_WRITABLE_PATH + WEIGHT_ODD_PARENT)
    assert any("process evil.exe:" in reason for reason in ranked[0]["reasons"])


def test_process_score_counts_a_repeated_reason_once():
    events = [make_event(3, ProcessGuid="{P}", Image=POWERSHELL, Initiated="true",
                         DestinationIp="8.8.8.%d" % i, DestinationPort="443")
              for i in range(1, 31)]
    process = scores_for(events)["{P}"]
    # 30 IPs, 30 findings kept for the IOC table, but scored once
    assert len([f for f in process["findings"] if f["kind"] == "subject"]) == 30
    assert process["score"] == WEIGHT_RARE_NETWORK_PROCESS


def test_process_score_counts_different_reasons_separately():
    events = [make_event(3, ProcessGuid="{P}", Image="C:\\Windows\\x.exe", Initiated="true",
                         DestinationIp="8.8.8.%d" % i, DestinationPort=port)
              for i, port in [(1, "4444"), (2, "8080"), (3, "4444")]]
    assert scores_for(events)["{P}"]["score"] == 2 * WEIGHT_UNUSUAL_PORT


def test_subject_finding_does_not_spread_to_other_iocs_of_the_same_process():
    events = [make_event(22, ProcessGuid="{C}", Image="C:\\Program Files\\chrome.exe",
                         QueryName=name) for name in ["paypa1.com", "example.org"]]
    ranked = rank_iocs([item("dns", "paypa1.com", ["{C}"]),
                        item("dns", "example.org", ["{C}"])], scores_for(events))
    by_value = {r["value"]: r["score"] for r in ranked}
    assert by_value == {"paypa1.com": WEIGHT_LOOKALIKE, "example.org": 0}


def test_same_subject_reason_from_many_processes_counts_once():
    events = [make_event(22, ProcessGuid=guid, QueryName="paypa1.com")
              for guid in ["{A}", "{B}", "{C}"]]
    ranked = rank_iocs([item("dns", "paypa1.com", ["{A}", "{B}", "{C}"])],
                       scores_for(events))
    assert ranked[0]["score"] == WEIGHT_LOOKALIKE


def test_file_that_sets_its_own_autorun_is_counted_once():
    key = "HKU\\x\\CurrentVersion\\Run\\a"
    events = [
        make_event(1, ProcessGuid="{A}", Image=TEMP_EXE, ParentImage="C:\\x\\p.exe",
                   Hashes="SHA256=" + HASH),
        make_event(13, ProcessGuid="{A}", Image=TEMP_EXE, EventType="SetValue",
                   TargetObject=key, Details=TEMP_EXE),
    ]
    ranked = rank_iocs([item("hash", HASH, ["{A}"])], scores_for(events))
    assert ranked[0]["score"] == WEIGHT_USER_WRITABLE_PATH + WEIGHT_REGISTRY_AUTORUN


def test_rank_order_ties_broken_by_count_then_first_seen():
    to_rank = [item("dns", "a.example.com", [], 1, "2024-01-02"),
               item("dns", "b.example.com", [], 3, "2024-01-03"),
               item("dns", "c.example.com", [], 1, "2024-01-01")]
    ranked = rank_iocs(to_rank, {})
    assert [r["value"] for r in ranked] == ["b.example.com", "c.example.com", "a.example.com"]

