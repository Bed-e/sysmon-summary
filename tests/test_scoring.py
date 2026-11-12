"""Tests for scoring/. Events are hand-built dicts, so the rules are checked
against the Sysmon schema and not against any sample dump.
"""

from parse import WANTED_FIELDS
from scoring.config import (WEIGHT_BEACONING, WEIGHT_DOUBLE_EXTENSION,
    WEIGHT_ODD_PARENT, WEIGHT_REGISTRY_AUTORUN, WEIGHT_TRUSTED_PATH,
    WEIGHT_USER_WRITABLE_PATH)
from scoring.domains import dns_signals, entropy, levenshtein
from scoring.network import beaconing_signal, network_signals
from scoring.paths import parent_child_signal, path_signals
from scoring.processes import (build_process_scores, failed_lookup_signal,
    registry_persistence_signal)
from scoring.ranking import (hash_persistence_signal, rank_iocs, score_ioc,
    trusted_path_adjustment)

CONFIG = {
    "ranges": [],
    "ad_domains": [],
    "trusted_paths": ["c:\\windows\\system32\\", "c:\\program files\\"],
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


# ---- build_process_scores ----

def test_process_scores_path_parent_and_inheritance_sources():
    events = [
        make_event(1, ProcessGuid="{A}", Image=TEMP_EXE,
                   ParentImage="C:\\Office\\winword.exe"),
        make_event(1, ProcessGuid="{B}", Image="C:\\Windows\\System32\\svchost.exe",
                   ParentImage="C:\\Windows\\System32\\services.exe"),
    ]
    scores = build_process_scores(events)
    assert scores["{A}"]["score"] == WEIGHT_USER_WRITABLE_PATH + WEIGHT_ODD_PARENT
    assert scores["{B}"]["score"] == 0


def test_process_signal_counted_once_per_process():
    key = "HKU\\x\\CurrentVersion\\Run\\a"
    events = [make_event(13, ProcessGuid="{A}", Image="C:\\Windows\\x.exe",
                         EventType="SetValue", TargetObject=key)] * 3
    assert build_process_scores(events)["{A}"]["score"] == WEIGHT_REGISTRY_AUTORUN


def test_failed_lookups_counted_per_process_across_names():
    events = [make_event(22, ProcessGuid="{A}", Image="C:\\Windows\\x.exe",
                         QueryName="n%d.example.com" % i, QueryStatus="9003")
              for i in range(5)]
    events.append(make_event(22, ProcessGuid="{B}", Image="C:\\Windows\\y.exe",
                             QueryName="z.example.com", QueryStatus="9003"))
    events.append(make_event(22, ProcessGuid="{B}", Image="C:\\Windows\\y.exe",
                             QueryName="ok.example.com", QueryStatus="0"))
    scores = build_process_scores(events)
    assert scores["{A}"]["score"] == 15
    assert scores["{B}"]["score"] == 0


def test_empty_query_status_is_not_a_failure():
    events = [make_event(22, ProcessGuid="{A}", Image="C:\\Windows\\x.exe",
                         QueryName="n%d.example.com" % i, QueryStatus="")
              for i in range(6)]
    assert build_process_scores(events)["{A}"]["score"] == 0


# ---- network_signals ----

def test_unexpected_process_and_unusual_port():
    event = make_event(3, Image="C:\\x\\tool.exe", Initiated="true",
                       DestinationIp="8.8.8.8", DestinationPort="4444")
    assert points(network_signals([event])) == [20, 10]


def test_browser_on_normal_port_fires_nothing():
    event = make_event(3, Image="C:\\Program Files\\Google\\chrome.exe",
                       Initiated="true", DestinationPort="443")
    assert network_signals([event]) == []


def test_inbound_connection_is_ignored_and_missing_fields_are_unknown():
    inbound = make_event(3, Image="C:\\x\\tool.exe", Initiated="false", DestinationPort="4444")
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


# ---- hash signals ----

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


def test_trusted_path_adjustment_all_paths_must_be_trusted():
    trusted = CONFIG["trusted_paths"]
    assert points(trusted_path_adjustment(["C:\\Windows\\System32\\a.exe"], trusted)) == [WEIGHT_TRUSTED_PATH]
    assert trusted_path_adjustment(["C:\\Windows\\System32\\a.exe", TEMP_EXE], trusted) == []
    assert trusted_path_adjustment([], trusted) == []


# ---- score_ioc / rank_iocs ----

def test_ioc_inherits_only_the_highest_scoring_process():
    events = [
        make_event(1, ProcessGuid="{BAD}", Image=TEMP_EXE,
                   ParentImage="C:\\Office\\winword.exe"),
        make_event(1, ProcessGuid="{OK}", Image="C:\\Windows\\System32\\svchost.exe",
                   ParentImage="C:\\Windows\\System32\\services.exe"),
        make_event(3, ProcessGuid="{BAD}", Image=TEMP_EXE, Initiated="true",
                   DestinationIp="8.8.8.8", DestinationPort="443"),
        make_event(3, ProcessGuid="{OK}", Image="C:\\Windows\\System32\\svchost.exe",
                   Initiated="true", DestinationIp="8.8.8.8", DestinationPort="443"),
    ]
    item = {"type": "ip", "value": "8.8.8.8",
            "record": {"count": 2, "first_seen": "", "process_guids": ["{OK}", "{BAD}"]}}
    process_scores = build_process_scores(events)
    from scoring.ranking import group_ip_events
    score, reasons = score_ioc(item, process_scores, group_ip_events(events), [], CONFIG)
    # network: unexpected process (+20); inherited from {BAD} only: 20 + 25
    assert score == 20 + WEIGHT_USER_WRITABLE_PATH + WEIGHT_ODD_PARENT
    assert any("evil.exe" in reason for reason in reasons)


def test_hash_inherits_path_points_once_from_its_process():
    events = [make_event(1, ProcessGuid="{A}", Image=TEMP_EXE, ParentImage="C:\\x\\a.exe")]
    item = {"type": "hash", "value": "a" * 64,
            "record": {"count": 1, "first_seen": "", "process_guids": ["{A}"],
                       "images": [TEMP_EXE]}}
    score, reasons = score_ioc(item, build_process_scores(events), {}, [], CONFIG)
    assert score == WEIGHT_USER_WRITABLE_PATH
    assert len(reasons) == 1


def test_trusted_hash_is_ranked_below_untrusted_but_not_removed():
    events = [
        make_event(1, ProcessGuid="{T}", Image="C:\\Windows\\System32\\a.exe", ParentImage="C:\\x\\p.exe"),
        make_event(1, ProcessGuid="{U}", Image=TEMP_EXE, ParentImage="C:\\x\\p.exe"),
    ]
    to_rank = [
        {"type": "hash", "value": "t" * 64,
         "record": {"count": 5, "first_seen": "", "process_guids": ["{T}"],
                    "images": ["C:\\Windows\\System32\\a.exe"]}},
        {"type": "hash", "value": "u" * 64,
         "record": {"count": 1, "first_seen": "", "process_guids": ["{U}"],
                    "images": [TEMP_EXE]}},
    ]
    ranked = rank_iocs(to_rank, events, CONFIG)
    assert [r["value"] for r in ranked] == ["u" * 64, "t" * 64]
    assert ranked[1]["score"] == WEIGHT_TRUSTED_PATH


def test_rank_order_ties_broken_by_count_then_first_seen():
    to_rank = [
        {"type": "dns", "value": "a.example.com",
         "record": {"count": 1, "first_seen": "2024-01-02", "process_guids": []}},
        {"type": "dns", "value": "b.example.com",
         "record": {"count": 3, "first_seen": "2024-01-03", "process_guids": []}},
        {"type": "dns", "value": "c.example.com",
         "record": {"count": 1, "first_seen": "2024-01-01", "process_guids": []}},
    ]
    ranked = rank_iocs(to_rank, [], CONFIG)
    assert [r["value"] for r in ranked] == ["b.example.com", "c.example.com", "a.example.com"]


# ---- fixes: IFEO value and double counting ----

IFEO = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\"


def test_ifeo_debugger_value_fires_but_other_values_do_not():
    hijack = make_event(13, EventType="SetValue", TargetObject=IFEO + "notepad.exe\\Debugger")
    audit = make_event(13, EventType="SetValue", TargetObject=IFEO + "LSASS.exe\\AuditLevel")
    assert points(registry_persistence_signal(hijack)) == [WEIGHT_REGISTRY_AUTORUN]
    assert registry_persistence_signal(audit) == []


def test_hash_reference_ignores_writes_by_its_own_process():
    own_write = make_event(13, ProcessGuid="{A}", EventType="SetValue",
                           TargetObject="HKU\\x\\CurrentVersion\\Run\\a", Details=TEMP_EXE)
    assert hash_persistence_signal([TEMP_EXE], [own_write], ["{A}"]) == []
    # the same write by a different process still counts
    assert points(hash_persistence_signal([TEMP_EXE], [own_write], ["{OTHER}"])) == [40]


def test_file_that_sets_its_own_autorun_is_counted_once():
    key = "HKU\\x\\CurrentVersion\\Run\\a"
    events = [
        make_event(1, ProcessGuid="{A}", Image=TEMP_EXE, ParentImage="C:\\x\\p.exe"),
        make_event(13, ProcessGuid="{A}", Image=TEMP_EXE, EventType="SetValue",
                   TargetObject=key, Details=TEMP_EXE),
    ]
    item = {"type": "hash", "value": "a" * 64,
            "record": {"count": 1, "first_seen": "", "process_guids": ["{A}"],
                       "images": [TEMP_EXE]}}
    registry = [e for e in events if e["event_id"] == 13]
    score, reasons = score_ioc(item, build_process_scores(events), {}, registry, CONFIG)
    assert score == WEIGHT_USER_WRITABLE_PATH + WEIGHT_REGISTRY_AUTORUN
