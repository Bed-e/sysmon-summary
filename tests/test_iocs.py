"""Tests for iocs.py. Events are hand-built dicts, so the rules are checked
against the Sysmon schema and not against any sample dump.
"""

from iocs import (
    add_sighting,
    collect_iocs,
    ip_from_event,
    is_valid_hash,
    normalize_dns,
    normalize_ip,
    pick_hash,
)
from parse import WANTED_FIELDS

SHA256 = "a" * 64
SHA1 = "b" * 40
MD5 = "c" * 32


def make_event(event_id, time="2024-05-01 10:00:00", computer="PC1", **fields):
    """A full event dict: every wanted field is "" unless given."""
    event = {"event_id": event_id, "time": time, "computer": computer}
    for name in WANTED_FIELDS[event_id]:
        event[name] = fields.get(name, "")
    return event


# ---- normalize_ip ----

def test_normalize_ip_accepts_ipv4_and_strips_spaces():
    assert normalize_ip(" 8.8.8.8 ") == "8.8.8.8"


def test_normalize_ip_rejects_ipv6():
    assert normalize_ip("2001:db8::1") is None


def test_normalize_ip_rejects_garbage_and_empty():
    assert normalize_ip("not-an-ip") is None
    assert normalize_ip("") is None
    assert normalize_ip("999.1.1.1") is None


def test_normalize_ip_keeps_private_addresses():
    # Private addresses are the filter's job (filters.py), not this step's.
    assert normalize_ip("192.168.1.5") == "192.168.1.5"


# ---- normalize_dns ----

def test_normalize_dns_lowercases_and_strips_trailing_dot():
    assert normalize_dns(" Example.COM. ") == "example.com"


def test_normalize_dns_empty_is_none():
    assert normalize_dns("") is None
    assert normalize_dns("  ") is None
    assert normalize_dns(".") is None


def test_normalize_dns_keeps_internal_names():
    assert normalize_dns("printer.local") == "printer.local"


# ---- is_valid_hash / pick_hash ----

def test_is_valid_hash_checks_length_and_hex():
    assert is_valid_hash("sha256", SHA256)
    assert is_valid_hash("sha1", SHA1)
    assert is_valid_hash("md5", MD5)
    assert not is_valid_hash("sha256", SHA1)          # wrong length
    assert not is_valid_hash("md5", "z" * 32)         # not hex
    assert not is_valid_hash("md5", "C" * 32)         # not lowercase
    assert not is_valid_hash("imphash", MD5)          # unknown algorithm
    assert not is_valid_hash("md5", "")


def test_pick_hash_prefers_sha256_then_sha1_then_md5():
    assert pick_hash({"md5": MD5, "sha1": SHA1, "sha256": SHA256}) == ("sha256", SHA256)
    assert pick_hash({"md5": MD5, "sha1": SHA1}) == ("sha1", SHA1)
    assert pick_hash({"md5": MD5}) == ("md5", MD5)


def test_pick_hash_falls_through_when_preferred_is_malformed():
    assert pick_hash({"sha256": "short", "md5": MD5}) == ("md5", MD5)


def test_pick_hash_ignores_imphash_and_empty():
    assert pick_hash({"imphash": MD5}) is None
    assert pick_hash({}) is None


# ---- ip_from_event ----

def test_ip_from_event_outbound_uses_destination():
    event = make_event(3, Initiated="true", SourceIp="10.0.0.5", DestinationIp="8.8.8.8")
    assert ip_from_event(event) == "8.8.8.8"


def test_ip_from_event_inbound_uses_source():
    event = make_event(3, Initiated="false", SourceIp="8.8.4.4", DestinationIp="10.0.0.5")
    assert ip_from_event(event) == "8.8.4.4"


def test_ip_from_event_unknown_direction_uses_destination():
    event = make_event(3, Initiated="", SourceIp="10.0.0.5", DestinationIp="8.8.8.8")
    assert ip_from_event(event) == "8.8.8.8"


# ---- add_sighting ----

def test_add_sighting_counts_and_tracks_times_hosts_guids():
    table = {}
    add_sighting(table, "k", make_event(22, time="2024-05-01 10:00:05", computer="A", ProcessGuid="{1}"))
    add_sighting(table, "k", make_event(22, time="2024-05-01 10:00:01", computer="B", ProcessGuid="{2}"))
    add_sighting(table, "k", make_event(22, time="2024-05-01 10:00:09", computer="A", ProcessGuid="{1}"))
    assert table["k"] == {
        "count": 3,
        "first_seen": "2024-05-01 10:00:01",
        "last_seen": "2024-05-01 10:00:09",
        "hosts": ["A", "B"],
        "process_guids": ["{1}", "{2}"],
    }


def test_add_sighting_ignores_empty_guid_and_time():
    table = {}
    add_sighting(table, "k", make_event(22, time="", computer="", ProcessGuid=""))
    record = table["k"]
    assert record["count"] == 1
    assert record["first_seen"] == "" and record["last_seen"] == ""
    assert record["hosts"] == [] and record["process_guids"] == []


# ---- collect_iocs ----

def test_collect_iocs_dedupes_ips_and_counts():
    events = [
        make_event(3, Initiated="true", DestinationIp="8.8.8.8", ProcessGuid="{1}"),
        make_event(3, Initiated="true", DestinationIp="8.8.8.8", ProcessGuid="{2}"),
        make_event(3, Initiated="true", DestinationIp="1.1.1.1", ProcessGuid="{1}"),
    ]
    iocs = collect_iocs(events)
    assert sorted(iocs["ip"]) == ["1.1.1.1", "8.8.8.8"]
    assert iocs["ip"]["8.8.8.8"]["count"] == 2
    assert iocs["ip"]["8.8.8.8"]["process_guids"] == ["{1}", "{2}"]


def test_collect_iocs_counts_ipv6_and_bad_ip_separately():
    events = [
        make_event(3, Initiated="true", DestinationIp="2001:db8::1"),
        make_event(3, Initiated="true", DestinationIp=""),
    ]
    iocs = collect_iocs(events)
    assert iocs["ip"] == {}
    assert iocs["stats"]["ipv6_seen"] == 1
    assert iocs["stats"]["event3_without_ipv4"] == 1


def test_collect_iocs_ignores_dns_answers_for_ips():
    events = [make_event(22, QueryName="example.com", QueryResults="type: 5 x.com;::ffff:93.184.216.34;")]
    iocs = collect_iocs(events)
    assert iocs["ip"] == {}
    assert list(iocs["dns"]) == ["example.com"]


def test_collect_iocs_dns_is_normalized_and_deduped():
    events = [
        make_event(22, QueryName="Example.com."),
        make_event(22, QueryName="example.com"),
        make_event(22, QueryName=""),
    ]
    iocs = collect_iocs(events)
    assert list(iocs["dns"]) == ["example.com"]
    assert iocs["dns"]["example.com"]["count"] == 2
    assert iocs["stats"]["event22_without_name"] == 1


def test_collect_iocs_hash_has_algorithm_and_full_image_paths():
    hashes = "MD5=%s,SHA256=%s" % (MD5.upper(), SHA256.upper())
    events = [
        make_event(1, Hashes=hashes, Image="C:\\Users\\bob\\Downloads\\a.exe"),
        make_event(1, Hashes=hashes, Image="C:\\Temp\\a.exe"),
        make_event(1, Hashes=hashes, Image="C:\\Temp\\a.exe"),
    ]
    iocs = collect_iocs(events)
    assert list(iocs["hash"]) == [SHA256]
    record = iocs["hash"][SHA256]
    assert record["algorithm"] == "sha256"
    assert record["count"] == 3
    assert record["images"] == ["C:\\Users\\bob\\Downloads\\a.exe", "C:\\Temp\\a.exe"]


def test_collect_iocs_event1_without_valid_hash_is_counted():
    events = [make_event(1, Hashes=""), make_event(1, Hashes="IMPHASH=%s" % MD5)]
    iocs = collect_iocs(events)
    assert iocs["hash"] == {}
    assert iocs["stats"]["event1_without_hash"] == 2


def test_collect_iocs_registry_and_file_events_are_not_iocs():
    events = [
        make_event(11, TargetFilename="C:\\x.txt"),
        make_event(12, TargetObject="HKLM\\X"),
        make_event(13, TargetObject="HKLM\\Run\\X", Details="C:\\x.exe"),
        make_event(14, TargetObject="HKLM\\X", NewName="HKLM\\Y"),
    ]
    iocs = collect_iocs(events)
    assert iocs["ip"] == {} and iocs["dns"] == {} and iocs["hash"] == {}


def test_collect_iocs_empty_event_list():
    iocs = collect_iocs([])
    assert iocs["ip"] == {} and iocs["dns"] == {} and iocs["hash"] == {}
