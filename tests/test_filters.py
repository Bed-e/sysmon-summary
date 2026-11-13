"""Tests for filters.py. Inputs are hand-built, so no sample dump is needed."""

import ipaddress

from filters import (
    is_dns_internal,
    is_ip_in_shared_range,
    is_ip_not_public,
    load_config,
    load_list,
    skip_reason,
    split_iocs,
)

CONFIG = {
    "ranges": [ipaddress.ip_network("104.16.0.0/13")],
    "ad_domains": ["corp.example.com"],
    "trusted_paths": [],
    "well_known": [],
}


# ---- ip_not_public ----

def test_private_ranges_are_not_public():
    for ip in ["10.1.2.3", "172.16.0.1", "192.168.1.1"]:
        assert is_ip_not_public(ip)


def test_loopback_linklocal_multicast_reserved_not_public():
    for ip in ["127.0.0.1", "169.254.10.10", "224.0.0.251", "240.0.0.1"]:
        assert is_ip_not_public(ip)


def test_cgnat_broadcast_and_unspecified_not_public():
    for ip in ["100.64.0.1", "100.127.255.254", "255.255.255.255", "0.0.0.0"]:
        assert is_ip_not_public(ip)


def test_public_ip_is_public():
    for ip in ["8.8.8.8", "1.1.1.1", "100.128.0.1"]:
        assert not is_ip_not_public(ip)


# ---- shared ranges ----

def test_ip_inside_shared_range():
    assert is_ip_in_shared_range("104.18.5.5", CONFIG["ranges"])


def test_ip_outside_shared_range():
    assert not is_ip_in_shared_range("8.8.8.8", CONFIG["ranges"])


# ---- dns_internal ----

def test_internal_suffixes():
    for name in ["printer.local", "a.b.lan", "x.internal", "nas.home",
                 "1.0.168.192.in-addr.arpa"]:
        assert is_dns_internal(name, [])


def test_single_label_is_internal():
    assert is_dns_internal("fileserver", [])


def test_own_ad_domain_and_subdomain_are_internal():
    assert is_dns_internal("corp.example.com", ["corp.example.com"])
    assert is_dns_internal("dc1.corp.example.com", ["corp.example.com"])


def test_similar_name_is_not_ad_domain():
    assert not is_dns_internal("evilcorp.example.com", ["corp.example.com"])


def test_public_name_is_not_internal():
    assert not is_dns_internal("example.com", [])


# ---- skip_reason / split_iocs ----

def test_skip_reason_codes():
    assert skip_reason("ip", "10.0.0.1", CONFIG) == "ip_not_public"
    assert skip_reason("ip", "104.18.5.5", CONFIG) == "ip_known_shared_range"
    assert skip_reason("dns", "x.local", CONFIG) == "dns_internal"
    assert skip_reason("ip", "8.8.8.8", CONFIG) is None
    assert skip_reason("dns", "example.com", CONFIG) is None


def test_hashes_are_never_skipped():
    iocs = {"ip": {}, "dns": {}, "hash": {"a" * 64: {"images": ["C:\\Windows\\System32\\x.exe"]}}}
    to_rank, skipped = split_iocs(iocs, CONFIG)
    assert len(to_rank) == 1 and skipped == []


def test_split_iocs_separates_and_keeps_reason():
    iocs = {
        "ip": {"10.0.0.1": {"count": 1}, "8.8.8.8": {"count": 2}},
        "dns": {"x.local": {"count": 1}, "example.com": {"count": 1}},
        "hash": {},
    }
    to_rank, skipped = split_iocs(iocs, CONFIG)
    assert [i["value"] for i in to_rank] == ["8.8.8.8", "example.com"]
    assert {(i["value"], i["reason"]) for i in skipped} == {
        ("10.0.0.1", "ip_not_public"), ("x.local", "dns_internal")}


# ---- loading lists ----

def test_load_list_drops_comments_and_blanks(tmp_path):
    path = tmp_path / "list.txt"
    path.write_text("# comment\n\n  a  \nb\n", encoding="utf-8")
    assert load_list(str(path)) == ["a", "b"]


def test_load_list_missing_file_is_empty(tmp_path):
    assert load_list(str(tmp_path / "nope.txt")) == []


def test_load_config_skips_bad_cidr_and_lowercases(tmp_path):
    (tmp_path / "shared_ranges.txt").write_text("1.2.3.0/24\nnot-a-cidr\n", encoding="utf-8")
    (tmp_path / "well_known_names.txt").write_text("Google.COM\n", encoding="utf-8")
    config = load_config(str(tmp_path))
    assert len(config["ranges"]) == 1
    assert config["well_known"] == ["google.com"]
    assert config["ad_domains"] == []


def test_load_config_real_data_dir_loads():
    config = load_config("data")
    assert config["ranges"] and config["well_known"]
