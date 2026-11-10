"""Smoke tests on the two sample dumps. They check things that must be true
for ANY dump, not numbers specific to these files (design.md section 3).
The .evtx files are git-ignored, so a test is skipped if its file is missing.
"""

import os

import pytest

from iocs import HASH_LENGTHS, collect_iocs, normalize_dns, normalize_ip
from main import build_summary, count_events
from parse import WANTED_FIELDS, read_events

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES = ["my-training-example.evtx", "day-in-life-events.evtx"]


def sample_path(name):
    """Full path of a sample, or skip the test if the file is missing."""
    path = os.path.join(ROOT, name)
    if not os.path.exists(path):
        pytest.skip("%s not present" % name)
    return path


@pytest.mark.parametrize("name", SAMPLES)
def test_sample_counts_add_up_and_ids_are_wanted(name):
    parsed = read_events(sample_path(name))

    dropped = sum(parsed["dropped_counts"].values())
    assert len(parsed["events"]) + dropped + parsed["error_count"] == parsed["total"]
    assert all(event["event_id"] in WANTED_FIELDS for event in parsed["events"])
    assert not any(event_id in WANTED_FIELDS for event_id in parsed["dropped_counts"])


@pytest.mark.parametrize("name", SAMPLES)
def test_sample_iocs_are_well_formed(name):
    path = sample_path(name)
    parsed = read_events(path)
    iocs = collect_iocs(parsed["events"])

    for ip, record in iocs["ip"].items():
        assert normalize_ip(ip) == ip
        assert record["count"] >= 1
    for dns_name, record in iocs["dns"].items():
        assert normalize_dns(dns_name) == dns_name
        assert record["count"] >= 1
    for value, record in iocs["hash"].items():
        assert len(value) == HASH_LENGTHS[record["algorithm"]]
        assert record["first_seen"] <= record["last_seen"]

    counts = count_events(parsed["events"])
    assert sum(counts.values()) == len(parsed["events"])
    assert "Unique IOCs" in build_summary(path, parsed, iocs)
