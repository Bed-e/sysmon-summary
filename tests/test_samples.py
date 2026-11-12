"""Smoke tests on the two sample dumps. They check things that must be true
for ANY dump, not numbers specific to these files (design.md section 3).
The .evtx files are git-ignored, so a test is skipped if its file is missing.
"""

import os

import pytest

from filters import list_iocs, load_config
from iocs import HASH_LENGTHS, collect_iocs, normalize_dns, normalize_ip
from parse import WANTED_FIELDS, read_events
from scoring.findings import find_findings
from scoring.processes import build_process_scores
from scoring.ranking import rank_iocs
from storylines import build_chains, walk_tree

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


@pytest.mark.parametrize("name", SAMPLES)
def test_sample_pipeline_puts_every_process_in_one_tree(name):
    events = read_events(sample_path(name))["events"]
    config = load_config()
    iocs = collect_iocs(events)
    scores = build_process_scores(events, find_findings(events, iocs, config))
    result = build_chains(events, iocs, scores)
    table = result["table"]

    roots = [chain["root"] for chain in result["chains"]] + result["other"]
    seen = []
    for root in roots:
        seen.extend(walk_tree(table, root))
    assert sorted(seen) == sorted(table)  # each process in exactly one tree

    for chain in result["chains"]:
        assert chain["flagged"] and chain["title_finding"] is not None
        assert chain["score"] == max(scores[guid]["score"] for guid in chain["flagged"])
    ranked = rank_iocs(list_iocs(iocs, config), scores)
    assert len(ranked) == len(iocs["ip"]) + len(iocs["dns"]) + len(iocs["hash"])
