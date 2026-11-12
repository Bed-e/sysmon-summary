"""Command line: give it one or more Sysmon .evtx files, it prints a summary.

    python main.py my-training-example.evtx day-in-life-events.evtx

M1: parse and collect. M2: skip and rank locally. No API calls yet.
"""

import argparse

from filters import load_config, split_iocs
from iocs import collect_iocs
from parse import read_events
from scoring import rank_iocs

# Short names so the summary is easy to read.
EVENT_NAMES = {
    1: "process created",
    3: "network connection",
    11: "file created",
    12: "registry object created/deleted",
    13: "registry value set",
    14: "registry key/value renamed",
    22: "DNS query",
}


def count_events(events):
    """Count events by event ID. Returns {event_id: count}."""
    counts = {}
    for event in events:
        event_id = event["event_id"]
        counts[event_id] = counts.get(event_id, 0) + 1
    return counts


def build_summary(path, parsed, iocs):
    """Return the summary for one file as one string."""
    events = parsed["events"]
    dropped = parsed["dropped_counts"]
    stats = iocs["stats"]
    lines = []

    lines.append("File: %s" % path)
    lines.append("Records read: %d" % parsed["total"])
    lines.append("  kept: %d" % len(events))
    lines.append("  dropped (other event IDs): %d" % sum(dropped.values()))
    if dropped:
        parts = ["%d x%d" % (event_id, dropped[event_id]) for event_id in sorted(dropped)]
        lines.append("    by ID: " + ", ".join(parts))
    lines.append("  parse errors: %d" % parsed["error_count"])

    lines.append("")
    lines.append("Kept events by ID:")
    counts = count_events(events)
    for event_id in sorted(counts):
        name = EVENT_NAMES.get(event_id, "")
        lines.append("  %-3d %-34s %d" % (event_id, name, counts[event_id]))

    lines.append("")
    lines.append("Unique IOCs:")
    lines.append("  IPs (IPv4, from event 3): %d" % len(iocs["ip"]))
    lines.append("  DNS names (event 22):     %d" % len(iocs["dns"]))
    lines.append("  Hashes (event 1):         %d" % len(iocs["hash"]))

    lines.append("")
    lines.append("Seen but not collected:")
    lines.append("  IPv6 addresses (event 3):              %d" % stats["ipv6_seen"])
    lines.append("  Network events with no usable IPv4:    %d" % stats["event3_without_ipv4"])
    lines.append("  DNS events with an empty name:         %d" % stats["event22_without_name"])
    lines.append("  Process events with no valid hash:     %d" % stats["event1_without_hash"])
    return "\n".join(lines)


def build_ranking_summary(skipped, ranked, top):
    """Return the skip counts and the top `top` ranked IOCs as one string."""
    lines = []
    lines.append("Skipped (not sent to any API):")
    reasons = {}
    for item in skipped:
        reasons[item["reason"]] = reasons.get(item["reason"], 0) + 1
    if not reasons:
        lines.append("  none")
    for reason in sorted(reasons):
        lines.append("  %-24s %d" % (reason, reasons[reason]))

    lines.append("")
    lines.append("Ranked IOCs: %d (top %d shown). Scores order the lookups; "
                 "they are not a verdict." % (len(ranked), min(top, len(ranked))))
    for item in ranked[:top]:
        lines.append("  %4d  %-5s %s" % (item["score"], item["type"], item["value"]))
        for reason in item["reasons"]:
            lines.append("          %s" % reason)
    return "\n".join(lines)


def get_arguments():
    """Read the command line. Returns an object with .paths (a list)."""
    parser = argparse.ArgumentParser(
        description="Summarize the events and IOCs in Sysmon .evtx files."
    )
    parser.add_argument(
        "paths",
        nargs="+",
        metavar="file.evtx",
        help="one or more Sysmon .evtx dump files",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=10,
        help="how many ranked IOCs to show (default 10)",
    )
    return parser.parse_args()


def main():
    args = get_arguments()
    config = load_config()

    for path in args.paths:
        parsed = read_events(path)
        iocs = collect_iocs(parsed["events"])
        to_rank, skipped = split_iocs(iocs, config)
        ranked = rank_iocs(to_rank, parsed["events"], config)
        print(build_summary(path, parsed, iocs))
        print()
        print(build_ranking_summary(skipped, ranked, args.top))
        print()


if __name__ == "__main__":
    main()
