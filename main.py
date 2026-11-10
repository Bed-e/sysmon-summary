"""Command line: give it one or more Sysmon .evtx files, it prints a summary.

    python main.py my-training-example.evtx day-in-life-events.evtx

M1: parse and collect only. No filtering, scoring or API calls yet.
"""

import argparse

from iocs import collect_iocs
from parse import read_events

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
    return parser.parse_args()


def main():
    args = get_arguments()

    for path in args.paths:
        parsed = read_events(path)
        iocs = collect_iocs(parsed["events"])
        print(build_summary(path, parsed, iocs))
        print()


if __name__ == "__main__":
    main()
