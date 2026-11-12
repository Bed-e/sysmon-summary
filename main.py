"""Command line: give it one or more Sysmon .evtx files, it prints a summary.

    python main.py my-training-example.evtx day-in-life-events.evtx

M1: parse and collect. M2: skip and rank locally. M3: ask the three local
portals about the top-ranked IOCs (set IP_PORTAL_URL, HASH_PORTAL_URL and
DNS_PORTAL_URL; use --no-enrich to skip). M4: --report writes one
self-contained HTML report with ranked process storylines.
"""

import argparse
import os

from dotenv import load_dotenv

from enrich import DEFAULT_CAP, enrich_ranked, load_portal_urls
from filters import load_config, split_iocs
from iocs import collect_iocs
from parse import read_events
from report import build_report, write_report
from scoring import rank_iocs
from storylines import build_storylines

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
    parser.add_argument(
        "--cap",
        type=int,
        default=DEFAULT_CAP,
        help="most portal lookups per file (default %d)" % DEFAULT_CAP,
    )
    parser.add_argument(
        "--no-enrich",
        action="store_true",
        help="skip the portal lookups (local ranking only)",
    )
    parser.add_argument(
        "--report",
        nargs="?",
        const="report.html",
        default=None,
        metavar="out.html",
        help="also write an HTML report (default name report.html; with "
             "several dumps the dump name is added to each file name)",
    )
    return parser.parse_args()


def report_path_for(out_path, dump_path, dump_count):
    """Return where one dump's report is written.

    Input: out_path, the --report value; dump_path, the .evtx being
    processed; dump_count, how many dumps were given.
    Output: out_path itself for one dump; otherwise "<out stem>-<dump
    stem><out ext>" so reports do not overwrite each other.
    Used by: main.
    """
    if dump_count == 1:
        return out_path
    out_stem, out_ext = os.path.splitext(out_path)
    dump_stem = os.path.splitext(os.path.basename(dump_path))[0]
    return "%s-%s%s" % (out_stem, dump_stem, out_ext)


def build_enrichment_summary(results):
    """Return the portal answers as one string.

    Input: results, the list from enrich.enrich_ranked (rank order).
    Output: text with the local score beside the portal's score and label,
    or the reason an IOC was not enriched. Read by the analyst on screen.
    """
    lines = ["Enrichment (portal scores are policy numbers, not a verdict):"]
    if not results:
        lines.append("  nothing to look up")
    over_cap = 0
    for result in results:
        if result["status"] == "not_enriched" and result["reasons"][0].startswith("over the cap"):
            over_cap += 1
        elif result["status"] != "not_enriched":
            note = " [partial: some sources failed]" if result["status"] == "partial" else ""
            lines.append("  %-5s %s  local %d | portal %s (%s)%s" % (
                result["type"], result["value"], result["local_score"],
                result["score_0_to_100"], result["label"], note))
            for reason in result["reasons"]:
                lines.append("          %s" % reason)
        else:
            lines.append("  %-5s %s  local %d | NOT ENRICHED: %s" % (
                result["type"], result["value"], result["local_score"],
                result["reasons"][0]))
    if over_cap:
        lines.append("  %d more IOCs not enriched: over the cap (raise --cap)" % over_cap)
    return "\n".join(lines)


def main():
    load_dotenv()
    args = get_arguments()
    config = load_config()
    urls = load_portal_urls()

    for path in args.paths:
        parsed = read_events(path)
        iocs = collect_iocs(parsed["events"])
        to_rank, skipped = split_iocs(iocs, config)
        ranked = rank_iocs(to_rank, parsed["events"], config)
        print(build_summary(path, parsed, iocs))
        print()
        print(build_ranking_summary(skipped, ranked, args.top))
        print()
        results = []
        if not args.no_enrich:
            results = enrich_ranked(ranked, urls, args.cap)
            print(build_enrichment_summary(results))
            print()
        if args.report:
            stories = build_storylines(parsed["events"], ranked, results)
            page = build_report(path, iocs, skipped, ranked, results,
                                args.cap, stories)
            out = report_path_for(args.report, path, len(args.paths))
            print("Report written: %s" % write_report(page, out))
            print()


if __name__ == "__main__":
    main()
