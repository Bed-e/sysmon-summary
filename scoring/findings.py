"""Step 3: turn the events into findings, the local clues about each process.

A finding is one clue about one process (design.md section 4):
    {"guid": "{...}", "points": 25, "reason": "document app started a program (...)",
     "kind": "process" or "subject", "subject": ("ip", "1.2.3.4") or None}

"process" findings are about the process itself (its path, its parent, an
autorun write, failed lookups, a burst of discovery commands). "subject"
findings are about one IOC the process touched (an odd connection, an odd
DNS name, a file that the registry points at).

The small signal functions in paths.py, processes.py, network.py and
domains.py still return (points, reason) tuples. The functions here run
them and wrap each tuple in a finding with make_finding.

Flow:
    events (parse.read_events), iocs (iocs.collect_iocs), config
    (filters.load_config) -> find_findings -> one list of findings
    -> processes.build_process_scores
"""

from iocs import ip_from_event, normalize_dns, normalize_ip
from scoring.config import (DISCOVERY_COMMANDS, ENUM_MIN_COUNT,
    ENUM_WINDOW_SECONDS, REGISTRY_EVENT_IDS, WEIGHT_ENUMERATION,
    WEIGHT_REGISTRY_REFERENCE)
from scoring.domains import dns_signals
from scoring.network import beaconing_signal, network_signals, parse_time
from scoring.paths import (lower_path, name_without_exe, parent_child_signal,
    path_signals)
from scoring.processes import failed_lookup_signal, registry_persistence_signal


def make_finding(guid, signal, subject=None):
    """Wrap one (points, reason) signal as a finding dict.

    Input: guid, the ProcessGuid the clue belongs to; signal, one
    (points, reason) tuple from a signal function; subject, an optional
    (type, value) pair naming the IOC the clue is about.
    Output: {"guid", "points", "reason", "kind", "subject"}. kind is
    "subject" when a subject is given, otherwise "process".
    Used by: every *_findings function in this file.
    """
    points, reason = signal
    return {
        "guid": guid,
        "points": points,
        "reason": reason,
        "kind": "process" if subject is None else "subject",
        "subject": subject,
    }


def process_findings(events):
    """Find the clues about each process itself.

    Input: events, the list of event dicts from parse.read_events.
    Output: a list of "process" findings. Each kind of clue is counted once
    per ProcessGuid: user-writable path and double extension (from the
    first event with an Image), odd parent pair (from event 1), autorun
    registry write (first one), and a burst of failed DNS lookups (event 22
    with a QueryStatus that is not 0).
    Used by: find_findings. The enumeration burst has its own function
    because it is about a group of children, not one event.
    """
    findings = []
    path_done = set()
    parent_done = set()
    registry_done = set()
    failures = {}

    for event in events:
        guid = event.get("ProcessGuid", "")
        if guid == "":
            continue
        image = event.get("Image", "")

        if guid not in path_done and image != "":
            path_done.add(guid)
            for signal in path_signals(image):
                findings.append(make_finding(guid, signal))

        if event["event_id"] == 1 and guid not in parent_done:
            parent_done.add(guid)
            for signal in parent_child_signal(event.get("ParentImage", ""), image):
                findings.append(make_finding(guid, signal))

        if guid not in registry_done:
            found = registry_persistence_signal(event)
            if found:
                registry_done.add(guid)
                for signal in found:
                    findings.append(make_finding(guid, signal))

        if event["event_id"] == 22 and event.get("QueryStatus", "") not in ("", "0"):
            failures[guid] = failures.get(guid, 0) + 1

    for guid, count in failures.items():
        for signal in failed_lookup_signal(count):
            findings.append(make_finding(guid, signal))
    return findings


def network_findings(events):
    """Find odd connections, judged per process and remote IP.

    Input: events from parse.read_events (only event 3 is used).
    Output: a list of "subject" findings with subject ("ip", ip). For each
    (process, IPv4) pair, network_signals checks for a program that rarely
    needs the network or an unusual port, and beaconing_signal checks for regular timing.
    Grouping by process as well as IP means each process that made the
    connection carries its own clue.
    Used by: find_findings.
    """
    groups = {}
    for event in events:
        if event["event_id"] != 3:
            continue
        guid = event.get("ProcessGuid", "")
        ip = normalize_ip(ip_from_event(event))
        if guid == "" or ip is None:
            continue
        groups.setdefault((guid, ip), []).append(event)

    findings = []
    for (guid, ip), group in groups.items():
        signals = network_signals(group)
        signals.extend(beaconing_signal([event["time"] for event in group]))
        for signal in signals:
            findings.append(make_finding(guid, signal, ("ip", ip)))
    return findings


def dns_findings(events, well_known):
    """Find odd DNS names and put each clue on every process that asked.

    Input: events from parse.read_events (only event 22 is used);
    well_known, the list of well-known names from filters.load_config.
    Output: a list of "subject" findings with subject ("dns", name). Each
    name is checked once with dns_signals (the lookalike test is the slow
    part) and the answer reused for every process that looked it up.
    Used by: find_findings.
    """
    checked = {}
    pairs = []
    seen = set()
    for event in events:
        if event["event_id"] != 22:
            continue
        guid = event.get("ProcessGuid", "")
        name = normalize_dns(event.get("QueryName", ""))
        if guid == "" or name is None or (guid, name) in seen:
            continue
        seen.add((guid, name))
        pairs.append((guid, name))
        if name not in checked:
            checked[name] = dns_signals(name, well_known)

    findings = []
    for guid, name in pairs:
        for signal in checked[name]:
            findings.append(make_finding(guid, signal, ("dns", name)))
    return findings


def hash_persistence_signal(images, registry_events, own_guids=()):
    """A registry write to an autorun location (the same test as
    registry_persistence_signal) whose TargetObject or Details contains the
    file's full path (lowercased plain substring).

    Input: images, every full path that ran with one hash (from the hash
    record in iocs.collect_iocs); registry_events, events 12, 13 and 14;
    own_guids, the ProcessGuids that ran this file.
    Output: [(points, reason)] or []. A bare filename never matches, and
    neither does a path in some other key (such as an application
    inventory entry). Writes made by the file's own processes are ignored:
    a process that sets its own autorun key already has the process-level
    autorun finding, so counting it here would be the same evidence twice.
    Used by: hash_findings.
    """
    for image in images:
        needle = lower_path(image)
        if needle == "":
            continue
        for event in registry_events:
            if not registry_persistence_signal(event):
                continue
            if event["ProcessGuid"] in own_guids:
                continue
            text = lower_path(event["TargetObject"] + " " + event.get("Details", ""))
            if needle in text:
                return [(WEIGHT_REGISTRY_REFERENCE,
                         "registry references this file's path (%s)" % image)]
    return []


def hash_findings(hash_iocs, events):
    """Find files that another process set up to run at startup.

    Input: hash_iocs, iocs["hash"] from iocs.collect_iocs ({hash: record},
    each record with "images" and "process_guids"); events from
    parse.read_events (the registry events are picked out here).
    Output: a list of "subject" findings with subject ("hash", value), one
    on every process that ran the file, when hash_persistence_signal fires.
    Used by: find_findings.
    """
    registry_events = [e for e in events if e["event_id"] in REGISTRY_EVENT_IDS]
    findings = []
    for value, record in hash_iocs.items():
        signals = hash_persistence_signal(record.get("images", []),
                                          registry_events,
                                          record["process_guids"])
        for guid in record["process_guids"]:
            for signal in signals:
                findings.append(make_finding(guid, signal, ("hash", value)))
    return findings


def busiest_window(starts):
    """Find the largest group of starts that fit inside the time window.

    Input: starts, a list of (moment, name) pairs sorted by moment, where
    moment is a datetime from parse_time and name a discovery command.
    Output: the longest run of pairs whose first and last moments are at
    most ENUM_WINDOW_SECONDS apart (the earliest such run on a tie).
    Used by: enumeration_findings.
    """
    best = []
    for first in range(len(starts)):
        window = []
        for moment, name in starts[first:]:
            if (moment - starts[first][0]).total_seconds() > ENUM_WINDOW_SECONDS:
                break
            window.append((moment, name))
        if len(window) > len(best):
            best = window
    return best


def enumeration_findings(events):
    """Find a burst of discovery commands started by one parent.

    Input: events from parse.read_events (only event 1 is used).
    Output: a list of "process" findings, at most one per parent. A parent
    gets one when ENUM_MIN_COUNT or more of its children are in
    DISCOVERY_COMMANDS (whoami, ipconfig, net, ...) and start within
    ENUM_WINDOW_SECONDS of each other. The points go to the parent (the
    shell doing the looking around), not to each command.
    Children with an unreadable time or no parent guid are left out.
    Used by: find_findings.
    """
    by_parent = {}
    for event in events:
        if event["event_id"] != 1:
            continue
        name = name_without_exe(event.get("Image", ""))
        parent = event.get("ParentProcessGuid", "")
        moment = parse_time(event.get("time", ""))
        if name not in DISCOVERY_COMMANDS or parent == "" or moment is None:
            continue
        by_parent.setdefault(parent, []).append((moment, name))

    findings = []
    for parent, starts in by_parent.items():
        starts.sort()
        window = busiest_window(starts)
        if len(window) < ENUM_MIN_COUNT:
            continue
        names = []
        for moment, name in window:
            if name not in names:
                names.append(name)
        seconds = (window[-1][0] - window[0][0]).total_seconds()
        reason = "burst of discovery commands: %d in %.0f s (%s)" % (
            len(window), seconds, ", ".join(names))
        findings.append(make_finding(parent, (WEIGHT_ENUMERATION, reason)))
    return findings


def find_findings(events, iocs, config):
    """Collect every local clue in the dump (step 3 of the pipeline).

    Input: events from parse.read_events; iocs from iocs.collect_iocs;
    config from filters.load_config (its "well_known" list is used).
    Output: one list of findings from process_findings,
    enumeration_findings, network_findings, dns_findings and hash_findings.
    Used by: web.enrich_jobs.make_state, which hands
    it to processes.build_process_scores.
    """
    findings = []
    findings.extend(process_findings(events))
    findings.extend(enumeration_findings(events))
    findings.extend(network_findings(events))
    findings.extend(dns_findings(events, config["well_known"]))
    findings.extend(hash_findings(iocs["hash"], events))
    return findings
