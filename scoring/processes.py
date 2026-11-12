"""Process-level signals (registry autorun writes, bursts of failed DNS
lookups) and step 4, build_process_scores, which groups the findings by
process and adds up each process's score once.
"""

from scoring.config import (AUTORUN_MARKERS, FAILED_LOOKUP_MIN,
    IFEO_HIJACK_VALUE, IFEO_MARKER, REGISTRY_EVENT_IDS, WEIGHT_FAILED_LOOKUPS,
    WEIGHT_REGISTRY_AUTORUN)


def is_registry_write(event):
    """True for a registry event (12, 13, 14) that is not a delete."""
    if event["event_id"] not in REGISTRY_EVENT_IDS:
        return False
    return not event.get("EventType", "").lower().startswith("delete")


def registry_persistence_signal(event):
    """A registry write (not a delete) to an autorun location."""
    if not is_registry_write(event):
        return []
    key = event["TargetObject"].lower()
    is_autorun = any(marker in key for marker in AUTORUN_MARKERS)
    is_ifeo_hijack = IFEO_MARKER in key and key.endswith(IFEO_HIJACK_VALUE)
    if is_autorun or is_ifeo_hijack:
        return [(WEIGHT_REGISTRY_AUTORUN,
                 "writes an autorun registry key (%s)" % event["TargetObject"])]
    return []


def failed_lookup_signal(count):
    """A burst of failed DNS lookups from one process."""
    if count >= FAILED_LOOKUP_MIN:
        return [(WEIGHT_FAILED_LOOKUPS,
                 "%d failed DNS lookups from one process" % count)]
    return []


def build_process_scores(events, findings):
    """Give every process its score (step 4 of the pipeline), once per dump.

    Input: events from parse.read_events (for each process's image path);
    findings from scoring.findings.find_findings.
    Output: {guid: {"image": path, "score": int, "findings": [finding]}}.
    Every ProcessGuid seen in an event gets an entry, with score 0 and no
    findings when nothing pointed at it. A finding for a guid with no event
    of its own (a parent that started before the capture) still gets an
    entry, with an empty image.
    The score is the sum of the findings' points, but the same reason text
    counts only once per process (the count-once cap). So powershell
    reaching 30 addresses gets "connection from a program that rarely needs
    the network" once, not 30 times; each IP still keeps its own finding
    for the IOC table. Different ports or different lookalike targets have
    different texts and each count.
    Used by: web.enrich_jobs.make_state, which keeps the result in the
    upload's state; the chains, the IOC rank and the timeline all read it.
    """
    table = {}
    for event in events:
        guid = event.get("ProcessGuid", "")
        if guid == "":
            continue
        entry = table.setdefault(guid, {"image": "", "score": 0, "findings": []})
        if entry["image"] == "":
            entry["image"] = event.get("Image", "")

    counted = set()
    for finding in findings:
        entry = table.setdefault(finding["guid"],
                                 {"image": "", "score": 0, "findings": []})
        entry["findings"].append(finding)
        key = (finding["guid"], finding["reason"])
        if key not in counted:
            counted.add(key)
            entry["score"] += finding["points"]
    return table


def process_wide_points(process):
    """Add up only the process findings (not the subject findings).

    Input: process, one entry of build_process_scores.
    Output: an int, the points an IOC inherits from this process.
    Used by: ranking.score_ioc, to pick which process an IOC inherits from.
    """
    return sum(f["points"] for f in process["findings"] if f["kind"] == "process")
