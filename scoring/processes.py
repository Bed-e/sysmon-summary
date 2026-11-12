"""Process-level scores: registry autorun writes, bursts of failed DNS lookups and
build_process_scores, which scores every ProcessGuid once.
"""

from scoring.config import (AUTORUN_MARKERS, FAILED_LOOKUP_MIN,
    IFEO_HIJACK_VALUE, IFEO_MARKER, REGISTRY_EVENT_IDS, WEIGHT_FAILED_LOOKUPS,
    WEIGHT_REGISTRY_AUTORUN)
from scoring.paths import parent_child_signal, path_signals


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


def build_process_scores(events):
    """Score every ProcessGuid once. Returns
        {guid: {"image": path, "signals": [(points, reason)], "score": int}}
    Path comes from any event with that guid, the parent pair from event 1,
    autorun from registry events, failed lookups from event 22. Each kind is
    counted once per process.
    """
    table = {}
    path_done = set()
    parent_done = set()
    registry_done = set()
    failures = {}

    for event in events:
        guid = event.get("ProcessGuid", "")
        if guid == "":
            continue
        entry = table.setdefault(guid, {"image": event.get("Image", ""),
                                        "signals": [], "score": 0})
        if entry["image"] == "":
            entry["image"] = event.get("Image", "")

        if guid not in path_done and event.get("Image", "") != "":
            path_done.add(guid)
            entry["signals"].extend(path_signals(event["Image"]))

        if event["event_id"] == 1 and guid not in parent_done:
            parent_done.add(guid)
            entry["signals"].extend(
                parent_child_signal(event["ParentImage"], event["Image"]))

        if guid not in registry_done:
            found = registry_persistence_signal(event)
            if found:
                registry_done.add(guid)
                entry["signals"].extend(found)

        if event["event_id"] == 22 and event["QueryStatus"] not in ("", "0"):
            failures[guid] = failures.get(guid, 0) + 1

    for guid, count in failures.items():
        table[guid]["signals"].extend(failed_lookup_signal(count))

    for entry in table.values():
        entry["score"] = sum(points for points, reason in entry["signals"])
    return table
