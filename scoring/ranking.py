"""Item-level scoring and ranking: combine the signals for one IOC and sort all
IOCs, highest score first. rank_iocs is the entry point used by the rest of
the project.
"""

from iocs import ip_from_event, normalize_ip
from scoring.config import (REGISTRY_EVENT_IDS, WEIGHT_REGISTRY_REFERENCE,
    WEIGHT_TRUSTED_PATH)
from scoring.domains import dns_signals
from scoring.network import beaconing_signal, network_signals
from scoring.paths import file_name, lower_path
from scoring.processes import build_process_scores, registry_persistence_signal


def hash_persistence_signal(images, registry_events, own_guids=()):
    """A registry write to an autorun location (the same test as
    registry_persistence_signal) whose TargetObject or Details contains the
    file's full path (lowercased plain substring). A bare filename never
    matches, and neither does a path that merely appears in some other key
    (for example a Windows application inventory entry).
    Writes made by the file's own processes (`own_guids`) are ignored: a
    process that sets its own autorun key is already scored once as a
    process-level signal, so counting it here would be the same evidence
    twice.
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


def trusted_path_adjustment(images, trusted_paths):
    """Take points off when EVERY path for the hash is in a protected
    location. Weak evidence: it only lowers the order.
    """
    if not images or not trusted_paths:
        return []
    for image in images:
        lowered = image.lower()
        if not any(lowered.startswith(prefix) for prefix in trusted_paths):
            return []
    return [(WEIGHT_TRUSTED_PATH,
             "all copies run from protected system paths (weak evidence)")]


def score_ioc(item, process_scores, ip_events, registry_events, config):
    """Score one IOC. Returns (score, reasons) where reasons is a list of
    text like '+25 document app started a program (...)'.
    """
    ioc_type = item["type"]
    value = item["value"]
    record = item["record"]
    signals = []

    if ioc_type == "ip":
        events = ip_events.get(value, [])
        signals.extend(network_signals(events))
        signals.extend(beaconing_signal([event["time"] for event in events]))
    elif ioc_type == "dns":
        signals.extend(dns_signals(value, config["well_known"]))
    elif ioc_type == "hash":
        images = record.get("images", [])
        signals.extend(hash_persistence_signal(images, registry_events,
                                               record["process_guids"]))
        signals.extend(trusted_path_adjustment(images, config["trusted_paths"]))

    # Inherit from the single highest-scoring process that touched it.
    best = None
    for guid in record["process_guids"]:
        process = process_scores.get(guid)
        if process is not None and (best is None or process["score"] > best["score"]):
            best = process
    if best is not None:
        who = file_name(best["image"]) or "unknown process"
        for points, reason in best["signals"]:
            signals.append((points, "process %s: %s" % (who, reason)))

    score = sum(points for points, reason in signals)
    reasons = ["%+d %s" % (points, reason) for points, reason in signals]
    return score, reasons


def group_ip_events(events):
    """Group event 3 records by their remote IPv4: {ip: [events]}."""
    table = {}
    for event in events:
        if event["event_id"] != 3:
            continue
        ip = normalize_ip(ip_from_event(event))
        if ip is not None:
            table.setdefault(ip, []).append(event)
    return table


def rank_iocs(to_rank, events, config):
    """Score every IOC in `to_rank` and return them highest score first
    (ties: more sightings first, then earliest first seen).
    """
    process_scores = build_process_scores(events)
    ip_events = group_ip_events(events)
    registry_events = [e for e in events if e["event_id"] in REGISTRY_EVENT_IDS]

    ranked = []
    for item in to_rank:
        score, reasons = score_ioc(item, process_scores, ip_events,
                                   registry_events, config)
        ranked.append({
            "type": item["type"],
            "value": item["value"],
            "score": score,
            "reasons": reasons,
            "record": item["record"],
        })

    ranked.sort(key=lambda r: (-r["score"], -r["record"]["count"],
                               r["record"]["first_seen"]))
    return ranked
