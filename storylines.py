"""Step 4 (M4): group events and IOCs by process into storylines.

A storyline is one process tree: a root process, everything it started, and
what each of those processes did (network connections, DNS queries, files
written, registry writes) plus the IOCs they touched.

Flow:
    events  (parse.read_events)           -> build_process_table
                                          -> attach_activity
                                          -> link_children
    ranked  (scoring.rank_iocs)           -> attach_ioc_results
    results (enrich.enrich_ranked)        -> attach_ioc_results
    scoring.build_process_scores          -> score_storyline
    build_storylines runs all of the above and returns the sorted result,
    which report.py (M4) and later web/app.py (M5) turn into a page.

Scores are policy numbers, not a verdict. A storyline is ranked by the
HIGHEST local score in its tree (not a sum). Portal scores are shown beside
the local score and are never merged into it (design.md section 6).
"""

from scoring.processes import build_process_scores

NOT_REQUESTED = "not requested"


def new_process(guid):
    """Return an empty process entry for `guid`.

    Input: guid, a Sysmon ProcessGuid string.
    Output: a dict with every field the report reads, all empty.
    Used by: build_process_table (event 1) and attach_activity (a process
    first seen in another event, which started before the capture began).
    """
    return {
        "guid": guid,
        "parent_guid": "",
        "image": "",
        "command_line": "",
        "parent_image": "",
        "parent_command_line": "",
        "user": "",
        "time": "",
        "children": [],
        "ips": [],
        "dns": [],
        "files": [],
        "registry": [],
        "iocs": [],
    }


def build_process_table(events):
    """Create one entry per process that has a process-created event.

    Input: events, the list of event dicts from parse.read_events.
    Output: {guid: process entry}. Identity fields come from event 1 only.
    Used by: build_storylines, first step.
    """
    table = {}
    for event in events:
        if event["event_id"] != 1:
            continue
        guid = event.get("ProcessGuid", "")
        if guid == "" or guid in table:
            continue
        entry = new_process(guid)
        entry["parent_guid"] = event.get("ParentProcessGuid", "")
        entry["image"] = event.get("Image", "")
        entry["command_line"] = event.get("CommandLine", "")
        entry["parent_image"] = event.get("ParentImage", "")
        entry["parent_command_line"] = event.get("ParentCommandLine", "")
        entry["user"] = event.get("User", "")
        entry["time"] = event.get("time", "")
        table[guid] = entry
    return table


def attach_activity(table, events):
    """Attach what each process did to its entry.

    Input: table from build_process_table; events from parse.read_events.
    Output: the number of events skipped because they had no ProcessGuid.
    The table is changed in place. Event 3 adds "ip:port", event 22 a query
    name, event 11 a file path, events 12/13/14 "event id + registry key".
    A process with no event 1 gets a stub entry (name from the event's
    Image), so its activity is not lost.
    Used by: build_storylines, second step.
    """
    skipped = 0
    for event in events:
        event_id = event["event_id"]
        if event_id == 1:
            continue
        guid = event.get("ProcessGuid", "")
        if guid == "":
            skipped += 1
            continue
        entry = table.get(guid)
        if entry is None:
            entry = new_process(guid)
            entry["image"] = event.get("Image", "")
            entry["time"] = event.get("time", "")
            table[guid] = entry

        if event_id == 3:
            text = "%s:%s" % (event.get("DestinationIp", ""),
                              event.get("DestinationPort", ""))
            if text not in entry["ips"]:
                entry["ips"].append(text)
        elif event_id == 22:
            name = event.get("QueryName", "")
            if name != "" and name not in entry["dns"]:
                entry["dns"].append(name)
        elif event_id == 11:
            path = event.get("TargetFilename", "")
            if path != "" and path not in entry["files"]:
                entry["files"].append(path)
        elif event_id in (12, 13, 14):
            text = "%d %s" % (event_id, event.get("TargetObject", ""))
            if text not in entry["registry"]:
                entry["registry"].append(text)
    return skipped


def link_children(table):
    """Build the process tree and find its roots.

    Input: table after build_process_table and attach_activity.
    Output: a list of root GUIDs, earliest start first. A root is a process
    whose parent GUID is empty or not in the table (the parent started
    before the capture, so only its image name is known). Each parent's
    "children" list is filled, earliest start first.
    Used by: build_storylines, third step.
    """
    roots = []
    for guid, entry in table.items():
        parent = table.get(entry["parent_guid"])
        if parent is None or entry["parent_guid"] == guid:
            roots.append(guid)
        else:
            parent["children"].append(guid)

    def start_key(guid):
        return (table[guid]["time"], guid)

    for entry in table.values():
        entry["children"].sort(key=start_key)
    roots.sort(key=start_key)
    return roots


def walk_tree(table, root_guid):
    """List every GUID in one storyline, parent before children.

    Input: table with children linked; root_guid, one root from link_children.
    Output: a list of GUIDs in depth-first order. A visited set makes a
    parent loop in bad data stop instead of running forever.
    Used by: score_storyline and report.py.
    """
    order = []
    seen = set()
    stack = [root_guid]
    while stack:
        guid = stack.pop()
        if guid in seen:
            continue
        seen.add(guid)
        order.append(guid)
        stack.extend(reversed(table[guid]["children"]))
    return order


def attach_ioc_results(table, ranked, results):
    """Put each IOC on every process that touched it.

    Input: table; ranked from scoring.rank_iocs (each item has type, value,
    score, reasons and record["process_guids"]); results from
    enrich.enrich_ranked, or [] when enrichment was not run.
    Output: the table, changed in place. Each process's "iocs" gets
    {type, value, local_score, local_reasons, portal}, where portal is the
    common-shape dict or the text "not requested". Processes with no entry
    in the table are ignored.
    Used by: build_storylines, fourth step.
    """
    answers = {}
    for result in results:
        answers[(result["type"], result["value"])] = result

    for item in ranked:
        portal = answers.get((item["type"], item["value"]), NOT_REQUESTED)
        for guid in item["record"]["process_guids"]:
            entry = table.get(guid)
            if entry is None:
                continue
            entry["iocs"].append({
                "type": item["type"],
                "value": item["value"],
                "local_score": item["score"],
                "local_reasons": item["reasons"],
                "portal": portal,
            })
    return table


def score_storyline(table, root_guid, process_scores):
    """Score one storyline by its single highest local score.

    Input: table (children linked, IOCs attached); root_guid; and
    process_scores from scoring.build_process_scores(events).
    Output: (score, reasons). The score is the highest local score of any
    process or IOC in the tree. The reasons are that item's own reasons plus
    one line counting the other scored items. Never a sum, never portal
    scores. Used by: build_storylines.
    """
    best_score = None
    best_reasons = []
    scored_items = 0

    for guid in walk_tree(table, root_guid):
        entry = table[guid]
        process = process_scores.get(guid)
        if process is not None:
            scored_items += 1
            if best_score is None or process["score"] > best_score:
                who = entry["image"] or "unknown process"
                best_score = process["score"]
                best_reasons = ["process %s: %+d %s" % (who, points, reason)
                                for points, reason in process["signals"]]
        for ioc in entry["iocs"]:
            scored_items += 1
            if best_score is None or ioc["local_score"] > best_score:
                best_score = ioc["local_score"]
                best_reasons = ["%s %s: %s" % (ioc["type"], ioc["value"], reason)
                                for reason in ioc["local_reasons"]]

    if best_score is None:
        return 0, []
    if scored_items > 1:
        best_reasons = best_reasons + ["highest of %d scored items in this tree"
                                       % scored_items]
    return best_score, best_reasons


def build_storylines(events, ranked, results):
    """Build the ranked storylines for one dump.

    Input: events (parse.read_events), ranked (scoring.rank_iocs), results
    (enrich.enrich_ranked, or [] with --no-enrich).
    Output: {"table": {guid: entry},
             "storylines": [{"root": guid, "score": int, "reasons": [...],
                             "size": processes in the tree,
                             "guids": [guid, ...] in tree order}],
             "events_without_guid": int}
    The storylines are sorted highest score first, then larger tree, then
    earliest start. Used by: main.py now, web/app.py in M5; report.py
    renders it.
    """
    table = build_process_table(events)
    skipped = attach_activity(table, events)
    roots = link_children(table)
    attach_ioc_results(table, ranked, results)
    process_scores = build_process_scores(events)

    storylines = []
    for root in roots:
        guids = walk_tree(table, root)
        score, reasons = score_storyline(table, root, process_scores)
        storylines.append({
            "root": root,
            "score": score,
            "reasons": reasons,
            "size": len(guids),
            "guids": guids,
        })

    storylines.sort(key=lambda s: (-s["score"], -s["size"],
                                   table[s["root"]]["time"]))
    return {
        "table": table,
        "storylines": storylines,
        "events_without_guid": skipped,
    }
