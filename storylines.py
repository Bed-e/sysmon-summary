"""Step 5: build the attack chains from the process trees.

A process tree is a root process, everything it started, and what each of
those processes did (network connections, DNS queries, files written,
registry writes) plus the IOCs it touched. A chain is a tree with at least
one flagged process (a process score above 0, from scoring/). Trees with
nothing flagged are kept in "other" (design.md section 5).

Flow:
    events (parse.read_events)                    -> build_process_table
                                                  -> attach_activity
                                                  -> link_children
    iocs (iocs.collect_iocs)                      -> attach_iocs
    events                                        -> find_dropped_by
    process_scores (scoring.build_process_scores) -> strongest_finding
    build_chains runs all of the above once per upload and returns the
    sorted result, which web/ reads.

A chain is ranked by the HIGHEST process score in its tree (not a sum).
Portal answers are never stored here: the page looks them up by
(type, value) when it draws, so enrichment never rebuilds the chains.
"""

from scoring.paths import lower_path


def new_process(guid):
    """Return an empty process entry for `guid`.

    Input: guid, a Sysmon ProcessGuid string.
    Output: a dict with every field the chain cards read, all empty.
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
        "dropped_by": None,
    }


def build_process_table(events):
    """Create one entry per process that has a process-created event.

    Input: events, the list of event dicts from parse.read_events.
    Output: {guid: process entry}. Identity fields come from event 1 only.
    Used by: build_chains, first step.
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
    Used by: build_chains, second step.
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
    Used by: build_chains, third step.
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
    Used by: build_chains.
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




def attach_iocs(table, iocs):
    """Note on each process which IOCs it touched.

    Input: table from build_process_table; iocs from iocs.collect_iocs
    ({"ip": {value: record}, "dns": ..., "hash": ...}, each record with
    "process_guids").
    Output: the table, changed in place. Each process's "iocs" list gets
    (type, value) for every IOC whose record names that process. No scores
    and no portal answers are stored. Processes not in the table are
    ignored.
    Used by: build_chains. "Enrich this chain" and the chain cards read
    these lists.
    """
    for ioc_type in ("ip", "dns", "hash"):
        for value, record in iocs[ioc_type].items():
            for guid in record["process_guids"]:
                entry = table.get(guid)
                if entry is not None and (ioc_type, value) not in entry["iocs"]:
                    entry["iocs"].append((ioc_type, value))
    return table


def find_dropped_by(table, events):
    """Find which process wrote each process's program file.

    Input: table from build_process_table; events from parse.read_events
    (only event 11, file created, is used).
    Output: the table, changed in place. When a process's image path
    (lowercased) matches a file another process created, the earliest such
    write is stored as entry["dropped_by"] = {"guid", "image", "time"}.
    Otherwise "dropped_by" stays None. Trees are never merged.
    Used by: build_chains. A chain card shows it as "file written by
    chrome.exe at 10:02", which links a download to the program that ran.
    """
    writes = {}
    for event in events:
        if event["event_id"] != 11:
            continue
        path = lower_path(event.get("TargetFilename", ""))
        if path == "":
            continue
        writes.setdefault(path, []).append(event)

    for guid, entry in table.items():
        best = None
        for event in writes.get(lower_path(entry["image"]), []):
            if event.get("ProcessGuid", "") in ("", guid):
                continue
            if best is None or event.get("time", "") < best.get("time", ""):
                best = event
        if best is not None:
            writer = table.get(best["ProcessGuid"])
            image = writer["image"] if writer else best.get("Image", "")
            entry["dropped_by"] = {"guid": best["ProcessGuid"], "image": image,
                                   "time": best.get("time", "")}
    return table


def strongest_finding(guids, process_scores):
    """Pick the one finding that best explains why a tree is suspicious.

    Input: guids, one tree in walk_tree order; process_scores from
    scoring.build_process_scores.
    Output: the finding dict with the most points among those processes
    (the earliest in tree order on a tie), or None when none has a finding
    with points above 0.
    Used by: build_chains, for the chain's title ("what made it
    suspicious", not the root process).
    """
    best = None
    for guid in guids:
        process = process_scores.get(guid)
        if process is None:
            continue
        for finding in process["findings"]:
            if finding["points"] > 0 and (best is None or finding["points"] > best["points"]):
                best = finding
    return best


def build_chains(events, iocs, process_scores):
    """Build the attack chains for one dump (step 5 of the pipeline).

    Input: events from parse.read_events; iocs from iocs.collect_iocs;
    process_scores from scoring.build_process_scores.
    Output: {"table": {guid: process entry},
             "chains": [{"root": guid, "score": int, "title_finding": finding,
                         "guids": [guid, ...] in tree order,
                         "flagged": [guids with a score above 0]}],
             "other": [root guids of trees with nothing flagged],
             "events_without_guid": int}
    Chains are sorted highest score first, then larger tree, then earliest
    start. "other" keeps start order.
    Used by: web.enrich_jobs.make_state, once per upload; the tabs and the
    timeline read it from the state.
    """
    table = build_process_table(events)
    without_guid = attach_activity(table, events)
    roots = link_children(table)
    attach_iocs(table, iocs)
    find_dropped_by(table, events)

    chains = []
    other = []
    for root in roots:
        guids = walk_tree(table, root)
        flagged = []
        score = 0
        for guid in guids:
            process = process_scores.get(guid)
            if process is not None and process["score"] > 0:
                flagged.append(guid)
                score = max(score, process["score"])
        if not flagged:
            other.append(root)
            continue
        chains.append({
            "root": root,
            "score": score,
            "title_finding": strongest_finding(guids, process_scores),
            "guids": guids,
            "flagged": flagged,
        })

    chains.sort(key=lambda c: (-c["score"], -len(c["guids"]),
                               table[c["root"]]["time"]))
    return {
        "table": table,
        "chains": chains,
        "other": other,
        "events_without_guid": without_guid,
    }
