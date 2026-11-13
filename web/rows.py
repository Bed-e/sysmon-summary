"""Row builders: turn ranked IOCs, results and upload counts into the plain
dicts the IOCs table and the Stats tiles show, plus small text helpers.
"""

from scoring.paths import file_name
from web.config import EVENT_ID_NAMES, NOT_ENRICHABLE_TEXT, SEEN_IN_NAMES
from web.reasons import portal_text, why_lines


def make_ioc_rows(ranked, results, table):
    """Build the rows of the ranked IOC table.

    Input: ranked (scoring.rank_iocs, in rank order); results, the portal
    answers so far (state["results"], copied by the caller); table, the
    process table from storylines.build_chains (state["chains"]["table"]).
    Output: a list of dicts {rank, type, value, score, why, full_why,
    seen_in, seen_in_full, portal, action, not_enrichable}, one per ranked
    IOC, in rank order. why is a list of short lines, one per process
    (why_lines); full_why holds every original reason (shown on hover).
    seen_in and seen_in_full come from touched_by. action is "Look up" when
    not requested, "Retry" when the lookup failed, else "" (ioc_action).
    An IOC tagged not_enrichable shows the plain reason (for example "not
    sent: internal name") as its portal text, no button, and
    not_enrichable True (drawn muted).
    Used by: build_ioc_rows (the grid draws the first rows).
    """
    answers = answers_by_ioc(results)
    rows = []
    for rank, item in enumerate(ranked, 1):
        portal = answers.get((item["type"], item["value"]), "not requested")
        action = ioc_action(item, portal)
        if item["not_enrichable"]:
            portal = NOT_ENRICHABLE_TEXT.get(item["not_enrichable"], "not sent")
        seen_in, seen_in_full = touched_by(item, table)
        rows.append({"rank": rank, "type": item["type"], "value": item["value"],
                     "score": item["score"], "why": why_lines(item["reasons"]),
                     "full_why": "\n".join(item["reasons"]),
                     "seen_in": seen_in, "seen_in_full": seen_in_full,
                     "portal": portal_text(portal), "action": action,
                     "not_enrichable": bool(item["not_enrichable"])})
    return rows


def touched_by(item, table):
    """Name the processes that touched one IOC.

    Input: item, a ranked IOC (its record["process_guids"] comes from
    iocs.collect_iocs, in first-seen order); table, the process table from
    storylines.build_chains, which holds every process, flagged or not.
    Output: (short_text, full_text). short_text lists up to SEEN_IN_NAMES
    distinct image names in first-seen order, then "+N more" for the rest,
    for example "chrome.exe, svchost.exe +4 more". full_text has every
    name with its process count ("chrome.exe ×12"), one per line, for the
    hover. A guid missing from the table, or with no image, is "unknown
    process".
    Used by: make_ioc_rows (the Seen in column).
    """
    counts = {}
    order = []
    for guid in item["record"]["process_guids"]:
        entry = table.get(guid)
        name = (file_name(entry["image"]) if entry else "") or "unknown process"
        if name not in counts:
            counts[name] = 0
            order.append(name)
        counts[name] += 1
    short_text = ", ".join(order[:SEEN_IN_NAMES])
    if len(order) > SEEN_IN_NAMES:
        short_text += " +%d more" % (len(order) - SEEN_IN_NAMES)
    full_text = "\n".join("%s ×%d" % (name, counts[name]) for name in order)
    return short_text, full_text


def ioc_action(item, portal):
    """Choose the button an IOC gets, the same on every tab.

    Input: item, a ranked IOC dict (scoring.rank_iocs, with its
    not_enrichable tag from filters); portal, its answer so far: a
    common-shape dict from state["results"], or the text "not requested".
    Output: "" when the IOC is never sent (not_enrichable) or already has a
    good answer, "Retry" after a "not_enriched" answer, "Look up" when it
    has not been asked about yet.
    Used by: make_ioc_rows (IOCs tab) and storyline_summary.ioc_details
    (chain cards), so both show the same button for the same IOC.
    """
    if item["not_enrichable"]:
        return ""
    if not isinstance(portal, dict):
        return "Look up"
    if portal["status"] == "not_enriched":
        return "Retry"
    return ""


def answers_by_ioc(results):
    """Index the portal answers by IOC.

    Input: results, the portal answers so far (state["results"], copied by
    the caller).
    Output: {(type, value): common-shape dict}.
    Used by: make_ioc_rows and web.storyline_summary.ioc_details.
    """
    answers = {}
    for result in results:
        answers[(result["type"], result["value"])] = result
    return answers


def stat(label, value):
    """Return one Stats tile {item, value}. Used by the *_stats functions."""
    return {"item": label, "value": str(value)}


def event_id_label(event_id):
    """Return "ID 1 (process start)", or "ID 7" for an ID with no short name.
    Used by event_stats."""
    name = EVENT_ID_NAMES.get(event_id)
    return "ID %s (%s)" % (event_id, name) if name else "ID %s" % event_id


def event_stats(state):
    """Count what happened to the events of one dump.

    Input: state, an UPLOADS entry: "parse" (dropped_counts, error_count,
    total, kept from parse.read_events by make_state), "events" (the kept
    events) and "chains" (events_without_guid from build_chains).
    Output: a list of {item, value} tiles: events in the file, events kept,
    one tile per kept event ID, one per dropped event ID, parse errors, and
    events with no ProcessGuid. IDs are in number order.
    Used by: build_stats_tab (the Events card).
    """
    parse = state["parse"]
    kept = {}
    for event in state["events"]:
        kept[event["event_id"]] = kept.get(event["event_id"], 0) + 1
    tiles = [stat("Events in the file", parse["total"]),
             stat("Events kept", len(state["events"]))]
    for event_id in sorted(kept):
        tiles.append(stat("Kept: " + event_id_label(event_id), kept[event_id]))
    for event_id in sorted(parse["dropped_counts"]):
        tiles.append(stat("Dropped: " + event_id_label(event_id),
                          parse["dropped_counts"][event_id]))
    tiles.append(stat("Parse errors", parse["error_count"]))
    tiles.append(stat("Events with no ProcessGuid (not in any chain)",
                      state["chains"]["events_without_guid"]))
    return tiles


def ioc_stats(state):
    """Count the IOCs of one dump and why some are never sent.

    Input: state, an UPLOADS entry: "iocs" (iocs.collect_iocs) and "ranked"
    (with the not_enrichable tag from filters).
    Output: a list of {item, value} tiles: IOCs found (by type in the
    caption), enrichable, then one tile per not-enrichable reason, in the
    plain words of NOT_ENRICHABLE_TEXT ("not sent: internal name").
    Used by: build_stats_tab (the IOCs card).
    """
    iocs = state["iocs"]
    found = len(iocs["ip"]) + len(iocs["dns"]) + len(iocs["hash"])
    reasons = {}
    for item in state["ranked"]:
        if item["not_enrichable"]:
            reasons[item["not_enrichable"]] = reasons.get(item["not_enrichable"], 0) + 1
    tiles = [stat("IOCs found (%d IPs, %d DNS names, %d hashes)"
                  % (len(iocs["ip"]), len(iocs["dns"]), len(iocs["hash"])), found),
             stat("Enrichable", len(state["ranked"]) - sum(reasons.values()))]
    for code in sorted(reasons):
        tiles.append(stat(NOT_ENRICHABLE_TEXT.get(code, code).capitalize(), reasons[code]))
    return tiles


def lookup_stats(state, results):
    """Count the portal lookups so far.

    Input: state, an UPLOADS entry ("ranked", for the enrichable count);
    results, the portal answers so far (state["results"], copied by the
    caller; one per IOC, store_result never duplicates).
    Output: a list of {item, value} tiles: looked up (enriched or partial),
    lookup failed (not enriched), and enrichable IOCs not requested yet.
    Used by: build_stats_tab (the Lookups card) and refresh_view, through
    view["draw_stats"].
    """
    failed = len([result for result in results if result["status"] == "not_enriched"])
    enrichable = len([item for item in state["ranked"] if not item["not_enrichable"]])
    return [stat("Looked up on the portals", len(results) - failed),
            stat("Lookup failed (not enriched)", failed),
            stat("Not requested", max(enrichable - len(results), 0))]


def count_text(number, word, plural):
    """Return "1 process" or "3 processes". Used by summary_caption."""
    return "%d %s" % (number, word if number == 1 else plural)
