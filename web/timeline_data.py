"""Timeline data: process lifetimes, event dots, row order and slice choices.

Pure data shaping with no chart or UI code, so it can be tested directly.
"""

import calendar

from report import MAX_DEPTH
from scoring import file_name, parse_time
from web.config import DETAIL_LENGTH, EVENT_LANES, HIGH_SCORE, INDENT
from web.reasons import short_why


def event_lane(event):
    """Return the timeline lane for one event: "Process start", "Network",
    "DNS", "File" or "Registry" (see EVENT_LANES). Used by
    make_process_timeline."""
    return EVENT_LANES.get(event["event_id"], "Other")


def event_detail(event):
    """Return one short line saying what an event did.

    Input: one event dict from parse.read_events.
    Output: text such as "onedrivesetup.exe → 20.205.115.102:443" or
    "cmd.exe queried example.com", cut to DETAIL_LENGTH characters.
    Used by: make_process_timeline.
    """
    who = file_name(event.get("Image", "")) or "unknown process"
    event_id = event["event_id"]
    if event_id == 1:
        text = "%s started: %s" % (who, event.get("CommandLine", ""))
    elif event_id == 3:
        text = "%s → %s:%s" % (who, event.get("DestinationIp", ""),
                               event.get("DestinationPort", ""))
    elif event_id == 22:
        text = "%s queried %s" % (who, event.get("QueryName", ""))
    elif event_id == 11:
        text = "%s wrote %s" % (who, event.get("TargetFilename", ""))
    else:
        text = "%s set %s" % (who, event.get("TargetObject", ""))
    if len(text) > DETAIL_LENGTH:
        text = text[:DETAIL_LENGTH - 1] + "…"
    return text


def time_in_ms(text):
    """Turn Sysmon's time text into milliseconds since 1970 (UTC), or None.

    Uses scoring.parse_time. Sysmon times are UTC, so calendar.timegm is
    used (not the local time zone). Used by: process_spans and make_process_timeline.
    """
    moment = parse_time(text)
    if moment is None:
        return None
    return calendar.timegm(moment.timetuple()) * 1000 + moment.microsecond // 1000


def score_level(score):
    """Return "normal" (0 or less), "flagged" (1 to HIGH_SCORE-1) or "high".

    Used by: make_process_timeline to pick the colour of a bar.
    """
    if score <= 0:
        return "normal"
    if score < HIGH_SCORE:
        return "flagged"
    return "high"


def process_spans(events):
    """Find when each process was first and last seen.

    Input: events from parse.read_events.
    Output: {guid: {"first": ms, "last": ms, "first_text": "hh:mm:ss",
    "last_text": "hh:mm:ss"}} over every event carrying that ProcessGuid.
    Events with no guid or an unreadable time are skipped.
    Used by: make_process_timeline (the lifetime bars and connectors).
    """
    spans = {}
    for event in events:
        guid = event.get("ProcessGuid", "")
        moment = time_in_ms(event.get("time", ""))
        if not guid or moment is None:
            continue
        clock_text = event["time"][11:19]
        span = spans.get(guid)
        if span is None:
            spans[guid] = {"first": moment, "last": moment,
                           "first_text": clock_text, "last_text": clock_text}
            continue
        if moment < span["first"]:
            span["first"] = moment
            span["first_text"] = clock_text
        if moment > span["last"]:
            span["last"] = moment
            span["last_text"] = clock_text
    return spans


def flagged_slice(table, process_scores):
    """Pick the flagged processes and every process above them.

    Input: table from storylines.build_storylines; process_scores from
    scoring.build_process_scores.
    Output: a set of guids: each process with a local score above 0, plus
    its parent, grandparent and so on (walking parent_guid while the parent
    is in the table), so each flagged process is shown with what started it.
    Stops after MAX_DEPTH steps in case of a malformed parent loop.
    Used by: slice_guids (the default timeline view).
    """
    chosen = set()
    for guid, process in process_scores.items():
        if process["score"] <= 0 or guid not in table:
            continue
        current = guid
        steps = 0
        while current in table and current not in chosen and steps < MAX_DEPTH:
            chosen.add(current)
            current = table[current]["parent_guid"]
            steps += 1
    return chosen


def storyline_slice(stories, number):
    """Return the set of guids in storyline `number` (1-based).

    Input: stories from storylines.build_storylines; number, a rank.
    Output: the guids of that storyline's process tree.
    Used by: slice_guids.
    """
    return set(stories["storylines"][number - 1]["guids"])


def order_rows(table, guids):
    """Put the chosen processes in tree order, one row each.

    Input: table from storylines.build_storylines; guids, the chosen set.
    Output: a list of (guid, depth). A chosen process whose parent is not
    chosen is a root (depth 0). Roots, and the children under each process,
    are sorted by start time. A process is never listed twice.
    Used by: draw_process_timeline.
    """
    chosen = set()
    for guid in guids:
        if guid in table:
            chosen.add(guid)
    roots = [guid for guid in chosen if table[guid]["parent_guid"] not in chosen]
    roots.sort(key=lambda guid: table[guid]["time"])
    rows = []
    seen = set()
    stack = [(guid, 0) for guid in reversed(roots)]
    while stack:
        guid, depth = stack.pop()
        if guid in seen:
            continue
        seen.add(guid)
        rows.append((guid, depth))
        children = [child for child in table[guid]["children"] if child in chosen]
        children.sort(key=lambda child: table[child]["time"])
        for child in reversed(children):
            stack.append((child, depth + 1))
    return rows


def row_label(table, guid, depth, process_scores):
    """Return the y-axis text for one process row.

    Input: table; guid; depth from order_rows; process_scores.
    Output: e.g. "      └ onedrivesetup.exe  (60)": indented by depth, the
    file name, and the local score when it is above 0.
    Used by: make_process_timeline.
    """
    name = file_name(table[guid]["image"]) or "unknown process"
    process = process_scores.get(guid)
    score = process["score"] if process is not None else 0
    text = INDENT * depth + ("└ " if depth else "") + name
    if score > 0:
        text += "  (%d)" % score
    return text


def make_suspicious_rows(events, process_scores):
    """List every flagged process in the order it first appeared.

    Input: events from parse.read_events; process_scores from
    scoring.build_process_scores.
    Output: rows {time, process, score, why}, sorted by first event time.
    why is the short text. Processes with score 0 are left out.
    Used by: build_timeline_tab (the table under the chart).
    """
    first_seen = {}
    for event in events:
        guid = event.get("ProcessGuid", "")
        if guid and event.get("time") and (guid not in first_seen
                                           or event["time"] < first_seen[guid]):
            first_seen[guid] = event["time"]
    rows = []
    for guid, process in process_scores.items():
        if process["score"] <= 0:
            continue
        reasons = [reason for points, reason in process["signals"]]
        rows.append({"time": first_seen.get(guid, "")[:19],
                     "process": file_name(process["image"]) or "unknown process",
                     "score": process["score"], "why": short_why(reasons),
                     "guid": guid})
    rows.sort(key=lambda r: r["time"])
    return rows
