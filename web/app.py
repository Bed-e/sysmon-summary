"""M5: the web app (NiceGUI), with tabs.

Run from the project folder:

    python -m web.app

Open http://127.0.0.1:5000. Upload a Sysmon .evtx dump: it is parsed,
filtered and ranked locally and the report is shown in five tabs:
Overview, IOCs, Storylines, Timeline and Skipped. NO portal is called until
the analyst presses "Enrich next N" or a row's Look up button. Then ONE
background thread looks up those IOCs, one at a time, highest rank first
(the same sequential loop as M3). "Next N" means the N highest-ranked IOCs
not tried yet, so pressing it twice with N=5 covers ranks 1-5, then 6-10.
A timer on the page updates the table and status in place as answers
arrive (no page reload).

Rules kept here (design.md section 7):
- The browser never sends an IOC value back. It sends only N or a row's
  rank number, so the server only ever looks up IOCs it ranked itself.
- Only hash lookups reach VirusTotal, so only they are counted and paced.
  The limits come from data/api_limits.txt; today's count is kept in
  data/hash_usage.txt so a restart does not reset it.
- Text from a dump is shown only through NiceGUI labels and tables, which
  escape it. The one piece of raw HTML (the upload form) is a fixed string.
- The server listens on 127.0.0.1 only.

NiceGUI hands an uploaded file to its own handlers only through async
methods, which this project avoids. So the upload is a plain synchronous
POST endpoint on NiceGUI's FastAPI app, and the page uses a basic HTML form.
"""

import calendar
import datetime
import os
import secrets
import threading
import time

from dotenv import load_dotenv
from fastapi import UploadFile
from fastapi.responses import RedirectResponse
from nicegui import app, ui

from enrich import enrich_one, load_portal_urls, not_enriched
from filters import load_config, split_iocs
from iocs import collect_iocs
from parse import read_events
from report import MAX_DEPTH
from scoring import build_process_scores, file_name, parse_time, rank_iocs
from storylines import build_storylines

LIMITS_PATH = os.path.join("data", "api_limits.txt")
USAGE_PATH = os.path.join("data", "hash_usage.txt")
UPLOAD_DIR = "uploads"

DEFAULT_LIMITS = {"hash_per_minute": 4, "hash_per_day": 500}
N_CHOICES = ["5", "10", "25", "50", "100", "all"]
REFRESH_SECONDS = 2
SHOW_STEP = 10  # rows (or storylines) shown at first, and added per "Show more"
MAX_UPLOAD_BYTES = 200 * 1024 * 1024
EVTX_MAGIC = b"ElfFile\x00"
BUDGET_REASON = "daily VirusTotal budget reached"

# Fixed messages for the upload page. The endpoint redirects with a code, so
# nothing the user typed is ever echoed back.
UPLOAD_ERRORS = {
    "none": "Choose a .evtx file first.",
    "type": "Only .evtx files are accepted.",
    "magic": "That file is not a Windows .evtx log.",
    "size": "That file is too large.",
    "read": "Could not read that file.",
}

UPLOAD_FORM = (
    '<form method="post" action="/upload" enctype="multipart/form-data">'
    '<input type="file" name="file" accept=".evtx"> '
    '<button type="submit">Upload and rank</button></form>'
)

# Shared state (design.md section 7): upload id -> state dict. Only the
# enrich thread writes "results", "run" and "error"; pages only read them.
UPLOADS = {}
# Time of the last hash lookup, so pacing also holds across two runs.
LAST_HASH = {"time": 0.0}
START_LOCK = threading.Lock()

# The IOC table is a plain grid (so each row can hold a Look up button).
IOC_HEADERS = ["Rank", "Type", "Value", "Local score", "Why", "Portal"]
IOC_GRID_COLUMNS = ("3em 3.5em minmax(9em, 16em) 4.5em minmax(14em, 1fr) "
                    "minmax(12em, 20em)")

SKIPPED_COLUMNS = [
    {"name": "reason", "label": "Reason", "field": "reason", "align": "left"},
    {"name": "type", "label": "Type", "field": "type", "align": "left"},
    {"name": "value", "label": "Value", "field": "value", "align": "left",
     "style": "white-space: normal; word-break: break-all"},
    {"name": "count", "label": "Sightings", "field": "count", "align": "left"},
]
COUNT_COLUMNS = [
    {"name": "item", "label": "Item", "field": "item", "align": "left"},
    {"name": "value", "label": "Value", "field": "value", "align": "left"},
]

SUSPICIOUS_COLUMNS = [
    {"name": "time", "label": "First seen (UTC)", "field": "time", "align": "left"},
    {"name": "process", "label": "Process", "field": "process", "align": "left"},
    {"name": "score", "label": "Local score", "field": "score", "align": "left"},
    {"name": "why", "label": "Why", "field": "why", "align": "left",
     "style": "white-space: normal"},
]

# Short phrases for the reasons scoring.py writes (see short_reason).
# (text the reason starts with, short phrase, keep the bracketed detail?)
SHORT_REASONS = [
    ("file runs from a user-writable path", "runs from a user folder", False),
    ("double extension", "has a double extension", True),
    ("document app started a program", "was started by a document app", True),
    ("explorer started a program from Temp", "was started by explorer from Temp", False),
    ("service started a program from a user-writable path",
     "was started by a service from a user folder", False),
    ("writes an autorun registry key", "sets an autorun registry key", False),
    ("connection from an unexpected process", "contacted by an unexpected program", False),
    ("unusual destination port", "unusual port", True),
    ("very long label", "very long DNS label", False),
    ("high-entropy label", "random-looking DNS label", False),
    ("registry references this file's path", "an autorun key points to this file", False),
    ("all copies run from protected system paths",
     "only seen in system folders (lowers the score)", False),
]

# Portal labels that count as a "portal hit" in a storyline summary.
PORTAL_HIT_LABELS = ["malicious", "suspicious", "likely_malware", "definitely_malware"]

# Timeline: one lane per kind of event, and three colour groups.
EVENT_LANES = {1: "Process start", 3: "Network", 22: "DNS", 11: "File",
               12: "Registry", 13: "Registry", 14: "Registry"}
LANE_ORDER = ["Registry", "File", "DNS", "Network", "Process start"]
HIGH_SCORE = 40  # a process score at or above this is shown red
DETAIL_LENGTH = 110  # longest hover text for one event
TIMELINE_SERIES = [  # (group, legend label, colour, dot size)
    ("normal", "Normal process (score 0)", "#b0b0b0", 5),
    ("flagged", "Flagged process (score 1-%d)" % (HIGH_SCORE - 1), "#f0a020", 8),
    ("high", "High-scoring process (score %d+)" % HIGH_SCORE, "#d62020", 11),
]


NOT_A_VERDICT = ("Scores are policy numbers, not a verdict. Local scores order "
                 "the work; portal scores are shown beside them and are never "
                 "merged or averaged.")


# ---------------------------------------------------------------- limits

def load_limits(path=LIMITS_PATH):
    """Read the hash lookup limits file.

    Input: path of data/api_limits.txt (lines "name=value"; "#" starts a
    comment). Written by the analyst by hand.
    Output: {"hash_per_minute": int, "hash_per_day": int}. A missing file,
    a missing line or a value that is not a whole number above 0 falls back
    to the default (4 and 500).
    Used by: the enrich route and run_enrichment.
    """
    limits = dict(DEFAULT_LIMITS)
    try:
        with open(path, encoding="utf-8") as handle:
            lines = handle.read().splitlines()
    except OSError:
        return limits
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        name = name.strip()
        value = value.strip()
        if name in limits and value.isdigit() and int(value) > 0:
            limits[name] = int(value)
    return limits


def today_text():
    """Return today's date as "YYYY-MM-DD". Used by the daily counter."""
    return datetime.date.today().isoformat()


def read_daily_count(path=USAGE_PATH, today=None):
    """Return how many hash lookups were made today.

    Input: path of data/hash_usage.txt (one line "YYYY-MM-DD count",
    written by add_daily_count); today, a date text (default: real today).
    Output: the count, or 0 when the file is missing, garbled or from
    another day.
    Used by: the enrich route (warning) and run_enrichment (hard stop).
    """
    today = today or today_text()
    try:
        with open(path, encoding="utf-8") as handle:
            parts = handle.read().split()
    except OSError:
        return 0
    if len(parts) == 2 and parts[0] == today and parts[1].isdigit():
        return int(parts[1])
    return 0


def add_daily_count(path=USAGE_PATH, today=None):
    """Add 1 to today's hash lookup count and save it.

    Input: path and today as in read_daily_count.
    Output: the new count. A new day starts again at 1.
    Used by: run_enrichment, after every hash call (cached or not).
    """
    today = today or today_text()
    count = read_daily_count(path, today) + 1
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("%s %d\n" % (today, count))
    return count

def count_hashes(items):
    """Count the hash IOCs among the items about to be looked up.

    Input: items, ranked dicts (from next_items, or one row's item).
    Output: an integer. Used by: needs_warning.
    """
    total = 0
    for item in items:
        if item["type"] == "hash":
            total += 1
    return total


def needs_warning(items, limits, used_today):
    """Say whether looking up these items would go over the hash limits.

    Input: items, the ranked dicts about to be sent (see count_hashes);
    limits from load_limits; used_today from read_daily_count.
    Output: a list of warning lines, empty when all is fine. Lines give the
    time the per-minute rate needs and the share of the daily budget.
    Used by: confirm_and_start, which shows the dialog when the list is not
    empty.
    """
    hashes = count_hashes(items)
    per_minute = limits["hash_per_minute"]
    per_day = limits["hash_per_day"]
    lines = []
    if hashes > per_minute:
        minutes = -(-hashes // per_minute)  # round up
        lines.append("%d hash lookups at %d per minute need about %d minutes; "
                     "they are spaced out, so this run will be slow."
                     % (hashes, per_minute, minutes))
    if hashes > 0 and used_today + hashes > per_day:
        left = max(per_day - used_today, 0)
        lines.append("Daily budget: %d of %d used today and this run needs %d "
                     "more. Only %d can be sent; the rest will show 'not "
                     "enriched: %s'." % (used_today, per_day, hashes, left,
                                          BUDGET_REASON))
    return lines


def seconds_to_wait(last_time, now, spacing):
    """Return how long to wait before the next hash lookup.

    Input: last_time and now, clock readings in seconds; spacing, seconds
    between hash lookups (60 / hash_per_minute).
    Output: seconds to wait, 0 or more. Used by: run_enrichment.
    """
    wait = last_time + spacing - now
    if wait < 0:
        return 0
    return wait


def next_items(state, n):
    """Pick the next n ranked IOCs that have not been tried yet.

    Input: state (an UPLOADS entry: ranked, results); n from choose_n.
    Output: up to n ranked dicts, in rank order, with no result yet. A failed
    lookup counts as tried, so "next" moves past it; its row has a Retry
    button instead. So with 5 already done, n=5 gives ranks 6 to 10.
    Used by: ask_enrich.
    """
    tried = set()
    for result in state["results"]:
        tried.add((result["type"], result["value"]))
    items = []
    for item in state["ranked"]:
        if len(items) >= n:
            break
        if (item["type"], item["value"]) not in tried:
            items.append(item)
    return items


def store_result(state, result):
    """Save one portal answer in the shared state.

    Input: state; result, a common-shape dict from enrich_one or
    not_enriched.
    Output: nothing. An earlier answer for the same IOC (a retry) is
    replaced, otherwise the answer is added, so no IOC is counted twice.
    state["version"] goes up by one so the page knows to redraw.
    Used by: run_enrichment (the only writer).
    """
    key = (result["type"], result["value"])
    replaced = False
    for index, old in enumerate(state["results"]):
        if (old["type"], old["value"]) == key:
            state["results"][index] = result
            replaced = True
            break
    if not replaced:
        state["results"].append(result)
    state["version"] += 1


# ------------------------------------------------------- enrich thread

def run_enrichment(state, items, urls, limits, usage_path=USAGE_PATH,
                   pause=time.sleep, clock=time.monotonic):
    """Look up the given IOCs one at a time. Runs in the thread.

    Input: state (an UPLOADS entry); items, the ranked dicts to look up (from
    next_items, or one row's item); urls from enrich.load_portal_urls;
    limits from load_limits; usage_path, the daily count file; pause and
    clock, replaceable so tests need no real waiting.
    Output: nothing. Each answer is saved with store_result and
    state["run_done"] goes up. Hash lookups wait for the per-minute spacing,
    are counted, and become "not enriched" once the daily budget is used up
    (a hard stop). A crash sets state["run"] = "failed" with the text in
    state["error"]; a normal end sets "done".
    Used by: start_enrichment (as the thread target). Same sequential loop
    as enrich.enrich_ranked.
    """
    try:
        spacing = 60.0 / limits["hash_per_minute"]
        for item in items:
            if item["type"] == "hash":
                if read_daily_count(usage_path) >= limits["hash_per_day"]:
                    result = not_enriched(item, BUDGET_REASON)
                else:
                    wait = seconds_to_wait(LAST_HASH["time"], clock(), spacing)
                    if wait > 0:
                        pause(wait)
                    result = enrich_one(item, urls)
                    LAST_HASH["time"] = clock()
                    add_daily_count(usage_path)
            else:
                result = enrich_one(item, urls)
            store_result(state, result)
            state["run_done"] += 1
        state["run"] = "done"
    except Exception as error:
        state["error"] = "%s: %s" % (type(error).__name__, error)
        state["run"] = "failed"


def start_enrichment(state, items, urls, limits):
    """Start the one background thread, unless a run is already going.

    Input: state; items, the ranked dicts to look up; urls, limits as in
    run_enrichment.
    Output: True when a thread was started, False when one was already
    running (the press then does nothing). A lock makes the check and the
    start one step, so two quick presses cannot start two runs. Earlier
    results are kept: each run adds to them.
    Used by: begin_enrichment.
    """
    with START_LOCK:
        if state["run"] == "running":
            return False
        state["error"] = ""
        state["run_size"] = len(items)
        state["run_done"] = 0
        state["run"] = "running"
    thread = threading.Thread(target=run_enrichment,
                              args=(state, items, urls, limits), daemon=True)
    thread.start()
    return True


# ------------------------------------------------------- text and rows

def portal_text(portal):
    """Return the portal answer for one IOC as plain text.

    Input: portal, the common-shape dict from enrich (status, score_0_to_100,
    label, reasons), or the text "not requested" when no lookup was made.
    Output: "not requested"; "NOT ENRICHED: reason" when there is no answer;
    or "portal 80 (label)" with " [partial: some sources failed]" added when
    some sources failed. A failed lookup is never shown as a low score.
    Plain text only: NiceGUI escapes it when it is drawn.
    Used by: make_ioc_rows and build_process_node.
    """
    if not isinstance(portal, dict):
        return str(portal)
    if portal["status"] == "not_enriched":
        reason = portal["reasons"][0] if portal["reasons"] else "no reason given"
        return "NOT ENRICHED: %s" % reason
    note = " [partial: some sources failed]" if portal["status"] == "partial" else ""
    return "portal %s (%s)%s" % (portal["score_0_to_100"], portal["label"], note)


def bracket_detail(text):
    """Return the last " (...)" part of a reason, or "" when there is none.

    Example: "double extension (.mp4.exe)" gives " (.mp4.exe)".
    Used by: short_reason.
    """
    start = text.rfind(" (")
    if start == -1 or not text.endswith(")"):
        return ""
    return text[start:]


def reason_parts(text):
    """Split one scoring reason into (process name, short phrase).

    Input: text, one reason made by scoring.py, for example
    "+20 process onedrivesetup.exe: file runs from a user-writable path
    (C:\\Users\\...)", or a process signal without the points and prefix.
    Output: ("onedrivesetup.exe", "runs from a user folder"); the name is ""
    when the reason is not about a process. Points and long paths are
    dropped; a short detail is kept where it helps (a port, a double
    extension). Unknown text falls back to itself without the points and
    the bracketed part.
    Used by: short_reason and short_why.
    """
    first, _, rest = text.partition(" ")
    if first[:1] in "+-" and first[1:].isdigit():
        text = rest
    who = ""
    if text.startswith("process ") and ": " in text:
        who, text = text[len("process "):].split(": ", 1)
        first, _, rest = text.partition(" ")  # storylines put points here
        if first[:1] in "+-" and first[1:].isdigit():
            text = rest

    phrase = None
    for start, short, keep_detail in SHORT_REASONS:
        if text.startswith(start):
            phrase = short + (bracket_detail(text) if keep_detail else "")
            break
    if phrase is None and text.endswith("failed DNS lookups from one process"):
        phrase = "made %s failed DNS lookups" % text.split(" ")[0]
    if phrase is None and text.startswith("regular timing: "):
        phrase = "possible beaconing (%s)" % text[len("regular timing: "):]
    if phrase is None:
        detail = bracket_detail(text)
        phrase = text[:len(text) - len(detail)] if detail else text
    return who, phrase


def short_reason(text):
    """Turn one scoring reason into one short phrase.

    Input: text, one reason (see reason_parts).
    Output: e.g. "onedrivesetup.exe runs from a user folder".
    Used by: tests and anywhere a single reason is shown.
    """
    who, phrase = reason_parts(text)
    if who:
        return "%s %s" % (who, phrase)
    return phrase


def short_why(reasons):
    """Join the short phrases for a list of reasons into one line.

    Input: reasons, a list of scoring texts (an IOC's "reasons", or the
    reason texts of a process's signals).
    Output: one line, parts joined with " · ". Phrases about the same
    process are grouped ("a.exe runs from a user folder and sets an autorun
    registry key"); repeated phrases appear once.
    Used by: make_ioc_rows, summarize_storyline, build_storyline,
    build_process_node and make_suspicious_rows.
    """
    order = []       # parts in first-seen order: ("process", name) or ("phrase", text)
    by_process = {}  # process name -> its phrases
    for reason in reasons:
        who, phrase = reason_parts(reason)
        if who:
            if who not in by_process:
                by_process[who] = []
                order.append(("process", who))
            if phrase not in by_process[who]:
                by_process[who].append(phrase)
        elif ("phrase", phrase) not in order:
            order.append(("phrase", phrase))
    parts = []
    for kind, text in order:
        if kind == "process":
            parts.append("%s %s" % (text, " and ".join(by_process[text])))
        else:
            parts.append(text)
    return " · ".join(parts)


def storyline_why(reasons):
    """Make a storyline's "why it ranks here" reasons short.

    Input: reasons from storylines.score_storyline. They look like
    "ip 1.2.3.4: +20 connection from ..." or "process a.exe: +40 writes ...",
    plus a closing "highest of N scored items in this tree" line.
    Output: one line such as "ip 1.2.3.4: contacted by an unexpected program
    · a.exe runs from a user folder". The "highest of" line is dropped (the
    caption already gives the counts).
    Used by: build_storyline.
    """
    subject = ""
    cleaned = []
    for reason in reasons:
        if reason.startswith("highest of "):
            continue
        for kind in ("ip ", "dns ", "hash "):
            if reason.startswith(kind) and ": " in reason:
                head, reason = reason.split(": ", 1)
                subject = subject or head
                break
        cleaned.append(reason)
    text = short_why(cleaned)
    if subject:
        return "%s: %s" % (subject, text)
    return text


def make_ioc_rows(ranked, results):
    """Build the rows of the ranked IOC table.

    Input: ranked (scoring.rank_iocs, in rank order); results, the portal
    answers so far (state["results"], copied by the caller).
    Output: a list of dicts {rank, type, value, score, why, full_why,
    portal, action}, one per ranked IOC, in rank order. why is the short
    text; full_why holds every original reason (shown on hover). action is
    "Look up" when not requested, "Retry" when the lookup failed, else "".
    Used by: build_ioc_rows (the grid draws the first rows).
    """
    answers = {}
    for result in results:
        answers[(result["type"], result["value"])] = result
    rows = []
    for rank, item in enumerate(ranked, 1):
        portal = answers.get((item["type"], item["value"]), "not requested")
        if not isinstance(portal, dict):
            action = "Look up"
        elif portal["status"] == "not_enriched":
            action = "Retry"
        else:
            action = ""
        rows.append({"rank": rank, "type": item["type"], "value": item["value"],
                     "score": item["score"], "why": short_why(item["reasons"]),
                     "full_why": "\n".join(item["reasons"]),
                     "portal": portal_text(portal), "action": action})
    return rows


def make_skipped_rows(skipped):
    """Build the rows of the skipped-IOC audit table.

    Input: skipped from filters.split_iocs (type, value, reason, record).
    Output: a list of dicts {reason, type, value, count} sorted by reason,
    type, value, so the analyst can audit the filter (design.md section 9,
    rule 4). Used by: build_skipped_tab.
    """
    rows = []
    for item in sorted(skipped, key=lambda s: (s["reason"], s["type"], s["value"])):
        rows.append({"reason": item["reason"], "type": item["type"],
                     "value": item["value"], "count": item["record"]["count"]})
    return rows


def make_counts_rows(state, results):
    """Build the counts shown on the Overview tab.

    Input: state (an UPLOADS entry: iocs, skipped, ranked); results, the
    portal answers so far (one per IOC: store_result never duplicates).
    Output: a list of {item, value}: IOCs found, skipped (never sent
    anywhere), ranked, looked up, lookup failed, and not requested.
    Used by: build_overview_tab and refresh_view.
    """
    iocs = state["iocs"]
    found = len(iocs["ip"]) + len(iocs["dns"]) + len(iocs["hash"])
    looked_up = 0
    failed = 0
    for result in results:
        if result["status"] == "not_enriched":
            failed += 1
        else:
            looked_up += 1
    ranked = len(state["ranked"])
    pairs = [
        ("IOCs found (%d IPs, %d DNS names, %d hashes)"
         % (len(iocs["ip"]), len(iocs["dns"]), len(iocs["hash"])), found),
        ("Skipped by the filter (never sent anywhere)", len(state["skipped"])),
        ("Ranked locally", ranked),
        ("Looked up on the portals", looked_up),
        ("Lookup failed (not enriched)", failed),
        ("Not requested", max(ranked - len(results), 0)),
    ]
    return [{"item": label, "value": str(value)} for label, value in pairs]


def status_text(state):
    """Return the one-line run status for the Overview tab.

    Input: state (run, run_done, run_size, results, ranked, error).
    Output: text such as "Running: 3 of 5 done." or "Run failed: ...".
    Used by: build_overview_tab and refresh_view.
    """
    run = state["run"]
    if run == "idle":
        return "No portal has been called yet."
    if run == "running":
        return "Running: %d of %d done." % (state["run_done"], state["run_size"])
    tried = "%d of %d ranked IOCs tried so far." % (len(state["results"]),
                                                     len(state["ranked"]))
    if run == "done":
        return "Last run finished: %d looked up. %s" % (state["run_done"], tried)
    return "Run failed: %s. %s" % (state["error"], tried)


def make_state(name, parsed):
    """Rank a parsed dump locally and build its UPLOADS entry.

    Input: name, the uploaded file's base name (shown as a title only);
    parsed, the dict from parse.read_events.
    Output: the state dict {name, events, iocs, skipped, ranked, results,
    run, error, run_size, run_done, version}. No portal is called.
    Used by: upload_endpoint.
    """
    config = load_config()
    iocs = collect_iocs(parsed["events"])
    to_rank, skipped = split_iocs(iocs, config)
    ranked = rank_iocs(to_rank, parsed["events"], config)
    return {"name": name, "events": parsed["events"], "iocs": iocs,
            "skipped": skipped, "ranked": ranked, "results": [], "run": "idle",
            "error": "", "run_size": 0, "run_done": 0, "version": 0}


def choose_n(text, ranked):
    """Turn the dropdown value into a number of IOCs.

    Input: text from the dropdown; ranked, the list.
    Output: an int (clamped to the list length), or None if text is not one
    of N_CHOICES. Used by: ask_enrich.
    """
    if text not in N_CHOICES:
        return None
    if text == "all":
        return len(ranked)
    return min(int(text), len(ranked))


# ------------------------------------------------- storyline summaries

def count_text(number, word, plural):
    """Return "1 process" or "3 processes". Used by summary_caption."""
    return "%d %s" % (number, word if number == 1 else plural)


def summarize_storyline(table, storyline, process_scores):
    """Work out what is in one storyline.

    Input: table and storyline from storylines.build_storylines (with the
    portal answers attached); process_scores from
    scoring.build_process_scores.
    Output: {"processes": n, "flagged": [{name, score, why}] highest first,
    "ips": n, "dns": n, "files": n, "registry": n,
    "portal_hits": [text], "first": time text, "last": time text}.
    flagged are processes with a local score above 0; portal_hits are IOCs a
    portal labelled suspicious or worse.
    Used by: summary_caption and build_storyline.
    """
    flagged = []
    ips = set()
    dns = set()
    files = 0
    registry = 0
    hits = []
    times = []
    for guid in storyline["guids"]:
        entry = table[guid]
        if entry["time"]:
            times.append(entry["time"])
        process = process_scores.get(guid)
        if process is not None and process["score"] > 0:
            reasons = [reason for points, reason in process["signals"]]
            flagged.append({"name": file_name(entry["image"]) or "unknown process",
                            "score": process["score"], "why": short_why(reasons)})
        ips.update(entry["ips"])
        dns.update(entry["dns"])
        files += len(entry["files"])
        registry += len(entry["registry"])
        for ioc in entry["iocs"]:
            portal = ioc["portal"]
            if isinstance(portal, dict) and portal["label"] in PORTAL_HIT_LABELS:
                text = "%s %s: %s" % (ioc["type"], ioc["value"], portal_text(portal))
                if text not in hits:
                    hits.append(text)
    flagged.sort(key=lambda f: -f["score"])
    return {"processes": len(storyline["guids"]), "flagged": flagged,
            "ips": len(ips), "dns": len(dns), "files": files,
            "registry": registry, "portal_hits": hits,
            "first": min(times) if times else "",
            "last": max(times) if times else ""}


def summary_caption(summary):
    """Build the one-line summary shown under a collapsed storyline.

    Input: summary from summarize_storyline.
    Output: text such as "9 processes · 2 flagged · 3 remote addresses ·
    1 DNS name · 120 files · 2 registry writes · 03:42–04:10". Zero counts
    (other than processes) are left out. Used by: build_storyline.
    """
    parts = [count_text(summary["processes"], "process", "processes")]
    if summary["flagged"]:
        parts.append("%d flagged" % len(summary["flagged"]))
    if summary["portal_hits"]:
        parts.append(count_text(len(summary["portal_hits"]), "portal hit", "portal hits"))
    for key, word, plural in (("ips", "remote address", "remote addresses"),
                              ("dns", "DNS name", "DNS names"),
                              ("files", "file", "files"),
                              ("registry", "registry write", "registry writes")):
        if summary[key]:
            parts.append(count_text(summary[key], word, plural))
    if summary["first"]:
        start = summary["first"][11:16]
        end = summary["last"][11:16]
        parts.append(start if start == end else "%s–%s" % (start, end))
    return " · ".join(parts)


# ------------------------------------------------------------ timeline

def event_lane(event):
    """Return the timeline lane for one event: "Process start", "Network",
    "DNS", "File" or "Registry" (see EVENT_LANES). Used by
    make_timeline_points."""
    return EVENT_LANES.get(event["event_id"], "Other")


def event_detail(event):
    """Return one short line saying what an event did.

    Input: one event dict from parse.read_events.
    Output: text such as "onedrivesetup.exe → 20.205.115.102:443" or
    "cmd.exe queried example.com", cut to DETAIL_LENGTH characters.
    Used by: make_timeline_points.
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
    used (not the local time zone). Used by: make_timeline_points.
    """
    moment = parse_time(text)
    if moment is None:
        return None
    return calendar.timegm(moment.timetuple()) * 1000 + moment.microsecond // 1000


def score_level(score):
    """Return "normal" (0 or less), "flagged" (1 to HIGH_SCORE-1) or "high".

    Used by: make_timeline_points to pick the colour of a point.
    """
    if score <= 0:
        return "normal"
    if score < HIGH_SCORE:
        return "flagged"
    return "high"


def make_timeline_points(events, process_scores):
    """Turn every event into a point on the timeline.

    Input: events from parse.read_events; process_scores from
    scoring.build_process_scores.
    Output: {"normal": [...], "flagged": [...], "high": [...]}. Each point
    is {"value": [time in ms, lane], "name": hover text}. The group comes
    from the local score of the process that made the event, so suspicious
    processes stand out. Events with an unreadable time are left out.
    Used by: build_timeline_tab (through make_timeline_option).
    """
    points = {"normal": [], "flagged": [], "high": []}
    for event in events:
        moment = time_in_ms(event.get("time", ""))
        if moment is None:
            continue
        process = process_scores.get(event.get("ProcessGuid", ""))
        score = process["score"] if process is not None else 0
        name = "%s  %s" % (event["time"][11:19], event_detail(event))
        if score > 0:
            name += "  (process score %d)" % score
        points[score_level(score)].append({"value": [moment, event_lane(event)],
                                           "name": name})
    return points


def make_timeline_option(points):
    """Build the ECharts settings for the timeline chart.

    Input: points from make_timeline_points.
    Output: a plain dict: time along the bottom (UTC), one row per lane, a
    legend that can hide a group, a zoom slider, and a hover box that shows
    each point's text ("{b}" is ECharts' plain placeholder for the name, not
    code). Grey = normal, orange = flagged, red = high.
    Used by: build_timeline_tab.
    """
    series = []
    for key, label, color, size in TIMELINE_SERIES:
        series.append({"name": label, "type": "scatter", "symbolSize": size,
                       "itemStyle": {"color": color}, "data": points[key]})
    return {
        "useUTC": True,
        "tooltip": {"trigger": "item", "formatter": "{b}"},
        "legend": {"top": 0},
        "grid": {"left": 110, "right": 30, "top": 40, "bottom": 70},
        "xAxis": {"type": "time"},
        "yAxis": {"type": "category", "data": LANE_ORDER},
        "dataZoom": [{"type": "slider"}, {"type": "inside"}],
        "series": series,
    }


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


# -------------------------------------------------------------- upload

def save_and_parse(stream):
    """Copy an uploaded stream to a server-made file, parse it, delete it.

    Input: stream, a readable binary file object (the upload from FastAPI).
    Output: (parsed, error_code). parsed is read_events' dict, or None with
    error_code one of "size", "magic" or "read" (keys of UPLOAD_ERRORS).
    The user's file name is never used as a path. Used by: upload_endpoint.
    """
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    path = os.path.join(UPLOAD_DIR, secrets.token_hex(8) + ".evtx")
    try:
        size = 0
        with open(path, "wb") as out:
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_UPLOAD_BYTES:
                    return None, "size"
                out.write(chunk)
        with open(path, "rb") as handle:
            if handle.read(len(EVTX_MAGIC)) != EVTX_MAGIC:
                return None, "magic"
        return read_events(path), ""
    except Exception:
        return None, "read"
    finally:
        if os.path.exists(path):
            os.remove(path)


def upload_endpoint(file: UploadFile | None = None):
    """POST /upload: the plain synchronous upload handler.

    Input: file, the form field "file" posted by the upload page's form.
    Output: a redirect: to /report/<id> on success, or to /?error=<code>
    (a key of UPLOAD_ERRORS). Parses, filters and ranks locally; no portal
    is called. The state is stored under a random upload id.
    Used by: the upload form on the start page.
    """
    if file is None or not file.filename:
        return RedirectResponse("/?error=none", status_code=303)
    if not file.filename.lower().endswith(".evtx"):
        return RedirectResponse("/?error=type", status_code=303)
    parsed, code = save_and_parse(file.file)
    if parsed is None:
        return RedirectResponse("/?error=" + code, status_code=303)
    upload_id = secrets.token_hex(8)
    UPLOADS[upload_id] = make_state(os.path.basename(file.filename), parsed)
    return RedirectResponse("/report/" + upload_id, status_code=303)


# ------------------------------------------------------------ the UI

def page_setup():
    """Set the title and force a light page (dark text on a white page).

    Output: nothing. Without it a browser that prefers dark mode shows dark
    text on a dark canvas. Used by: upload_page and report_page.
    """
    ui.page_title("Sysmon summary")
    ui.dark_mode(False)
    ui.query("body").style("background-color: white")


def upload_page(error: str = ""):
    """The start page (route "/"): explanation, optional error, upload form.

    Input: error, the query value ?error=<code>; only keys of UPLOAD_ERRORS
    show a message, anything else is ignored.
    Output: draws the page. Nothing is sent to any portal by uploading.
    """
    page_setup()
    ui.label("Sysmon summary").classes("text-3xl font-bold")
    ui.label("Upload a Sysmon .evtx dump. It is read, filtered and ranked on "
             "this machine. No portal is called until you press "
             "\"Enrich next N\" or a Look up button on the report page.")
    if error in UPLOAD_ERRORS:
        ui.label(UPLOAD_ERRORS[error]).classes("text-red-700 font-bold")
    ui.html(UPLOAD_FORM, sanitize=False)


def build_show_more(draw, total_fn, step=SHOW_STEP):
    """Add a "Showing X of Y" label and a "Show more" button under content.

    Input: draw(limit), a function that (re)draws the first `limit` items of
    the content above; total_fn(), returns how many items exist; step, how
    many more each click reveals.
    Output: a redraw() function. Calling it redraws with the current limit
    and updates the label and button (used when the data changes). The
    button hides once everything is shown.
    Used by: build_ioc_tab, build_storylines_tab and build_skipped_tab.
    """
    box = {"limit": step}
    label = ui.label().classes("text-sm text-gray-600")

    def redraw():
        total = total_fn()
        draw(box["limit"])
        label.text = "Showing %d of %d" % (min(box["limit"], total), total)
        more.set_visibility(box["limit"] < total)

    def click():
        box["limit"] += step
        redraw()

    more = ui.button("Show more", on_click=click)
    redraw()
    return redraw


def build_overview_tab(view):
    """Draw the Overview tab: note, counts, and the enrich controls.

    Input: view, the page's dict of live parts (see report_page). This
    function stores "counts", "status" and "button" in it for refresh_view.
    Output: draws the tab. The N dropdown and button call ask_enrich.
    Used by: report_page.
    """
    state = view["state"]
    ui.label(NOT_A_VERDICT).classes("p-2 bg-yellow-100")
    view["counts"] = ui.table(columns=COUNT_COLUMNS, row_key="item",
                              rows=make_counts_rows(state, state["results"]))
    view["counts"].props("hide-header dense flat bordered")
    ui.label("Enrich on demand").classes("text-xl font-bold")
    ui.label("Each press sends the next N highest-ranked IOCs that have not "
             "been tried yet, one at a time. Single IOCs can be looked up "
             "from the IOCs tab.")
    with ui.row().classes("items-center"):
        choice = ui.select(N_CHOICES, value="5", label="N").classes("w-32")
        view["button"] = ui.button(
            "Enrich next N", on_click=lambda: ask_enrich(view, choice.value))
    view["status"] = ui.label(status_text(state))
    view["button"].set_enabled(state["run"] != "running")


def lookup_handler(view, rank):
    """Return a no-argument click handler that looks up one row.

    Input: view; rank, the row's 1-based rank (a number the server made).
    Output: a function for a button's on_click. A separate function is used
    so each button keeps its own rank. Used by: build_ioc_rows.
    """
    def click():
        lookup_one(view, rank)
    return click


def build_ioc_rows(container, view, limit):
    """Draw the first `limit` rows of the IOC table as a plain grid.

    Input: container, the column that holds the grid (cleared first); view
    (reads state); limit, from build_show_more.
    Output: draws a header row and one row per IOC: rank, type, value, local
    score, the short "why" (full reasons on hover), the portal answer and,
    when there is no answer yet or it failed, a Look up / Retry button.
    Used by: build_ioc_tab (through build_show_more) and refresh_view.
    """
    state = view["state"]
    rows = make_ioc_rows(state["ranked"], list(state["results"]))
    container.clear()
    with container:
        with ui.grid().classes("w-full gap-x-4 gap-y-2 items-center text-sm") \
                .style("grid-template-columns: %s" % IOC_GRID_COLUMNS):
            for title in IOC_HEADERS:
                ui.label(title).classes("font-bold")
            for row in rows[:limit]:
                ui.label(str(row["rank"]))
                ui.label(row["type"])
                ui.label(row["value"]).classes("break-all")
                ui.label(str(row["score"]))
                with ui.label(row["why"]):
                    ui.tooltip(row["full_why"]).classes("whitespace-pre-line text-sm")
                with ui.row().classes("items-center gap-2"):
                    ui.label(row["portal"])
                    if row["action"]:
                        ui.button(row["action"], on_click=lookup_handler(view, row["rank"])) \
                            .props("dense outline size=sm")


def build_ioc_tab(view):
    """Draw the IOCs tab: the ranked grid, 10 rows then "Show more".

    Input: view (stores "redraw_ioc" in it for refresh_view).
    Output: draws the tab. Used by: report_page.
    """
    state = view["state"]
    ui.label("Hover over a \"why\" to see the full reasons.") \
        .classes("text-sm text-gray-600")
    container = ui.column().classes("w-full")

    def draw(limit):
        build_ioc_rows(container, view, limit)

    view["redraw_ioc"] = build_show_more(draw, lambda: len(state["ranked"]))


def build_process_node(table, guid, depth=0):
    """Draw one process as an expandable block, then its children inside it.

    Input: table from storylines.build_storylines; guid, the process; depth,
    the nesting so far (stops at report.MAX_DEPTH).
    Output: draws an expansion with command line, user, orphan note, IPs,
    DNS names, files, registry writes, IOCs (local score beside the portal
    answer), then the children. Used by: build_storyline.
    """
    entry = table[guid]
    name = entry["image"] or "unknown process"
    with ui.expansion(name, value=(depth == 0)).classes("w-full"):
        if entry["command_line"]:
            ui.label("command line: " + entry["command_line"])
        if entry["user"]:
            ui.label("user: " + entry["user"])
        if entry["parent_image"] and entry["parent_guid"] not in table:
            ui.label("parent: %s (orphan: parent started before the capture)"
                     % entry["parent_image"]).classes("text-gray-600")
        for label, items in (("IPs contacted", entry["ips"]),
                             ("DNS names queried", entry["dns"]),
                             ("files written", entry["files"]),
                             ("registry writes", entry["registry"])):
            if items:
                ui.label("%s: %s" % (label, ", ".join(items)))
        for ioc in entry["iocs"]:
            ui.label("%s %s: local score %s | %s" % (
                ioc["type"], ioc["value"], ioc["local_score"],
                portal_text(ioc["portal"])))
            if ioc["local_reasons"]:
                ui.label(short_why(ioc["local_reasons"])).classes("text-gray-600 text-sm")
        if depth >= MAX_DEPTH and entry["children"]:
            ui.label("(deeper children not shown)").classes("text-gray-600")
        else:
            for child in entry["children"]:
                build_process_node(table, child, depth + 1)


def build_storyline(view, number):
    """Draw one ranked storyline: a summary first, full details inside.

    Input: view (reads "stories" and "process_scores"); number, the 1-based
    rank of the storyline to draw.
    Output: draws a collapsed block whose title gives rank, score and root
    process, with a one-line caption from summary_caption. Opened, it shows
    why it ranked high, the flagged processes, portal hits, and a nested
    "Full details" block holding the process tree.
    Used by: build_storylines_tab.
    """
    stories = view["stories"]
    storyline = stories["storylines"][number - 1]
    table = stories["table"]
    summary = summarize_storyline(table, storyline, view["process_scores"])
    name = file_name(table[storyline["root"]]["image"]) or "unknown process"
    title = "#%d  score %s  ·  %s" % (number, storyline["score"], name)
    with ui.expansion(title, caption=summary_caption(summary)).classes("w-full border"):
        if storyline["reasons"]:
            ui.label("Why it ranks here: " + storyline_why(storyline["reasons"]))
        if summary["flagged"]:
            ui.label("Flagged processes").classes("font-bold mt-2")
            for flagged in summary["flagged"]:
                ui.label("%s (score %d): %s" % (flagged["name"], flagged["score"],
                                                flagged["why"]))
        if summary["portal_hits"]:
            ui.label("Portal hits").classes("font-bold mt-2")
            for hit in summary["portal_hits"]:
                ui.label(hit)
        with ui.expansion("Full details").classes("w-full"):
            build_process_node(table, storyline["root"])


def build_storylines_tab(view):
    """Draw the Storylines tab: ranked process chains, 10 then "Show more".

    Input: view; reads view["state"] and keeps the built storylines in
    view["stories"]. Stores "redraw_story" for refresh_view.
    Output: draws the tab. The storylines are rebuilt (see refresh_view)
    when a run finishes so the IOC answers appear inside them.
    Used by: report_page.
    """
    state = view["state"]
    view["stories"] = build_storylines(state["events"], state["ranked"],
                                       list(state["results"]))
    view["story_version"] = state["version"]
    box = ui.column().classes("w-full")

    def draw(limit):
        box.clear()
        with box:
            for number in range(1, min(limit, len(view["stories"]["storylines"])) + 1):
                build_storyline(view, number)

    view["redraw_story"] = build_show_more(
        draw, lambda: len(view["stories"]["storylines"]))
    if view["stories"]["events_without_guid"]:
        ui.label("%d events had no process ID and are not in any storyline."
                 % view["stories"]["events_without_guid"]).classes("text-gray-600")


def build_timeline_tab(view):
    """Draw the Timeline tab: every event on a time chart, then a table of
    flagged processes in the order they first appeared.

    Input: view; reads view["state"]["events"] and view["process_scores"].
    Output: draws the tab. Uses ui.echart, which ships with NiceGUI (no new
    library). Used by: report_page.
    """
    events = view["state"]["events"]
    scores = view["process_scores"]
    ui.label("Each dot is one event. Red and orange dots come from processes "
             "with a local score (red: %d or more). Drag the slider or scroll "
             "on the chart to zoom; click a legend entry to hide a group. "
             "Times are UTC." % HIGH_SCORE).classes("text-sm text-gray-600")
    ui.echart(make_timeline_option(make_timeline_points(events, scores))) \
        .classes("w-full").style("height: 420px")
    rows = make_suspicious_rows(events, scores)
    ui.label("Flagged processes, in order of first appearance") \
        .classes("text-xl font-bold mt-4")
    if not rows:
        ui.label("none")
        return
    ui.table(columns=SUSPICIOUS_COLUMNS, rows=rows, row_key="guid") \
        .classes("w-full").props("dense flat bordered")


def build_skipped_tab(view):
    """Draw the Skipped tab: IOCs the filter never sent anywhere.

    Input: view; reads view["state"]["skipped"].
    Output: draws the audit table with reason codes, 10 rows then "Show
    more". Used by: report_page.
    """
    rows = make_skipped_rows(view["state"]["skipped"])
    ui.label("Skipped IOCs (never sent to any portal)").classes("text-xl font-bold")
    table = ui.table(columns=SKIPPED_COLUMNS, row_key="value", rows=[])
    table.classes("w-full")

    def draw(limit):
        table.rows[:] = rows[:limit]
        table.update()

    build_show_more(draw, lambda: len(rows))


def begin_enrichment(view, items, limits):
    """Start the background run and the page timer.

    Input: view; items, the ranked dicts to look up; limits from
    load_limits.
    Output: nothing. Calls start_enrichment (one run at a time); when it
    starts, the timer is switched on so the page fills in.
    Used by: confirm_and_start.
    """
    started = start_enrichment(view["state"], items, load_portal_urls(), limits)
    if started:
        view["timer"].activate()
        refresh_view(view)
    else:
        ui.notify("A run is already in progress.")


def confirm_and_start(view, items):
    """Start a run for these items, asking first if the hash limits would
    be broken.

    Input: view; items, the ranked dicts to look up.
    Output: nothing. If needs_warning returns lines, a dialog shows them with
    "Send anyway" and "Cancel"; otherwise the run starts at once.
    Used by: ask_enrich (next N) and lookup_one (a single row).
    """
    if view["state"]["run"] == "running":
        ui.notify("A run is already in progress.")
        return
    limits = load_limits()
    lines = needs_warning(items, limits, read_daily_count())
    if not lines:
        begin_enrichment(view, items, limits)
        return

    def send_anyway():
        dialog.close()
        begin_enrichment(view, items, limits)

    with ui.dialog() as dialog, ui.card():
        ui.label("Check before sending").classes("text-xl font-bold")
        for line in lines:
            ui.label(line)
        with ui.row():
            ui.button("Send anyway", on_click=send_anyway)
            ui.button("Cancel", on_click=dialog.close)
    dialog.open()


def ask_enrich(view, text):
    """Handle the "Enrich next N" button.

    Input: view; text, the dropdown value (the only thing the browser sends).
    Output: nothing. A value not in N_CHOICES is refused. Otherwise the next
    N untried IOCs (next_items) go to confirm_and_start.
    Used by: build_overview_tab (button click).
    """
    state = view["state"]
    n = choose_n(text, state["ranked"])
    if n is None:
        ui.notify("Pick N from the list.")
        return
    items = next_items(state, n)
    if not items:
        ui.notify("Every ranked IOC has been tried. Use Retry on the IOCs tab.")
        return
    confirm_and_start(view, items)


def lookup_one(view, rank):
    """Handle a row's Look up / Retry button.

    Input: view; rank, the row's 1-based rank. The browser sends only this
    number; the IOC value comes from the server's own ranked list.
    Output: nothing. A rank outside the list is ignored. Otherwise that one
    IOC goes to confirm_and_start.
    Used by: lookup_handler (row buttons).
    """
    ranked = view["state"]["ranked"]
    if not isinstance(rank, int) or rank < 1 or rank > len(ranked):
        return
    confirm_and_start(view, [ranked[rank - 1]])


def refresh_view(view):
    """Update the page from the shared state. The timer calls this.

    Input: view (state and the live parts stored by the build_* functions).
    Output: nothing. Updates the status line, the counts and the Enrich
    button every tick, and redraws the IOC rows only when an answer arrived
    (state["version"] changed) or the run state changed. When the run is no
    longer "running" it stops the timer and, if the answers changed, rebuilds
    the storylines once so the portal answers appear inside them.
    Used by: report_page (timer) and begin_enrichment.
    """
    state = view["state"]
    results = list(state["results"])
    view["status"].text = status_text(state)
    view["button"].set_enabled(state["run"] != "running")
    view["counts"].rows[:] = make_counts_rows(state, results)
    view["counts"].update()
    seen = (state["version"], state["run"])
    if view.get("seen") != seen:
        view["seen"] = seen
        view["redraw_ioc"]()
    if state["run"] != "running":
        view["timer"].deactivate()
        if view["story_version"] != state["version"]:
            view["stories"] = build_storylines(state["events"], state["ranked"],
                                               results)
            view["story_version"] = state["version"]
            view["redraw_story"]()


def report_page(upload_id: str):
    """The report page (route "/report/<id>"): header, five tabs, timer.

    Input: upload_id, from the URL; a key of UPLOADS.
    Output: draws the page. An unknown id (for example after a server
    restart) shows a message and a link to upload again. The process scores
    are worked out once here for the storylines and the timeline.
    """
    page_setup()
    state = UPLOADS.get(upload_id)
    if state is None:
        ui.label("That report does not exist (the server may have "
                 "restarted).").classes("text-red-700 font-bold")
        ui.link("Upload again", "/")
        return
    view = {"state": state, "upload_id": upload_id,
            "process_scores": build_process_scores(state["events"]),
            "seen": (state["version"], state["run"])}
    ui.label("Sysmon summary").classes("text-3xl font-bold")
    ui.label("File: " + state["name"])
    with ui.tabs() as tabs:
        overview = ui.tab("Overview")
        iocs = ui.tab("IOCs")
        stories = ui.tab("Storylines")
        timeline = ui.tab("Timeline")
        skipped = ui.tab("Skipped")
    with ui.tab_panels(tabs, value=overview).classes("w-full"):
        with ui.tab_panel(overview):
            build_overview_tab(view)
        with ui.tab_panel(iocs):
            build_ioc_tab(view)
        with ui.tab_panel(stories):
            build_storylines_tab(view)
        with ui.tab_panel(timeline):
            build_timeline_tab(view)
        with ui.tab_panel(skipped):
            build_skipped_tab(view)
    view["timer"] = ui.timer(REFRESH_SECONDS, lambda: refresh_view(view),
                             active=(state["run"] == "running"))


app.add_api_route("/upload", upload_endpoint, methods=["POST"])
ui.page("/")(upload_page)
ui.page("/report/{upload_id}")(report_page)


def main():
    """Start the web server on 127.0.0.1 (this machine only).

    The port is 5000 unless the PORT environment variable says otherwise.
    """
    load_dotenv()
    ui.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")),
           show=False, reload=False, title="Sysmon summary")


if __name__ == "__main__":
    main()
