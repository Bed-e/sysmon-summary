"""M5: the web app (NiceGUI), with tabs.

Run from the project folder:

    python -m web.app

Open http://127.0.0.1:5000. Upload a Sysmon .evtx dump: it is parsed,
filtered and ranked locally and the report is shown in four tabs:
Overview, IOCs, Storylines and Skipped. NO portal is called until the
analyst picks N and presses "Enrich top N". Then ONE background thread looks
up the top N IOCs, one at a time, highest rank first (the same sequential
loop as M3). A timer on the page updates the table and status in place as
answers arrive (no page reload).

Rules kept here (design.md section 7):
- The browser never sends an IOC value back. It sends only N, so the server
  only ever looks up IOCs it ranked itself.
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

import datetime
import os
import secrets
import shutil
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
from scoring import rank_iocs
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

IOC_COLUMNS = [
    {"name": "rank", "label": "Rank", "field": "rank", "align": "left"},
    {"name": "type", "label": "Type", "field": "type", "align": "left"},
    {"name": "value", "label": "Value", "field": "value", "align": "left",
     "style": "white-space: normal; word-break: break-all; min-width: 14em; max-width: 20em"},
    {"name": "score", "label": "Local score", "field": "score", "align": "left"},
    {"name": "why", "label": "Why", "field": "why", "align": "left",
     "style": "white-space: normal; min-width: 24em"},
    {"name": "portal", "label": "Portal", "field": "portal", "align": "left",
     "style": "white-space: normal; min-width: 12em"},
]
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


def count_hashes(ranked, n):
    """Count the hash IOCs among the top n ranked items.

    Input: ranked, the list from scoring.rank_iocs; n, how many to look up.
    Output: an integer. Used by: needs_warning.
    """
    total = 0
    for item in ranked[:n]:
        if item["type"] == "hash":
            total += 1
    return total


def needs_warning(ranked, n, limits, used_today):
    """Say whether the top n would go over the hash limits.

    Input: ranked and n (see count_hashes); limits from load_limits;
    used_today from read_daily_count.
    Output: a list of warning lines, empty when all is fine. Lines give the
    time the per-minute rate needs and the share of the daily budget.
    Used by: the enrich route, which shows the confirmation page when the
    list is not empty.
    """
    hashes = count_hashes(ranked, n)
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


# ------------------------------------------------------- enrich thread

def run_enrichment(state, n, urls, limits, usage_path=USAGE_PATH,
                   pause=time.sleep, clock=time.monotonic):
    """Look up the top n ranked IOCs one at a time. Runs in the thread.

    Input: state (an UPLOADS entry, with "ranked"); n; urls from
    enrich.load_portal_urls; limits from load_limits; usage_path, the daily
    count file; pause and clock, replaceable so tests need no real waiting.
    Output: nothing. It appends one common-shape dict per IOC to
    state["results"] in rank order. Hash lookups wait for the per-minute
    spacing, are counted, and become "not enriched" once the daily budget is
    used up (a hard stop). A crash sets state["run"] = "failed" with the
    text in state["error"]; a normal end sets "done".
    Used by: start_enrichment (as the thread target). Same loop as
    enrich.enrich_ranked, one IOC at a time.
    """
    try:
        spacing = 60.0 / limits["hash_per_minute"]
        for item in state["ranked"][:n]:
            if item["type"] == "hash":
                if read_daily_count(usage_path) >= limits["hash_per_day"]:
                    state["results"].append(not_enriched(item, BUDGET_REASON))
                    continue
                wait = seconds_to_wait(LAST_HASH["time"], clock(), spacing)
                if wait > 0:
                    pause(wait)
                result = enrich_one(item, urls)
                LAST_HASH["time"] = clock()
                add_daily_count(usage_path)
            else:
                result = enrich_one(item, urls)
            state["results"].append(result)
        state["run"] = "done"
    except Exception as error:
        state["error"] = "%s: %s" % (type(error).__name__, error)
        state["run"] = "failed"


def start_enrichment(state, n, urls, limits):
    """Start the one background thread, unless a run is already going.

    Input: state, n, urls, limits as in run_enrichment.
    Output: True when a thread was started, False when one was already
    running (the button press then does nothing). A lock makes the check and
    the start one step, so two quick presses cannot start two runs.
    Starting a new run clears the earlier results of this upload.
    Used by: the enrich route.
    """
    with START_LOCK:
        if state["run"] == "running":
            return False
        state["results"] = []
        state["error"] = ""
        state["n"] = n
        state["run"] = "running"
    thread = threading.Thread(target=run_enrichment,
                              args=(state, n, urls, limits), daemon=True)
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


def make_ioc_rows(ranked, results):
    """Build the rows of the ranked IOC table.

    Input: ranked (scoring.rank_iocs, in rank order); results, the portal
    answers so far (state["results"], copied by the caller).
    Output: a list of dicts {rank, type, value, score, why, portal}, one per
    ranked IOC, in rank order. portal is "not requested" until looked up.
    Used by: build_ioc_tab and refresh_view (the table draws the first rows).
    """
    answers = {}
    for result in results:
        answers[(result["type"], result["value"])] = result
    rows = []
    for rank, item in enumerate(ranked, 1):
        portal = answers.get((item["type"], item["value"]), "not requested")
        rows.append({"rank": rank, "type": item["type"], "value": item["value"],
                     "score": item["score"], "why": "; ".join(item["reasons"]),
                     "portal": portal_text(portal)})
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
    portal answers so far.
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

    Input: state (run, results, n, ranked, error).
    Output: text such as "Running: 3 of 5 done." or "Run failed: ...".
    Used by: build_overview_tab and refresh_view.
    """
    run = state["run"]
    if run == "idle":
        return "No portal has been called yet."
    if run == "running":
        return "Running: %d of %d done." % (len(state["results"]),
                                            min(state["n"], len(state["ranked"])))
    if run == "done":
        return "Finished: %d IOCs looked up." % len(state["results"])
    return "Run failed: " + state["error"]


def make_state(name, parsed):
    """Rank a parsed dump locally and build its UPLOADS entry.

    Input: name, the uploaded file's base name (shown as a title only);
    parsed, the dict from parse.read_events.
    Output: the state dict {name, events, iocs, skipped, ranked, results,
    run, error, n}. No portal is called.
    Used by: upload_endpoint.
    """
    config = load_config()
    iocs = collect_iocs(parsed["events"])
    to_rank, skipped = split_iocs(iocs, config)
    ranked = rank_iocs(to_rank, parsed["events"], config)
    return {"name": name, "events": parsed["events"], "iocs": iocs,
            "skipped": skipped, "ranked": ranked, "results": [], "run": "idle",
            "error": "", "n": 0}


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
             "\"Enrich top N\" on the report page.")
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
    Output: draws the tab. The Top N dropdown and button call ask_enrich.
    Used by: report_page.
    """
    state = view["state"]
    ui.label(NOT_A_VERDICT).classes("p-2 bg-yellow-100")
    view["counts"] = ui.table(columns=COUNT_COLUMNS, row_key="item",
                              rows=make_counts_rows(state, state["results"]))
    view["counts"].props("hide-header dense flat bordered")
    ui.label("Enrich on demand").classes("text-xl font-bold")
    ui.label("Only the top N ranked IOCs are sent to the portals, one at a time.")
    with ui.row().classes("items-center"):
        choice = ui.select(N_CHOICES, value="5", label="Top N").classes("w-32")
        view["button"] = ui.button(
            "Enrich top N", on_click=lambda: ask_enrich(view, choice.value))
    view["status"] = ui.label(status_text(state))
    view["button"].set_enabled(state["run"] != "running")


def build_ioc_tab(view):
    """Draw the IOCs tab: the ranked table, 10 rows then "Show more".

    Input: view (stores "redraw_ioc" in it for refresh_view).
    Output: draws the tab. The table shows the first rows of
    make_ioc_rows; each Show more click adds SHOW_STEP rows.
    Used by: report_page.
    """
    state = view["state"]
    table = ui.table(columns=IOC_COLUMNS, row_key="rank", rows=[])
    table.classes("w-full")

    def rows():
        return make_ioc_rows(state["ranked"], list(state["results"]))

    def draw(limit):
        table.rows[:] = rows()[:limit]
        table.update()

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
                ui.label("; ".join(ioc["local_reasons"])).classes("text-gray-600 text-sm")
        if depth >= MAX_DEPTH and entry["children"]:
            ui.label("(deeper children not shown)").classes("text-gray-600")
        else:
            for child in entry["children"]:
                build_process_node(table, child, depth + 1)


def build_storyline(stories, number):
    """Draw one ranked storyline.

    Input: stories, the dict from storylines.build_storylines; number, the
    1-based rank of the storyline to draw.
    Output: draws a collapsed block titled with rank, score, root process
    and tree size, holding the reasons and the process tree.
    Used by: build_storylines_tab.
    """
    storyline = stories["storylines"][number - 1]
    table = stories["table"]
    name = table[storyline["root"]]["image"] or "unknown process"
    title = "#%d score %s: %s (%d processes)" % (number, storyline["score"],
                                                 name, storyline["size"])
    with ui.expansion(title).classes("w-full border"):
        for reason in storyline["reasons"]:
            ui.label(reason)
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
    view["story_results"] = len(state["results"])
    box = ui.column().classes("w-full")

    def draw(limit):
        box.clear()
        with box:
            for number in range(1, min(limit, len(view["stories"]["storylines"])) + 1):
                build_storyline(view["stories"], number)

    view["redraw_story"] = build_show_more(
        draw, lambda: len(view["stories"]["storylines"]))
    if view["stories"]["events_without_guid"]:
        ui.label("%d events had no process ID and are not in any storyline."
                 % view["stories"]["events_without_guid"]).classes("text-gray-600")


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


def begin_enrichment(view, n, limits):
    """Start the background run and the page timer.

    Input: view; n, number of IOCs; limits from load_limits.
    Output: nothing. Calls start_enrichment (one run at a time); when it
    starts, the timer is switched on so the page fills in. Used by
    ask_enrich.
    """
    started = start_enrichment(view["state"], n, load_portal_urls(), limits)
    if started:
        view["timer"].activate()
        refresh_view(view)
    else:
        ui.notify("A run is already in progress.")


def ask_enrich(view, text):
    """Handle the "Enrich top N" button.

    Input: view; text, the dropdown value (the only thing the browser sends).
    Output: nothing. A value that is not in N_CHOICES is refused. If the top
    N would break the hash limits (needs_warning), a dialog shows the warning
    lines with "Send anyway" and "Cancel"; otherwise the run starts at once.
    Used by: build_overview_tab (button click).
    """
    state = view["state"]
    n = choose_n(text, state["ranked"])
    if n is None:
        ui.notify("Pick N from the list.")
        return
    limits = load_limits()
    lines = needs_warning(state["ranked"], n, limits, read_daily_count())
    if not lines:
        begin_enrichment(view, n, limits)
        return

    def send_anyway():
        dialog.close()
        begin_enrichment(view, n, limits)

    with ui.dialog() as dialog, ui.card():
        ui.label("Check before sending").classes("text-xl font-bold")
        for line in lines:
            ui.label(line)
        with ui.row():
            ui.button("Send anyway", on_click=send_anyway)
            ui.button("Cancel", on_click=dialog.close)
    dialog.open()


def refresh_view(view):
    """Update the page from the shared state. The timer calls this.

    Input: view (state and the live parts stored by the build_* functions).
    Output: nothing. Updates the status line, the counts, the Enrich button
    and the IOC table. When the run is no longer "running" it stops the
    timer and, if the answers changed, rebuilds the storylines once so the
    portal answers appear inside them.
    Used by: report_page (timer) and begin_enrichment.
    """
    state = view["state"]
    results = list(state["results"])
    view["status"].text = status_text(state)
    view["button"].set_enabled(state["run"] != "running")
    view["counts"].rows[:] = make_counts_rows(state, results)
    view["counts"].update()
    view["redraw_ioc"]()
    if state["run"] != "running":
        view["timer"].deactivate()
        if view["story_results"] != len(results):
            view["stories"] = build_storylines(state["events"], state["ranked"],
                                               results)
            view["story_results"] = len(results)
            view["redraw_story"]()


def report_page(upload_id: str):
    """The report page (route "/report/<id>"): header, four tabs, timer.

    Input: upload_id, from the URL; a key of UPLOADS.
    Output: draws the page. An unknown id (for example after a server
    restart) shows a message and a link to upload again.
    """
    page_setup()
    state = UPLOADS.get(upload_id)
    if state is None:
        ui.label("That report does not exist (the server may have "
                 "restarted).").classes("text-red-700 font-bold")
        ui.link("Upload again", "/")
        return
    view = {"state": state, "upload_id": upload_id}
    ui.label("Sysmon summary").classes("text-3xl font-bold")
    ui.label("File: " + state["name"])
    with ui.tabs() as tabs:
        overview = ui.tab("Overview")
        iocs = ui.tab("IOCs")
        stories = ui.tab("Storylines")
        skipped = ui.tab("Skipped")
    with ui.tab_panels(tabs, value=overview).classes("w-full"):
        with ui.tab_panel(overview):
            build_overview_tab(view)
        with ui.tab_panel(iocs):
            build_ioc_tab(view)
        with ui.tab_panel(stories):
            build_storylines_tab(view)
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
