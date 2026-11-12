"""M5: the Flask web app.

Run from the project folder:

    python -m web.app

Open http://127.0.0.1:5000. Upload a Sysmon .evtx dump: it is parsed,
filtered and ranked locally and the report is shown. NO portal is called
until the analyst picks N and presses "Enrich top N". Then ONE background
thread looks up the top N IOCs, one at a time, highest rank first (the same
sequential loop as M3), and the page reloads itself every few seconds
(<meta refresh>, no JavaScript) so the answers appear as they arrive.

Rules kept here (design.md section 7):
- The browser never sends an IOC value back. It sends only N, so the server
  only ever looks up IOCs it ranked itself.
- Only hash lookups reach VirusTotal, so only they are counted and paced.
  The limits come from data/api_limits.txt; today's count is kept in
  data/hash_usage.txt so a restart does not reset it.
- Everything that came from a dump is escaped by report.escape_text.
- The server listens on 127.0.0.1 only.

Flask forces one module-level object (app). Routes are attached with plain
add_url_rule calls, not decorators.
"""

import datetime
import os
import secrets
import threading
import time

from dotenv import load_dotenv
from flask import Flask, redirect, request

from enrich import enrich_one, load_portal_urls, not_enriched
from filters import load_config, split_iocs
from iocs import collect_iocs
from parse import read_events
from report import build_report, describe_portal, escape_text
from scoring import rank_iocs
from storylines import build_storylines

LIMITS_PATH = os.path.join("data", "api_limits.txt")
USAGE_PATH = os.path.join("data", "hash_usage.txt")
UPLOAD_DIR = "uploads"

DEFAULT_LIMITS = {"hash_per_minute": 4, "hash_per_day": 500}
N_CHOICES = ["5", "10", "25", "50", "100", "all"]
REFRESH_SECONDS = 3
MAX_UPLOAD_BYTES = 200 * 1024 * 1024
EVTX_MAGIC = b"ElfFile\x00"
BUDGET_REASON = "daily VirusTotal budget reached"

# Shared state (design.md section 7): upload id -> state dict. Only the
# enrich thread writes "results", "run" and "error"; pages only read them.
UPLOADS = {}
# Time of the last hash lookup, so pacing also holds across two runs.
LAST_HASH = {"time": 0.0}
START_LOCK = threading.Lock()

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES

STYLE = """
body { font-family: sans-serif; margin: 1.5em; line-height: 1.4; }
.panel { border: 1px solid #888; padding: 0.5em 1em; margin: 1em 0; max-width: 60em; }
.error { color: #b00020; font-weight: bold; }
table.ranked { width: 100%; font-size: 0.9em; }
table.ranked td:nth-child(3) { min-width: 16em; }
table.ranked td:nth-child(5) { font-size: 0.85em; }
button, select { font-size: 1em; }
"""


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


# ------------------------------------------------------------- HTML

def page(title, body, extra_head=""):
    """Wrap a body in a small full HTML document (upload and confirm pages).

    Input: title and body; body is HTML built by this module, title is
    escaped here. Used by: build_upload_page and build_confirm_page.
    """
    return ("<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<title>%s</title><style>%s</style>%s</head><body>%s</body></html>"
            % (escape_text(title), STYLE, extra_head, body))


def build_upload_page(message=""):
    """Build the start page: one upload form.

    Input: message, an error text to show (escaped here), or "".
    Output: HTML. Nothing is sent to any portal by uploading.
    Used by: the index and upload routes.
    """
    body = ["<h1>Sysmon summary</h1>",
            "<p>Upload a Sysmon <code>.evtx</code> dump. It is read, filtered "
            "and ranked on this machine. No portal is called until you press "
            "&ldquo;Enrich top N&rdquo; on the report page.</p>"]
    if message:
        body.append('<p class="error">%s</p>' % escape_text(message))
    body.append('<form method="post" action="/upload" enctype="multipart/form-data">'
                '<input type="file" name="dump" accept=".evtx"> '
                '<button type="submit">Upload and rank</button></form>')
    return page("Sysmon summary", "\n".join(body))


def build_ranked_table(ranked, results):
    """Build the table of ranked IOCs with the portal column.

    Input: ranked (scoring.rank_iocs); results, the answers so far.
    Output: HTML with rank, type, value, local score, reasons and the portal
    answer ("not requested" until looked up). Rank is the order the lookups
    follow. Used by: build_controls.
    """
    answers = {}
    for result in results:
        answers[(result["type"], result["value"])] = result
    lines = ['<table class="ranked"><tr><th>rank</th><th>type</th><th>value</th>'
             '<th>local score</th><th>why</th><th>portal</th></tr>']
    for rank, item in enumerate(ranked, 1):
        portal = answers.get((item["type"], item["value"]), "not requested")
        lines.append("<tr><td>%d</td><td>%s</td><td><code>%s</code></td>"
                     "<td>%s</td><td>%s</td><td>%s</td></tr>"
                     % (rank, escape_text(item["type"]), escape_text(item["value"]),
                        escape_text(item["score"]),
                        "; ".join(escape_text(r) for r in item["reasons"]),
                        describe_portal(portal)))
    lines.append("</table>")
    return "\n".join(lines)


def build_controls(upload_id, state):
    """Build the panel with the enrich form, run status and ranked table.

    Input: upload_id (our own token) and state (UPLOADS entry).
    Output: HTML. The form posts only N. The button is disabled while a run
    is going. Shows the failure text if the thread crashed.
    Used by: render_report, passed to build_report as extra_body.
    """
    total = len(state["ranked"])
    run = state["run"]
    if run == "idle":
        status = "No portal has been called yet."
    elif run == "running":
        status = "Running: %d of %d done. This page reloads by itself." % (
            len(state["results"]), min(state["n"], total))
    elif run == "done":
        status = "Finished: %d IOCs looked up." % len(state["results"])
    else:
        status = "Run failed: " + state["error"]
    options = "".join('<option value="%s">%s</option>' % (c, c) for c in N_CHOICES)
    disabled = " disabled" if run == "running" else ""
    lines = ['<div class="panel"><h2>Enrich on demand</h2>',
             "<p>%d IOCs ranked locally. Only the top N are sent to the portals, "
             "one at a time.</p>" % total,
             '<form method="post" action="/enrich/%s">' % escape_text(upload_id),
             'Top N: <select name="n">%s</select> ' % options,
             '<button type="submit"%s>Enrich top N</button></form>' % disabled,
             '<p class="%s">%s</p>' % ("error" if run == "failed" else "",
                                       escape_text(status)),
             "</div>", "<h2>Ranked IOCs</h2>",
             build_ranked_table(state["ranked"], state["results"])]
    return "\n".join(lines)


def build_confirm_page(upload_id, n, lines):
    """Build the warning page shown before a run that would break the limits.

    Input: upload_id; n (the choice, "5".."all"); lines from needs_warning.
    Output: HTML with the warnings, a Send anyway button (posts n and
    confirm=yes) and a Cancel link back to the report.
    Used by: the enrich route.
    """
    items = "".join("<li>%s</li>" % escape_text(line) for line in lines)
    uid = escape_text(upload_id)
    body = ("<h1>Check before sending</h1><ul>%s</ul>"
            '<form method="post" action="/enrich/%s">'
            '<input type="hidden" name="n" value="%s">'
            '<input type="hidden" name="confirm" value="yes">'
            '<button type="submit">Send anyway</button> '
            '<a href="/report/%s">Cancel</a></form>'
            % (items, uid, escape_text(n), uid))
    return page("Check before sending", body)


def render_report(upload_id):
    """Build the full report page for one upload.

    Input: upload_id, a key of UPLOADS.
    Output: HTML from report.build_report with the controls inserted and,
    while the thread runs, the refresh tag in <head>. Reads the results
    list as a copy, because the thread may be appending to it.
    Used by: the report route.
    """
    state = UPLOADS[upload_id]
    results = list(state["results"])
    stories = build_storylines(state["events"], state["ranked"], results)
    extra_head = "<style>%s</style>" % STYLE
    if state["run"] == "running":
        extra_head += '<meta http-equiv="refresh" content="%d">' % REFRESH_SECONDS
    shown = dict(state, results=results)
    cap = state["n"] if state["n"] else len(state["ranked"])
    return build_report(state["name"], state["iocs"], state["skipped"],
                        state["ranked"], results, cap, stories,
                        extra_head, build_controls(upload_id, shown))


# ------------------------------------------------------------ routes

def index():
    """GET /: the upload form."""
    return build_upload_page()


def save_and_parse(storage):
    """Save an uploaded file under a server-made name, parse it, delete it.

    Input: storage, the uploaded file object from Flask.
    Output: (parsed, error_text). parsed is read_events' dict, or None with
    the reason in error_text. The user's file name is never used as a path.
    Used by: upload.
    """
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    path = os.path.join(UPLOAD_DIR, secrets.token_hex(8) + ".evtx")
    storage.save(path)
    try:
        with open(path, "rb") as handle:
            if handle.read(len(EVTX_MAGIC)) != EVTX_MAGIC:
                return None, "That file is not a Windows .evtx log."
        return read_events(path), ""
    except Exception as error:
        return None, "Could not read that file (%s)." % type(error).__name__
    finally:
        os.remove(path)


def upload():
    """POST /upload: parse, filter and rank locally, then show the report.

    Output: a redirect to /report/<id>, or the upload page with an error.
    No portal is called. The state is stored under a random upload id.
    """
    storage = request.files.get("dump")
    if storage is None or not storage.filename:
        return build_upload_page("Choose a .evtx file first."), 400
    if not storage.filename.lower().endswith(".evtx"):
        return build_upload_page("Only .evtx files are accepted."), 400
    parsed, error = save_and_parse(storage)
    if parsed is None:
        return build_upload_page(error), 400
    config = load_config()
    iocs = collect_iocs(parsed["events"])
    to_rank, skipped = split_iocs(iocs, config)
    ranked = rank_iocs(to_rank, parsed["events"], config)
    upload_id = secrets.token_hex(8)
    UPLOADS[upload_id] = {
        "name": os.path.basename(storage.filename),
        "events": parsed["events"], "iocs": iocs, "skipped": skipped,
        "ranked": ranked, "results": [], "run": "idle", "error": "", "n": 0,
    }
    return redirect("/report/" + upload_id)


def report(upload_id):
    """GET /report/<id>: the report page, 404 for an unknown id."""
    if upload_id not in UPLOADS:
        return build_upload_page("That report does not exist (the server "
                                 "may have restarted). Upload again."), 404
    return render_report(upload_id)


def choose_n(text, ranked):
    """Turn the dropdown value into a number of IOCs.

    Input: text from the form; ranked, the list.
    Output: an int (clamped to the list length), or None if text is not one
    of N_CHOICES. Used by: enrich.
    """
    if text not in N_CHOICES:
        return None
    if text == "all":
        return len(ranked)
    return min(int(text), len(ranked))


def enrich(upload_id):
    """POST /enrich/<id>: start the lookups for the top N.

    Input from the browser: only "n" (and "confirm" on the warning page).
    Output: the confirmation page when the limits would be exceeded and not
    yet confirmed; otherwise starts the thread (or does nothing if one is
    running) and redirects to the report.
    """
    if upload_id not in UPLOADS:
        return build_upload_page("That report does not exist."), 404
    state = UPLOADS[upload_id]
    n = choose_n(request.form.get("n", ""), state["ranked"])
    if n is None:
        return build_upload_page("Pick N from the list."), 400
    limits = load_limits()
    if request.form.get("confirm") != "yes":
        lines = needs_warning(state["ranked"], n, limits, read_daily_count())
        if lines:
            return build_confirm_page(upload_id, request.form["n"], lines)
    start_enrichment(state, n, load_portal_urls(), limits)
    return redirect("/report/" + upload_id)


app.add_url_rule("/", "index", index)
app.add_url_rule("/upload", "upload", upload, methods=["POST"])
app.add_url_rule("/report/<upload_id>", "report", report)
app.add_url_rule("/enrich/<upload_id>", "enrich", enrich, methods=["POST"])


def main():
    """Start the web server on 127.0.0.1 (this machine only).

    The port is 5000 unless the PORT environment variable says otherwise.
    """
    load_dotenv()
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")),
            debug=False)


if __name__ == "__main__":
    main()
