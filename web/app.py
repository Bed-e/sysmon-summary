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

import os
import secrets

from dotenv import load_dotenv
from fastapi import UploadFile
from fastapi.responses import RedirectResponse
from nicegui import app, ui

from enrich import load_portal_urls
from parse import read_events
from report import MAX_DEPTH
from scoring import build_process_scores, file_name
from storylines import build_storylines
from web.config import (UPLOAD_DIR, N_CHOICES, REFRESH_SECONDS, SHOW_STEP,
    MAX_UPLOAD_BYTES, EVTX_MAGIC, UPLOAD_ERRORS, UPLOAD_FORM, IOC_HEADERS,
    IOC_GRID_COLUMNS, SKIPPED_COLUMNS, COUNT_COLUMNS, SUSPICIOUS_COLUMNS,
    STORYLINE_CHOICES, ROWS_VISIBLE, ROW_HEIGHT, NOT_A_VERDICT)
from web.enrich_jobs import (make_state, next_items, start_enrichment,
    status_text)
from web.limits import load_limits, needs_warning, read_daily_count
from web.reasons import portal_text, short_why, storyline_why
from web.rows import (choose_n, make_counts_rows, make_ioc_rows,
    make_skipped_rows)
from web.runtime import UPLOADS
from web.storyline_summary import summarize_storyline, summary_caption
from web.timeline_chart import make_process_timeline
from web.timeline_data import (flagged_slice, make_suspicious_rows,
    order_rows, process_spans, storyline_slice)


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


def slice_choices(stories):
    """Build the entries of the timeline's "Show" dropdown.

    Input: stories from storylines.build_storylines.
    Output: {value: label}: "flagged" (the default), "story:1" ...
    "story:20" for the top STORYLINE_CHOICES storylines, and "all".
    Used by: build_timeline_tab.
    """
    choices = {"flagged": "Flagged processes and their parents"}
    table = stories["table"]
    for number, storyline in enumerate(stories["storylines"][:STORYLINE_CHOICES], 1):
        name = file_name(table[storyline["root"]]["image"]) or "unknown process"
        choices["story:%d" % number] = "Storyline #%d: %s (%d processes)" % (
            number, name, storyline["size"])
    choices["all"] = "All processes (%d)" % len(table)
    return choices


def slice_guids(view, choice):
    """Turn a dropdown value into the set of processes to show.

    Input: view (reads "stories" and "process_scores"); choice, a key of
    slice_choices. Anything unknown falls back to the flagged slice.
    Output: a set of guids. Used by: draw_process_timeline.
    """
    stories = view["stories"]
    if choice == "all":
        return set(stories["table"])
    if choice.startswith("story:"):
        number = choice[len("story:"):]
        if number.isdigit() and 1 <= int(number) <= len(stories["storylines"]):
            return storyline_slice(stories, int(number))
    return flagged_slice(stories["table"], view["process_scores"])


def draw_process_timeline(view, box, note, choice):
    """Redraw the timeline chart for one slice.

    Input: view; box, the column that holds the chart; note, a label for the
    row count; choice, the dropdown value.
    Output: nothing. Clears the box and draws a new ui.echart from
    make_process_timeline for the chosen processes, with its height set from
    the row count (up to ROWS_VISIBLE rows), and updates the note. A new
    chart is made each time because an existing chart keeps drawing at its
    old size when only its height changes.
    Used by: build_timeline_tab (first draw and dropdown changes).
    """
    table = view["stories"]["table"]
    rows = order_rows(table, slice_guids(view, choice))
    option = make_process_timeline(table, rows, view["spans"],
                                   view["state"]["events"], view["process_scores"])
    visible = max(min(len(rows), ROWS_VISIBLE), 3)
    box.clear()
    with box:
        height = visible * ROW_HEIGHT + 130
        ui.echart(option).classes("w-full").style("height: %dpx" % height)
    note.text = "%d processes shown." % len(rows)


def build_timeline_tab(view):
    """Draw the Timeline tab: a per-process timeline, then a table of
    flagged processes in the order they first appeared.

    Input: view; reads view["state"]["events"], view["stories"] (built by
    build_storylines_tab, which is drawn first) and view["process_scores"].
    Stores view["spans"].
    Output: draws a "Show" dropdown (flagged processes and their parents,
    one storyline, or all), the chart and the table. Uses ui.echart, which
    ships with NiceGUI (no new library). Used by: report_page.
    """
    events = view["state"]["events"]
    view["spans"] = process_spans(events)
    ui.label("One row per process, in tree order (children under their "
             "parent). The bar runs from a process's first to its last event "
             "and is coloured by its local score; dots are its events; dashed "
             "lines link a parent to each child it started. Hover for details, "
             "click a legend entry to hide a group, drag the sliders to zoom. "
             "Times are UTC.").classes("text-sm text-gray-600")
    with ui.row().classes("items-center"):
        choice = ui.select(slice_choices(view["stories"]), value="flagged",
                           label="Show").classes("w-96")
        note = ui.label().classes("text-sm text-gray-600")
    box = ui.column().classes("w-full")
    choice.on_value_change(lambda event: draw_process_timeline(view, box, note, event.value))
    draw_process_timeline(view, box, note, "flagged")

    rows = make_suspicious_rows(events, view["process_scores"])
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
