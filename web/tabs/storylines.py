"""The Storylines tab: one expandable process tree per storyline.
"""

from nicegui import ui

from report import MAX_DEPTH
from scoring.paths import file_name
from storylines import build_storylines
from web.reasons import portal_text, short_why, storyline_why
from web.storyline_summary import summarize_storyline, summary_caption
from web.tabs.common import build_show_more, score_badge


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
    with ui.expansion(name, value=(depth == 0)).classes("w-full process-node"):
        if entry["command_line"]:
            ui.label("command line: " + entry["command_line"]).classes("process-cmd")
        if entry["user"]:
            ui.label("user: " + entry["user"])
        if entry["parent_image"] and entry["parent_guid"] not in table:
            ui.label("parent: %s (orphan: parent started before the capture)"
                     % entry["parent_image"]).classes("app-muted")
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
                ui.label(short_why(ioc["local_reasons"])).classes("app-muted")
        if depth >= MAX_DEPTH and entry["children"]:
            ui.label("(deeper children not shown)").classes("app-muted")
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
    title = "#%d  ·  %s" % (number, name)
    with ui.expansion().classes("w-full app-card storyline") as box:
        with box.add_slot("header"):
            with ui.row().classes("items-center gap-3 no-wrap"):
                score_badge(storyline["score"])
                with ui.column().classes("gap-0"):
                    ui.label(title).classes("app-title")
                    ui.label(summary_caption(summary)).classes("app-muted")
        if storyline["reasons"]:
            ui.label("Why it ranks here: " + storyline_why(storyline["reasons"]))
        if summary["flagged"]:
            ui.label("Flagged processes").classes("app-section")
            for flagged in summary["flagged"]:
                ui.label("%s (score %d): %s" % (flagged["name"], flagged["score"],
                                                flagged["why"]))
        if summary["portal_hits"]:
            ui.label("Portal hits").classes("app-section")
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
                 % view["stories"]["events_without_guid"]).classes("app-muted")
