"""The Storylines tab: one expandable card per attack chain.

(R3 turns this into the Chains tab with Enrich this chain; R2 only switches
it to the chains built once at upload.)
"""

from nicegui import ui

from scoring.paths import file_name
from web.config import MAX_DEPTH
from web.reasons import portal_text, short_why
from web.storyline_summary import (chain_title, ioc_details,
    summarize_storyline, summary_caption)
from web.tabs.common import build_show_more, score_badge


def build_process_node(table, guid, details, depth=0):
    """Draw one process as an expandable block, then its children inside it.

    Input: table from storylines.build_chains; guid, the process; details
    from ioc_details (local score and portal answer per IOC); depth, the
    nesting so far (stops at MAX_DEPTH).
    Output: draws an expansion with command line, user, orphan note,
    "dropped by" note, IPs, DNS names, files, registry writes, IOCs (local
    score beside the portal answer), then the children.
    Used by: build_storyline.
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
        if entry["dropped_by"]:
            dropper = entry["dropped_by"]
            ui.label("file written by %s at %s" % (
                file_name(dropper["image"]) or "unknown process",
                dropper["time"][11:19])).classes("app-section")
        for label, items in (("IPs contacted", entry["ips"]),
                             ("DNS names queried", entry["dns"]),
                             ("files written", entry["files"]),
                             ("registry writes", entry["registry"])):
            if items:
                ui.label("%s: %s" % (label, ", ".join(items)))
        for key in entry["iocs"]:
            detail = details.get(key)
            if detail is None:
                continue
            ui.label("%s %s: local score %s | %s" % (
                key[0], key[1], detail["score"], portal_text(detail["portal"])))
            if detail["reasons"]:
                ui.label(short_why(detail["reasons"])).classes("app-muted")
        if depth >= MAX_DEPTH and entry["children"]:
            ui.label("(deeper children not shown)").classes("app-muted")
        else:
            for child in entry["children"]:
                build_process_node(table, child, details, depth + 1)


def build_storyline(view, number, details):
    """Draw one ranked chain: a summary first, full details inside.

    Input: view (reads "chains" and "process_scores"); number, the 1-based
    rank of the chain to draw; details from ioc_details.
    Output: draws a collapsed block whose title is the chain's strongest
    finding (chain_title), with a one-line caption from summary_caption.
    Opened, it shows the flagged processes, portal hits, and a nested
    "Full details" block holding the process tree.
    Used by: build_storylines_tab.
    """
    chains = view["chains"]
    chain = chains["chains"][number - 1]
    table = chains["table"]
    summary = summarize_storyline(table, chain, view["process_scores"], details)
    title = "#%d  ·  %s" % (number, chain_title(table, chain["title_finding"]))
    with ui.expansion().classes("w-full app-card storyline") as box:
        with box.add_slot("header"):
            with ui.row().classes("items-center gap-3 no-wrap"):
                score_badge(chain["score"])
                with ui.column().classes("gap-0"):
                    ui.label(title).classes("app-title")
                    ui.label(summary_caption(summary)).classes("app-muted")
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
            build_process_node(table, chain["root"], details)


def build_storylines_tab(view):
    """Draw the Storylines tab: ranked chains, 10 then "Show more".

    Input: view; reads view["state"]["chains"] (built once at upload) and
    keeps it in view["chains"]. Stores "redraw_story" for refresh_view.
    Output: draws the tab. When a run finishes, refresh_view calls
    redraw_story, and the portal answers are read again (ioc_details), so
    they appear inside the chains without rebuilding them. A muted line
    says how many process trees had nothing flagged.
    Used by: report_page.
    """
    state = view["state"]
    view["chains"] = state["chains"]
    view["story_version"] = state["version"]
    box = ui.column().classes("w-full")

    def draw(limit):
        details = ioc_details(state)
        box.clear()
        with box:
            for number in range(1, min(limit, len(view["chains"]["chains"])) + 1):
                build_storyline(view, number, details)

    view["redraw_story"] = build_show_more(
        draw, lambda: len(view["chains"]["chains"]))
    if view["chains"]["other"]:
        ui.label("%d other process trees had nothing flagged."
                 % len(view["chains"]["other"])).classes("app-muted")
    if view["chains"]["events_without_guid"]:
        ui.label("%d events had no process ID and are not in any chain."
                 % view["chains"]["events_without_guid"]).classes("app-muted")
