"""The Chains tab: one card per attack chain, the most suspicious first, then a
collapsed list of the process trees where nothing was flagged (design.md
section 5).

The chains are built once at upload (chains.build_chains). This tab only
draws them; portal answers are looked up by (type, value) on every draw, so
enrichment never rebuilds a chain.
"""

from nicegui import ui

from scoring.paths import file_name
from chains import walk_tree
from web.actions import enrich_chain
from web.enrich_jobs import chain_items
from web.reasons import portal_text, short_reason
from web.chain_summary import (chain_title, ioc_details,
    summarize_chain, summary_caption)
from web.tabs.common import build_show_more, lookup_handler, score_badge
from web.timeline_data import order_rows

INDENT_REM = 1.25  # left margin per tree level, in rem


def indent_style(depth):
    """Return the CSS that pushes a tree row right by its depth.
    Used by build_flagged_node and build_plain_line."""
    return "margin-left: %.2frem" % (depth * INDENT_REM)


def build_ioc_line(view, key, detail):
    """Draw one IOC a flagged process touched.

    Input: view (for the button); key, (type, value) from the process
    entry's "iocs" list (chains.attach_iocs); detail, that IOC's entry
    from chain_summary.ioc_details (rank, score, portal, action).
    Output: one row: type and value, the local score badge, the portal
    answer as text, and a Look up / Retry button when detail["action"] is
    set. For a not-enrichable IOC the portal text is the reason it is never
    sent, and there is no button. The button sends only the IOC's rank.
    Used by: build_flagged_node.
    """
    with ui.row().classes("items-center gap-2 no-wrap text-sm"):
        ui.label("%s %s" % key).classes("break-all")
        score_badge(detail["score"])
        ui.label(portal_text(detail["portal"])).classes("app-muted")
        if detail["action"]:
            ui.button(detail["action"], on_click=lookup_handler(view, detail["rank"])) \
                .props("dense unelevated no-caps size=sm color=primary")


def build_flagged_node(view, table, guid, depth, details):
    """Draw a flagged process in full, at its place in the tree.

    Input: view (reads "process_scores"); table from build_chains; guid, a
    process in the chain's "flagged" list; depth, from order_rows; details
    from ioc_details.
    Output: a bordered block holding the process name and score badge,
    each finding (points and short text, full text on hover, the IOC it is
    about when it has one), command line, user, the note for a parent that
    started before the capture, "file written by X at hh:mm:ss", activity
    counts, then one build_ioc_line per IOC it touched.
    Used by: build_chain_tree.
    """
    entry = table[guid]
    process = view["process_scores"].get(guid, {"score": 0, "findings": []})
    with ui.column().classes("chain-node w-full").style(indent_style(depth)):
        with ui.row().classes("items-center gap-2"):
            ui.label(("└ " if depth else "") + (file_name(entry["image"])
                     or "unknown process")).classes("font-bold")
            score_badge(process["score"])
            if entry["time"]:
                ui.label(entry["time"][11:19]).classes("app-muted")
        for finding in process["findings"]:
            text = "+%d %s" % (finding["points"], short_reason(finding["reason"]))
            if finding["subject"] is not None and finding["subject"][0] != "hash":
                text += " → " + finding["subject"][1]
            with ui.label(text):
                ui.tooltip(finding["reason"]).classes("text-sm")
        if entry["command_line"]:
            ui.label("command line: " + entry["command_line"]).classes("process-cmd")
        if entry["user"]:
            ui.label("user: " + entry["user"]).classes("app-muted")
        if entry["parent_image"] not in ("", "-") and entry["parent_guid"] not in table:
            ui.label("parent: %s (started before the capture)"
                     % entry["parent_image"]).classes("app-muted")
        if entry["dropped_by"]:
            dropper = entry["dropped_by"]
            ui.label("file written by %s at %s" % (
                file_name(dropper["image"]) or "unknown process",
                dropper["time"][11:19])).classes("app-section")
        counts = []
        for label, items in (("IPs", entry["ips"]), ("DNS names", entry["dns"]),
                             ("files written", entry["files"]),
                             ("registry writes", entry["registry"])):
            if items:
                counts.append("%d %s" % (len(items), label))
        if counts:
            ui.label(" · ".join(counts)).classes("app-muted")
        for key in entry["iocs"]:
            if key in details:
                build_ioc_line(view, key, details[key])


def build_plain_line(table, guid, depth):
    """Draw an unflagged process as one muted line, with no detail.

    Input: table from build_chains; guid, a process in the chain that is
    not flagged; depth, from order_rows.
    Output: a label such as "└ explorer.exe 10:02:11", indented by depth,
    so the whole flow of the tree stays visible around the flagged parts.
    Used by: build_chain_tree.
    """
    entry = table[guid]
    text = ("└ " if depth else "") + (file_name(entry["image"]) or "unknown process")
    if entry["time"]:
        text += "  " + entry["time"][11:19]
    ui.label(text).classes("chain-plain").style(indent_style(depth))


def build_chain_tree(view, chain, details):
    """Draw a chain's whole process tree, flagged processes in full.

    Input: view (reads "chains"); chain, one entry of chains["chains"];
    details from ioc_details.
    Output: one row per process in tree order (timeline_data.order_rows
    gives the order and the depth), drawn by build_flagged_node for the
    chain's "flagged" processes and build_plain_line for the rest.
    Used by: build_chain_card.
    """
    table = view["chains"]["table"]
    flagged = set(chain["flagged"])
    with ui.column().classes("w-full gap-1"):
        for guid, depth in order_rows(table, chain["guids"]):
            if guid in flagged:
                build_flagged_node(view, table, guid, depth, details)
            else:
                build_plain_line(table, guid, depth)


def remember_open(view, number, is_open):
    """Record whether chain card `number` is open, so a redraw keeps it so.
    Input: view; number, the card's 1-based rank; is_open, the expansion's
    new value. Used by: build_chain_card (on_value_change)."""
    if is_open:
        view["open_chains"].add(number)
    else:
        view["open_chains"].discard(number)


def build_chain_card(view, number, details):
    """Draw one chain as a card: a summary header, the rest inside.

    Input: view (reads "chains", "process_scores", "open_chains"); number,
    the chain's 1-based rank; details from ioc_details.
    Output: an expansion whose header holds the chain's score badge, its
    title (chain_title: the strongest finding, not the root) and the
    one-line summary_caption. Opened, it shows the portal hits, the
    "Enrich this chain (k IOCs)" button (k = IOCs of the flagged processes,
    from chain_items, that are enrichable and not asked about yet; failed
    ones are left to their own Retry button; disabled when k is 0), and the process
    tree. The card is drawn open when its number is in view["open_chains"],
    so a redraw after lookups does not close it.
    Used by: build_chains_tab.
    """
    chains = view["chains"]
    chain = chains["chains"][number - 1]
    table = chains["table"]
    summary = summarize_chain(table, chain, view["process_scores"], details)
    title = "#%d  ·  %s" % (number, chain_title(table, chain["title_finding"]))
    sendable = [item for item in chain_items(view["state"], number)
                if details[(item["type"], item["value"])]["action"] == "Look up"]
    box = ui.expansion(value=(number in view["open_chains"]),
                       on_value_change=lambda event: remember_open(view, number, event.value))
    with box.classes("w-full app-card chain-card"):
        with box.add_slot("header"):
            with ui.row().classes("items-center gap-3 no-wrap"):
                score_badge(chain["score"])
                with ui.column().classes("gap-0"):
                    ui.label(title).classes("app-title")
                    ui.label(summary_caption(summary)).classes("app-muted")
        if summary["portal_hits"]:
            ui.label("Portal hits").classes("app-section")
            for hit in summary["portal_hits"]:
                ui.label(hit)
        with ui.row().classes("items-center gap-2"):
            button = ui.button("Enrich this chain (%d IOCs)" % len(sendable),
                               on_click=lambda: enrich_chain(view, number)) \
                .props("unelevated no-caps color=primary")
            if not sendable:
                button.set_enabled(False)
                ui.label("nothing to send").classes("app-muted")
        ui.label("Process tree").classes("app-section")
        build_chain_tree(view, chain, details)


def build_other_activity(view):
    """Draw the collapsed list of process trees with nothing flagged.

    Input: view (reads chains["other"], the root guids in start order, and
    chains["table"]).
    Output: an expansion "Other activity (n process trees, nothing
    flagged)", closed at first. Inside, one plain line per tree: root name,
    start time and process count (chains.walk_tree), 10 at a time
    with Show more. Nothing is
    drawn when the list is empty.
    Used by: build_chains_tab.
    """
    chains = view["chains"]
    other = chains["other"]
    if not other:
        return
    table = chains["table"]
    with ui.expansion("Other activity (%d process trees, nothing flagged)"
                      % len(other)).classes("w-full app-card"):
        box = ui.column().classes("w-full gap-1")

        def draw(limit):
            box.clear()
            with box:
                for root in other[:limit]:
                    size = len(walk_tree(table, root))
                    text = file_name(table[root]["image"]) or "unknown process"
                    if table[root]["time"]:
                        text += "  " + table[root]["time"][11:19]
                    text += "  (%d %s)" % (size, "process" if size == 1 else "processes")
                    ui.label(text).classes("chain-plain")

        build_show_more(draw, lambda: len(other))


def build_chains_tab(view):
    """Draw the Chains tab: ranked chain cards, 10 then "Show more", then
    Other activity and the note about events with no process ID.

    Input: view; reads view["state"]["chains"] (built once at upload) and
    keeps it in view["chains"] (the Timeline tab reads it too). Stores
    "redraw_chains", "chains_version" and "open_chains" for refresh_view.
    Output: draws the tab. When the worker stops, refresh_view calls
    redraw_chains and the portal answers are read again (ioc_details), so
    they appear inside the chains without rebuilding them.
    Used by: report_page.
    """
    state = view["state"]
    view["chains"] = state["chains"]
    view["chains_version"] = state["version"]
    view["open_chains"] = set()
    chains = view["chains"]["chains"]
    if not chains:
        ui.label("No process tree had anything flagged.").classes("app-muted")
    box = ui.column().classes("w-full")

    def draw(limit):
        details = ioc_details(state)
        box.clear()
        with box:
            for number in range(1, min(limit, len(chains)) + 1):
                build_chain_card(view, number, details)

    view["redraw_chains"] = build_show_more(draw, lambda: len(chains))
    build_other_activity(view)
    if view["chains"]["events_without_guid"]:
        ui.label("%d events had no process ID and are not in any chain."
                 % view["chains"]["events_without_guid"]).classes("app-muted")
