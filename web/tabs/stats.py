"""The Stats tab: the counts kept out of the way (design.md section 8):
events kept and dropped, IOCs found and not enrichable, lookups done.
"""

from nicegui import ui

from web.rows import event_stats, ioc_stats, lookup_stats


def draw_count_tiles(box, rows):
    """Draw counts as a grid of tiles (a big number with a label).

    Input: box, the NiceGUI container that holds the tiles; rows, a list of
    {item, value} from event_stats, ioc_stats or lookup_stats
    (web/rows.py). An item such as "IOCs found (8 IPs, 33 DNS names, 97
    hashes)" is split at " (": the first part is the tile's title, the rest
    a small caption.
    Output: nothing. Clears the box and draws one tile per row, as labels
    only (text is never raw HTML).
    Used by: build_stats_tab (first draw) and refresh_view, through
    view["draw_stats"], on every timer tick while lookups are running.
    """
    box.clear()
    with box:
        for row in rows:
            title, _, caption = row["item"].partition(" (")
            with ui.column().classes("count-tile"):
                ui.label(row["value"]).classes("count-value")
                ui.label(title).classes("count-title")
                if caption:
                    ui.label("(" + caption).classes("app-muted")


def build_stats_tab(view):
    """Draw the Stats tab: Events, IOCs and Lookups cards of tiles.

    Input: view; reads view["state"] (parse counts, events, chains, iocs,
    ranked, results). Stores "draw_stats" for refresh_view, which redraws
    only the Lookups tiles (the other counts never change after upload).
    Output: draws the tab. Used by: report_page.
    """
    state = view["state"]
    for title, rows in (("Events", event_stats(state)), ("IOCs", ioc_stats(state))):
        with ui.column().classes("app-card w-full"):
            ui.label(title).classes("app-title")
            draw_count_tiles(ui.element("div").classes("count-grid"), rows)
    with ui.column().classes("app-card w-full"):
        ui.label("Lookups").classes("app-title")
        tiles = ui.element("div").classes("count-grid")
    view["draw_stats"] = lambda rows: draw_count_tiles(tiles, rows)
    draw_count_tiles(tiles, lookup_stats(state, list(state["results"])))
