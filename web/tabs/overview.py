"""The Overview tab: counts, status and the Enrich next N controls.
"""

from nicegui import ui

from web.actions import ask_enrich
from web.config import NOT_A_VERDICT, N_CHOICES
from web.enrich_jobs import status_text
from web.rows import make_counts_rows


def draw_count_tiles(box, rows):
    """Draw the counts as a grid of tiles (a big number with a label).

    Input: box, the NiceGUI container that holds the tiles; rows, the list
    of {item, value} from make_counts_rows (web/rows.py). An item such as
    "IOCs found (8 IPs, 33 DNS names, 97 hashes)" is split at " (": the
    first part is the tile's title, the rest a small caption.
    Output: nothing. Clears the box and draws one tile per row, as labels
    only (text is never raw HTML).
    Used by: build_overview_tab (first draw) and refresh_view, through
    view["draw_counts"], on every timer tick while a run is going.
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


def build_overview_tab(view):
    """Draw the Overview tab: note, count tiles, and the enrich controls.

    Input: view, the page's dict of live parts (see report_page). This
    function stores "draw_counts", "status" and "button" in it for
    refresh_view.
    Output: draws the tab. The N dropdown and button call ask_enrich.
    Used by: report_page.
    """
    state = view["state"]
    ui.label(NOT_A_VERDICT).classes("app-notice")
    tiles = ui.element("div").classes("count-grid")
    view["draw_counts"] = lambda rows: draw_count_tiles(tiles, rows)
    draw_count_tiles(tiles, make_counts_rows(state, state["results"]))
    with ui.column().classes("app-card"):
        ui.label("Enrich on demand").classes("app-title")
        ui.label("Each press sends the next N highest-ranked IOCs that have "
                 "not been tried yet, one at a time. Single IOCs can be "
                 "looked up from the IOCs tab.").classes("app-muted")
        with ui.row().classes("items-center"):
            choice = ui.select(N_CHOICES, value="5", label="N").classes("w-32")
            view["button"] = ui.button(
                "Enrich next N",
                on_click=lambda: ask_enrich(view, choice.value))
        view["status"] = ui.label(status_text(state))
    view["button"].set_enabled(state["run"] != "running")
