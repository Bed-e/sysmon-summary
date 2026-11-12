"""The Overview tab: the note and the count tiles.
(R3 step 4 adds the soft verdict and the top chains, and moves the counts
to the Stats tab.)
"""

from nicegui import ui

from web.config import NOT_A_VERDICT
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
    view["draw_counts"], on every timer tick while lookups are running.
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
    """Draw the Overview tab: the note and the count tiles.

    Input: view, the page's dict of live parts (see report_page). This
    function stores "draw_counts" in it for refresh_view.
    Output: draws the tab. Lookups are started from the IOCs tab (and, from
    R3 step 2, from each chain); the progress bar sits above the tabs.
    Used by: report_page.
    """
    state = view["state"]
    ui.label(NOT_A_VERDICT).classes("app-notice")
    tiles = ui.element("div").classes("count-grid")
    view["draw_counts"] = lambda rows: draw_count_tiles(tiles, rows)
    draw_count_tiles(tiles, make_counts_rows(state, state["results"]))
