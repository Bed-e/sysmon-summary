"""The Skipped tab: IOCs that were filtered out, with the reason.
"""

from nicegui import ui

from web.config import SKIPPED_COLUMNS
from web.rows import make_skipped_rows
from web.tabs.common import build_show_more


def build_skipped_tab(view):
    """Draw the Skipped tab: IOCs the filter never sent anywhere.

    Input: view; reads view["state"]["skipped"].
    Output: draws a card with a title, a muted explanation and the audit
    table with reason codes, 10 rows then "Show more". Used by: report_page.
    """
    rows = make_skipped_rows(view["state"]["skipped"])
    with ui.column().classes("app-card"):
        ui.label("Skipped IOCs").classes("app-title")
        ui.label("The filter never sent these to any portal.").classes("app-muted")
        table = ui.table(columns=SKIPPED_COLUMNS, row_key="value", rows=[])
        table.classes("w-full")

        def draw(limit):
            table.rows[:] = rows[:limit]
            table.update()

        build_show_more(draw, lambda: len(rows))
