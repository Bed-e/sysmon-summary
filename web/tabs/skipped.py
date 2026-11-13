"""The Skipped tab: IOCs that are never sent to a portal, with the reason.
(R3 removes this tab; the IOCs table shows the same reason per row.)
"""

from nicegui import ui

from web.config import SKIPPED_COLUMNS
from web.rows import make_skipped_rows
from web.tabs.common import build_show_more


def build_skipped_tab(view):
    """Draw the Skipped tab: IOCs that are never sent anywhere.

    Input: view; reads view["state"]["ranked"] (items with a not_enrichable
    tag).
    Output: draws a card with a title, a muted explanation and the audit
    table with the reasons, 10 rows then "Show more". Used by: report_page.
    """
    rows = make_skipped_rows(view["state"]["ranked"])
    with ui.column().classes("app-card"):
        ui.label("Not enrichable IOCs").classes("app-title")
        ui.label("These stay in the chains and the IOCs table, but are never "
                 "sent to any portal.").classes("app-muted")
        table = ui.table(columns=SKIPPED_COLUMNS, row_key="value", rows=[])
        table.classes("w-full")

        def draw(limit):
            table.rows[:] = rows[:limit]
            table.update()

        build_show_more(draw, lambda: len(rows))
