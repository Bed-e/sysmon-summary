"""The IOCs tab: the ranked IOC grid with a Look up button per row.
"""

from nicegui import ui

from web.actions import lookup_one
from web.config import IOC_GRID_COLUMNS, IOC_HEADERS
from web.rows import make_ioc_rows
from web.tabs.common import build_show_more, score_badge


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
        with ui.grid().classes("w-full items-center text-sm") \
                .style("gap: 0; grid-template-columns: %s" % IOC_GRID_COLUMNS):
            for title in IOC_HEADERS:
                ui.label(title).classes("ioc-head")
            for row in rows[:limit]:
                ui.label(str(row["rank"])).classes("ioc-cell")
                ui.label(row["type"]).classes("ioc-cell")
                ui.label(row["value"]).classes("ioc-cell break-all")
                with ui.element("div").classes("ioc-cell"):
                    score_badge(row["score"])
                with ui.label(row["why"]).classes("ioc-cell"):
                    ui.tooltip(row["full_why"]).classes("whitespace-pre-line text-sm")
                with ui.row().classes("ioc-cell items-center gap-2"):
                    ui.label(row["portal"])
                    if row["action"]:
                        ui.button(row["action"], on_click=lookup_handler(view, row["rank"])) \
                            .props("dense unelevated no-caps size=sm color=primary")


def build_ioc_tab(view):
    """Draw the IOCs tab: the ranked grid, 10 rows then "Show more".

    Input: view (stores "redraw_ioc" in it for refresh_view).
    Output: draws the tab. Used by: report_page.
    """
    state = view["state"]
    with ui.column().classes("app-card"):
        ui.label("Ranked IOCs").classes("app-title")
        ui.label("Hover over a \"why\" to see the full reasons.") \
            .classes("app-muted")
        container = ui.column().classes("w-full overflow-x-auto")

        def draw(limit):
            build_ioc_rows(container, view, limit)

        view["redraw_ioc"] = build_show_more(draw, lambda: len(state["ranked"]))
