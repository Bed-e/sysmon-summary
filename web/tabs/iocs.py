"""The IOCs tab: the ranked IOC grid with a Look up button per row.
"""

from nicegui import ui

from web.config import IOC_GRID_COLUMNS, IOC_HEADERS
from web.rows import make_ioc_rows
from web.tabs.common import build_show_more, lookup_handler, score_badge


def build_ioc_rows(container, view, limit):
    """Draw the first `limit` rows of the IOC table as a plain grid.

    Input: container, the column that holds the grid (cleared first); view
    (reads state, including state["chains"]["table"] for process names);
    limit, from build_show_more.
    Output: draws a header row and one row per IOC: rank, type, value, local
    score, the "why" as one line per process (full reasons on hover), the
    processes that touched it (every name and count on hover), the portal
    answer and, when there is no answer yet or it failed, a Look up / Retry
    button. A not-enrichable IOC shows its reason, muted, instead of a
    button.
    Used by: build_ioc_tab (through build_show_more) and refresh_view.
    """
    state = view["state"]
    rows = make_ioc_rows(state["ranked"], list(state["results"]),
                         state["chains"]["table"])
    container.clear()
    with container:
        with ui.grid().classes("w-full items-stretch text-sm") \
                .style("gap: 0; grid-template-columns: %s" % IOC_GRID_COLUMNS):
            for title in IOC_HEADERS:
                ui.label(title).classes("ioc-head")
            for row in rows[:limit]:
                ui.label(str(row["rank"])).classes("ioc-cell")
                ui.label(row["type"]).classes("ioc-cell")
                ui.label(row["value"]).classes("ioc-cell break-all")
                with ui.element("div").classes("ioc-cell ioc-row-cell"):
                    score_badge(row["score"])
                with ui.column().classes("ioc-cell gap-0"):
                    for line in row["why"] or ["nothing flagged"]:
                        ui.label(line)
                    ui.tooltip(row["full_why"] or "no reasons") \
                        .classes("whitespace-pre-line text-sm")
                with ui.label(row["seen_in"]).classes("ioc-cell break-words"):
                    ui.tooltip(row["seen_in_full"]).classes("whitespace-pre-line text-sm")
                with ui.row().classes("ioc-cell ioc-row-cell gap-2"):
                    portal = ui.label(row["portal"])
                    if row["not_enrichable"]:
                        portal.classes("app-muted")
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
        ui.label("Each line of a \"why\" is one process. Hover for the full "
                 "reasons or every process.").classes("app-muted")
        container = ui.column().classes("w-full overflow-x-auto")

        def draw(limit):
            build_ioc_rows(container, view, limit)

        view["redraw_ioc"] = build_show_more(draw, lambda: len(state["ranked"]))
