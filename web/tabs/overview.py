"""The Overview tab: counts, status and the Enrich next N controls.
"""

from nicegui import ui

from web.actions import ask_enrich
from web.config import COUNT_COLUMNS, NOT_A_VERDICT, N_CHOICES
from web.enrich_jobs import status_text
from web.rows import make_counts_rows


def build_overview_tab(view):
    """Draw the Overview tab: note, counts, and the enrich controls.

    Input: view, the page's dict of live parts (see report_page). This
    function stores "counts", "status" and "button" in it for refresh_view.
    Output: draws the tab. The N dropdown and button call ask_enrich.
    Used by: report_page.
    """
    state = view["state"]
    ui.label(NOT_A_VERDICT).classes("p-2 bg-yellow-100")
    view["counts"] = ui.table(columns=COUNT_COLUMNS, row_key="item",
                              rows=make_counts_rows(state, state["results"]))
    view["counts"].props("hide-header dense flat bordered")
    ui.label("Enrich on demand").classes("text-xl font-bold")
    ui.label("Each press sends the next N highest-ranked IOCs that have not "
             "been tried yet, one at a time. Single IOCs can be looked up "
             "from the IOCs tab.")
    with ui.row().classes("items-center"):
        choice = ui.select(N_CHOICES, value="5", label="N").classes("w-32")
        view["button"] = ui.button(
            "Enrich next N", on_click=lambda: ask_enrich(view, choice.value))
    view["status"] = ui.label(status_text(state))
    view["button"].set_enabled(state["run"] != "running")
