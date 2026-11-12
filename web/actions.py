"""Analyst actions: start an enrichment run, confirm it when it would go over
the hash limits, look up one IOC, and redraw the page as answers arrive.

The tabs call these from their buttons. They reach the tabs only through the
redraw functions stored in the page's "view" dict, so there is no import
cycle between this module and web/tabs/.
"""

from nicegui import ui

from enrich import load_portal_urls
from storylines import build_storylines
from web.enrich_jobs import next_items, start_enrichment, status_text
from web.limits import load_limits, needs_warning, read_daily_count
from web.rows import choose_n, make_counts_rows


def begin_enrichment(view, items, limits):
    """Start the background run and the page timer.

    Input: view; items, the ranked dicts to look up; limits from
    load_limits.
    Output: nothing. Calls start_enrichment (one run at a time); when it
    starts, the timer is switched on so the page fills in.
    Used by: confirm_and_start.
    """
    started = start_enrichment(view["state"], items, load_portal_urls(), limits)
    if started:
        view["timer"].activate()
        refresh_view(view)
    else:
        ui.notify("A run is already in progress.")


def confirm_and_start(view, items):
    """Start a run for these items, asking first if the hash limits would
    be broken.

    Input: view; items, the ranked dicts to look up.
    Output: nothing. If needs_warning returns lines, a dialog shows them with
    "Send anyway" and "Cancel"; otherwise the run starts at once.
    Used by: ask_enrich (next N) and lookup_one (a single row).
    """
    if view["state"]["run"] == "running":
        ui.notify("A run is already in progress.")
        return
    limits = load_limits()
    lines = needs_warning(items, limits, read_daily_count())
    if not lines:
        begin_enrichment(view, items, limits)
        return

    def send_anyway():
        dialog.close()
        begin_enrichment(view, items, limits)

    with ui.dialog() as dialog, ui.card():
        ui.label("Check before sending").classes("text-xl font-bold")
        for line in lines:
            ui.label(line)
        with ui.row():
            ui.button("Send anyway", on_click=send_anyway)
            ui.button("Cancel", on_click=dialog.close)
    dialog.open()


def ask_enrich(view, text):
    """Handle the "Enrich next N" button.

    Input: view; text, the dropdown value (the only thing the browser sends).
    Output: nothing. A value not in N_CHOICES is refused. Otherwise the next
    N untried IOCs (next_items) go to confirm_and_start.
    Used by: build_overview_tab (button click).
    """
    state = view["state"]
    n = choose_n(text, state["ranked"])
    if n is None:
        ui.notify("Pick N from the list.")
        return
    items = next_items(state, n)
    if not items:
        ui.notify("Every ranked IOC has been tried. Use Retry on the IOCs tab.")
        return
    confirm_and_start(view, items)


def lookup_one(view, rank):
    """Handle a row's Look up / Retry button.

    Input: view; rank, the row's 1-based rank. The browser sends only this
    number; the IOC value comes from the server's own ranked list.
    Output: nothing. A rank outside the list is ignored. Otherwise that one
    IOC goes to confirm_and_start.
    Used by: lookup_handler (row buttons).
    """
    ranked = view["state"]["ranked"]
    if not isinstance(rank, int) or rank < 1 or rank > len(ranked):
        return
    confirm_and_start(view, [ranked[rank - 1]])


def refresh_view(view):
    """Update the page from the shared state. The timer calls this.

    Input: view (state and the live parts stored by the build_* functions).
    Output: nothing. Updates the status line, the counts and the Enrich
    button every tick, and redraws the IOC rows only when an answer arrived
    (state["version"] changed) or the run state changed. When the run is no
    longer "running" it stops the timer and, if the answers changed, rebuilds
    the storylines once so the portal answers appear inside them.
    Used by: report_page (timer) and begin_enrichment.
    """
    state = view["state"]
    results = list(state["results"])
    view["status"].text = status_text(state)
    view["button"].set_enabled(state["run"] != "running")
    view["counts"].rows[:] = make_counts_rows(state, results)
    view["counts"].update()
    seen = (state["version"], state["run"])
    if view.get("seen") != seen:
        view["seen"] = seen
        view["redraw_ioc"]()
    if state["run"] != "running":
        view["timer"].deactivate()
        if view["story_version"] != state["version"]:
            view["stories"] = build_storylines(state["events"], state["ranked"],
                                               results)
            view["story_version"] = state["version"]
            view["redraw_story"]()
