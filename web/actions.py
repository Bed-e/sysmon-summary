"""Analyst actions: queue IOCs for lookup (one row or a whole chain) and
redraw the page as answers arrive (design.md section 7).

The tabs call these from their buttons. They reach the tabs only through the
redraw functions stored in the page's "view" dict, so there is no import
cycle between this module and web/tabs/.
"""

from nicegui import ui

from enrich import load_portal_urls
from web.enrich_jobs import (add_to_queue, chain_items, progress_text,
                             progress_value, start_worker)
from web.limits import load_limits
from web.rows import make_counts_rows


def enqueue(view, items, retry=False):
    """Queue IOCs for lookup and make sure the background thread runs.

    Input: view, the page's dict of live parts (see report_page); items,
    ranked IOC dicts picked on the server (lookup_one or enrich_chain);
    retry, True for a Retry press (replaces a failed answer).
    Output: nothing. Calls add_to_queue, then start_worker (which does
    nothing if the thread is already running: it picks up the new IOCs
    itself), switches the page timer on and redraws once. A short note says
    how many were added and how many were already queued or answered.
    Used by: lookup_one and enrich_chain.
    """
    state = view["state"]
    added = add_to_queue(state, items, retry)
    start_worker(state, load_portal_urls(), load_limits())
    left_out = len(items) - added
    if added == 0:
        ui.notify("Nothing new to look up: already queued, answered or never sent.")
    elif left_out:
        ui.notify("%d added to the queue, %d already queued, answered or never "
                  "sent." % (added, left_out))
    else:
        ui.notify("%d added to the queue." % added)
    view["timer"].activate()
    refresh_view(view)


def lookup_one(view, rank):
    """Handle a row's Look up / Retry button.

    Input: view; rank, the row's 1-based rank. The browser sends only this
    number; the IOC value comes from the server's own ranked list.
    Output: nothing. A rank outside the list is ignored, and a
    not-enrichable IOC is refused with a note. Otherwise that one IOC goes
    to enqueue, as a retry when its last answer was "not_enriched".
    Used by: lookup_handler (row buttons on the IOCs tab).
    """
    state = view["state"]
    ranked = state["ranked"]
    if not isinstance(rank, int) or rank < 1 or rank > len(ranked):
        return
    item = ranked[rank - 1]
    if item["not_enrichable"]:
        ui.notify("This IOC is never sent to a portal.")
        return
    retry = False
    for result in list(state["results"]):
        if (result["type"], result["value"]) == (item["type"], item["value"]):
            retry = result["status"] == "not_enriched"
    enqueue(view, [item], retry)


def enrich_chain(view, number):
    """Handle a chain card's "Enrich this chain" button.

    Input: view; number, the chain's 1-based position (the only thing the
    browser sends).
    Output: nothing. The IOCs touched by that chain's flagged processes
    (chain_items) go to enqueue; an unknown number is ignored.
    Used by: build_chain_card (the Chains tab).
    """
    items = chain_items(view["state"], number)
    if items:
        enqueue(view, items)


def refresh_view(view):
    """Update the page from the shared state. The timer calls this.

    Input: view (state and the live parts stored by the build_* functions).
    Output: nothing. Updates the progress bar and its text every tick
    (hidden while nothing has been queued), and the count tiles. Redraws
    the IOC rows only when an answer arrived (state["version"] changed) or
    the worker state changed. When the worker is no longer running it stops
    the timer and, if the answers changed, redraws the chains once so the
    portal answers appear inside them. The chains themselves are never
    rebuilt: they are worked out once at upload.
    Used by: report_page (timer) and enqueue.
    """
    state = view["state"]
    text = progress_text(state)
    view["progress"].set_value(progress_value(state))
    view["progress_text"].text = text
    view["progress_box"].set_visibility(bool(text))
    view["draw_counts"](make_counts_rows(state, list(state["results"])))
    seen = (state["version"], state["worker"])
    if view.get("seen") != seen:
        view["seen"] = seen
        view["redraw_ioc"]()
    if state["worker"] != "running":
        view["timer"].deactivate()
        if view["chains_version"] != state["version"]:
            view["chains_version"] = state["version"]
            view["redraw_chains"]()
