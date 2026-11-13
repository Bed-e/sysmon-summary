"""The Overview tab: the soft verdict and its reason, then the top chains
(design.md section 8). The counts are on the Stats tab.
"""

from nicegui import ui

from web.actions import show_chain
from web.config import TOP_CHAINS
from web.chain_summary import (chain_title, ioc_details,
    summarize_chain, summary_caption)
from web.tabs.common import score_badge
from web.verdict import make_verdict


def show_chain_handler(view, number):
    """Return a no-argument click handler for one Show in Chains button.
    A separate function so each button keeps its own number.
    Used by: draw_top_chains."""
    def click():
        show_chain(view, number)
    return click


def draw_top_chains(view, box):
    """Draw the top chains under the verdict.

    Input: view (reads "state": chains, process_scores, ranked, results);
    box, the column that holds the list (cleared first).
    Output: one line per chain for the first TOP_CHAINS chains: score
    badge, "#n · title" (chain_title), the one-line summary_caption (with
    the current portal hit count) and a Show in Chains button. When there
    are no chains, a muted line says so.
    Used by: build_overview_tab, on the first draw and through
    view["redraw_overview"] when portal answers change.
    """
    state = view["state"]
    chains = state["chains"]
    details = ioc_details(state)
    box.clear()
    with box:
        ui.label("Top chains").classes("app-title")
        if not chains["chains"]:
            ui.label("No process tree had anything flagged.").classes("app-muted")
            return
        for number, chain in enumerate(chains["chains"][:TOP_CHAINS], 1):
            summary = summarize_chain(chains["table"], chain,
                                      state["process_scores"], details)
            # The row may wrap: on a narrow screen the button drops under the
            # text instead of squeezing the text and itself into a thin column.
            with ui.row().classes("items-center gap-3 w-full"):
                score_badge(chain["score"])
                with ui.column().classes("gap-0 grow basis-0 min-w-[12rem]"):
                    ui.label("#%d  ·  %s" % (number, chain_title(
                        chains["table"], chain["title_finding"], chain["title_more"]))).classes("font-bold")
                    ui.label(summary_caption(summary)).classes("app-muted")
                ui.button("Show in Chains", on_click=show_chain_handler(view, number)) \
                    .classes("whitespace-nowrap") \
                    .props("dense flat no-caps color=primary")


def build_overview_tab(view):
    """Draw the Overview tab: the verdict card, then the top chains.

    Input: view, the page's dict of live parts (see report_page); reads
    view["state"]["chains"]. Stores "redraw_overview" for refresh_view.
    Output: draws a card with the soft verdict (make_verdict: a coloured
    label in the score-badge colours and its one-line reason) and a muted
    note that portal answers never change it, then the top chains
    (draw_top_chains).
    Used by: report_page.
    """
    verdict = make_verdict(view["state"]["chains"])
    with ui.column().classes("app-card gap-2"):
        ui.label(verdict["label"]).classes(
            "app-badge app-badge-%s verdict-label" % verdict["level"])
        ui.label(verdict["reason"])
        ui.label("Local evidence only. Portal answers are shown but never "
                 "change this.").classes("app-muted")
    box = ui.column().classes("app-card w-full gap-3")
    view["redraw_overview"] = lambda: draw_top_chains(view, box)
    draw_top_chains(view, box)
