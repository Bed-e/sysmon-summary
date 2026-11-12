"""Helpers shared by the tabs: Show more, the Look up button handler, score badges.
"""

from nicegui import ui

from web.actions import lookup_one
from web.config import SHOW_STEP
from web.timeline_data import score_level


def build_show_more(draw, total_fn, step=SHOW_STEP):
    """Add a "Showing X of Y" label and a "Show more" button under content.

    Input: draw(limit), a function that (re)draws the first `limit` items of
    the content above; total_fn(), returns how many items exist; step, how
    many more each click reveals.
    Output: a redraw() function. Calling it redraws with the current limit
    and updates the label and button (used when the data changes). The
    button hides once everything is shown.
    Used by: build_ioc_tab, build_chains_tab, build_other_activity and
    build_skipped_tab.
    """
    box = {"limit": step}
    label = ui.label().classes("app-muted")

    def redraw():
        total = total_fn()
        draw(box["limit"])
        label.text = "Showing %d of %d" % (min(box["limit"], total), total)
        more.set_visibility(box["limit"] < total)

    def click():
        box["limit"] += step
        redraw()

    more = ui.button("Show more", on_click=click)
    redraw()
    return redraw


def lookup_handler(view, rank):
    """Return a no-argument click handler that looks up one IOC.

    Input: view; rank, the IOC's 1-based rank in state["ranked"] (a number
    the server made, from make_ioc_rows or ioc_details).
    Output: a function for a button's on_click that calls
    web.actions.lookup_one. A separate function is used so each button
    keeps its own rank.
    Used by: build_ioc_rows (IOCs tab) and build_ioc_line (Chains tab).
    """
    def click():
        lookup_one(view, rank)
    return click


def score_badge(score):
    """Draw a small coloured pill holding a score number.

    Input: score, an int local score (from a ranked IOC, a process or a chain).
    Output: the drawn label. Its colour comes from score_level, the same
    grouping the timeline bars use: grey (0), orange (1 to 39), red (40+),
    through the app-badge-<level> classes in web/theme.py. Text only, so
    nothing from a dump is ever raw HTML.
    Used by: build_ioc_rows and the Chains tab.
    """
    return ui.label(str(score)).classes(
        "app-badge app-badge-" + score_level(score))
