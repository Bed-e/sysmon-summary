"""Helper shared by the tabs: a list that shows a few rows and a Show more button.
"""

from nicegui import ui

from web.config import SHOW_STEP


def build_show_more(draw, total_fn, step=SHOW_STEP):
    """Add a "Showing X of Y" label and a "Show more" button under content.

    Input: draw(limit), a function that (re)draws the first `limit` items of
    the content above; total_fn(), returns how many items exist; step, how
    many more each click reveals.
    Output: a redraw() function. Calling it redraws with the current limit
    and updates the label and button (used when the data changes). The
    button hides once everything is shown.
    Used by: build_ioc_tab, build_storylines_tab and build_skipped_tab.
    """
    box = {"limit": step}
    label = ui.label().classes("text-sm text-gray-600")

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
