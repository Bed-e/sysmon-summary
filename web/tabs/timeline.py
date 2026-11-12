"""The Timeline tab: the slice selector and the per-process timeline chart.
"""

from nicegui import ui

from web.config import ROWS_VISIBLE, ROW_HEIGHT, SUSPICIOUS_COLUMNS
from web.timeline_chart import make_process_timeline
from web.timeline_data import (make_suspicious_rows, order_rows,
    process_spans, slice_choices, slice_guids)


def draw_process_timeline(view, box, note, choice):
    """Redraw the timeline chart for one slice.

    Input: view; box, the column that holds the chart; note, a label for the
    row count; choice, the dropdown value.
    Output: nothing. Clears the box and draws a new ui.echart from
    make_process_timeline for the chosen processes, with its height set from
    the row count (up to ROWS_VISIBLE rows), and updates the note. A new
    chart is made each time because an existing chart keeps drawing at its
    old size when only its height changes.
    Used by: build_timeline_tab (first draw and dropdown changes).
    """
    table = view["stories"]["table"]
    rows = order_rows(table, slice_guids(view, choice))
    option = make_process_timeline(table, rows, view["spans"],
                                   view["state"]["events"], view["process_scores"])
    visible = max(min(len(rows), ROWS_VISIBLE), 3)
    box.clear()
    with box:
        height = visible * ROW_HEIGHT + 130
        ui.echart(option).classes("w-full").style("height: %dpx" % height)
    note.text = "%d processes shown." % len(rows)


def build_timeline_tab(view):
    """Draw the Timeline tab: a per-process timeline, then a table of
    flagged processes in the order they first appeared.

    Input: view; reads view["state"]["events"], view["stories"] (built by
    build_storylines_tab, which is drawn first) and view["process_scores"].
    Stores view["spans"].
    Output: draws a "Show" dropdown (flagged processes and their parents,
    one storyline, or all), the chart and the table. Uses ui.echart, which
    ships with NiceGUI (no new library). Used by: report_page.
    """
    events = view["state"]["events"]
    view["spans"] = process_spans(events)
    ui.label("One row per process, in tree order (children under their "
             "parent). The bar runs from a process's first to its last event "
             "and is coloured by its local score; dots are its events; dashed "
             "lines link a parent to each child it started. Hover for details, "
             "click a legend entry to hide a group, drag the sliders to zoom. "
             "Times are UTC.").classes("text-sm text-gray-600")
    with ui.row().classes("items-center"):
        choice = ui.select(slice_choices(view["stories"]), value="flagged",
                           label="Show").classes("w-96")
        note = ui.label().classes("text-sm text-gray-600")
    box = ui.column().classes("w-full")
    choice.on_value_change(lambda event: draw_process_timeline(view, box, note, event.value))
    draw_process_timeline(view, box, note, "flagged")

    rows = make_suspicious_rows(events, view["process_scores"])
    ui.label("Flagged processes, in order of first appearance") \
        .classes("text-xl font-bold mt-4")
    if not rows:
        ui.label("none")
        return
    ui.table(columns=SUSPICIOUS_COLUMNS, rows=rows, row_key="guid") \
        .classes("w-full").props("dense flat bordered")
