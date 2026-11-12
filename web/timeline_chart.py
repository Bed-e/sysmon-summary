"""Timeline chart: builds the ECharts option dict for the process timeline.
"""

from scoring import file_name
from web.config import EVENT_TYPE_COLORS, LABEL_WIDTH, ROWS_VISIBLE, SCORE_BARS
from web.timeline_data import (event_detail, event_lane, row_label,
    score_level, time_in_ms)


def make_process_timeline(table, rows, spans, events, process_scores):
    """Build the ECharts settings for the per-process timeline.

    Input: table; rows from order_rows; spans from process_spans; events
    from parse.read_events; process_scores.
    Output: a plain settings dict:
    - one y-axis row per process, top to bottom in tree order;
    - a thick bar per process from its first to its last event, coloured by
      its local score (grey 0, orange 1-39, red 40+), as three "lines"
      series so the legend can hide each group;
    - a dashed vertical connector at each child's first event, from the
      parent's row to the child's row;
    - a dot per event on its process's row, one series per event type;
    - hover text through ECharts' "{b}" placeholder (the item's name);
    - a time zoom slider, and a row scroll slider when there are more than
      ROWS_VISIBLE rows;
    - process names left-aligned in a LABEL_WIDTH column so the tree
      indentation shows (long names are cut with "...").
    Rows are placed by number, so two processes with the same name stay
    apart. Used by: draw_process_timeline.
    """
    index = {}
    labels = []
    for position, (guid, depth) in enumerate(rows):
        index[guid] = position
        labels.append(row_label(table, guid, depth, process_scores))

    bars = {"normal": [], "flagged": [], "high": []}
    links = []
    for guid, position in index.items():
        span = spans.get(guid)
        if span is None:
            continue
        process = process_scores.get(guid)
        score = process["score"] if process is not None else 0
        name = file_name(table[guid]["image"]) or "unknown process"
        text = "%s  %s to %s" % (name, span["first_text"], span["last_text"])
        if score > 0:
            text += "  (score %d)" % score
        bars[score_level(score)].append(
            {"coords": [[span["first"], position], [span["last"], position]],
             "name": text})
        parent = table[guid]["parent_guid"]
        if parent in index:
            parent_name = file_name(table[parent]["image"]) or "unknown process"
            links.append({"coords": [[span["first"], index[parent]],
                                     [span["first"], position]],
                          "name": "%s %s started %s" % (span["first_text"],
                                                        parent_name, name)})

    dots = {}
    for lane, color in EVENT_TYPE_COLORS:
        dots[lane] = []
    for event in events:
        position = index.get(event.get("ProcessGuid", ""))
        moment = time_in_ms(event.get("time", ""))
        if position is None or moment is None:
            continue
        lane = event_lane(event)
        if lane in dots:
            dots[lane].append({"value": [moment, position],
                               "name": "%s  %s" % (event["time"][11:19],
                                                   event_detail(event))})

    series = []
    for level, label, color in SCORE_BARS:
        series.append({"name": label, "type": "lines",
                       "coordinateSystem": "cartesian2d", "z": 1,
                       "lineStyle": {"color": color, "width": 9, "opacity": 0.7,
                                     "cap": "round"},
                       "data": bars[level]})
    series.append({"name": "Parent → child", "type": "lines",
                   "coordinateSystem": "cartesian2d", "z": 2,
                   "lineStyle": {"color": "#555555", "width": 1.5, "type": "dashed"},
                   "data": links})
    for lane, color in EVENT_TYPE_COLORS:
        series.append({"name": lane, "type": "scatter", "symbolSize": 7, "z": 3,
                       "itemStyle": {"color": color}, "data": dots[lane]})

    zoom = [{"type": "slider", "xAxisIndex": 0, "bottom": 10},
            {"type": "inside", "xAxisIndex": 0}]
    if len(rows) > ROWS_VISIBLE:
        zoom.append({"type": "slider", "yAxisIndex": 0, "right": 5, "width": 14,
                     "startValue": 0, "endValue": ROWS_VISIBLE - 1})
    return {
        "useUTC": True,
        "animation": False,
        "tooltip": {"trigger": "item", "formatter": "{b}"},
        "legend": {"top": 0, "type": "scroll"},
        "grid": {"left": LABEL_WIDTH, "right": 40, "top": 40, "bottom": 60},
        "xAxis": {"type": "time"},
        "yAxis": {"type": "category", "data": labels, "inverse": True,
                  "axisLabel": {"interval": 0, "fontSize": 11, "align": "left",
                                "margin": LABEL_WIDTH - 10, "width": LABEL_WIDTH - 20,
                                "overflow": "truncate"}},
        "dataZoom": zoom,
        "series": series,
    }
