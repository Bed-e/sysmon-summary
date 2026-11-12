"""Step 5 (M4): turn the finished data into one self-contained HTML string.

Plain string building. No JavaScript, no outside files, standard library
only. Every value that came from a dump (command lines, DNS names, paths)
is untrusted and is escaped exactly once, in escape_text, so a hostile
process name cannot inject markup into the report.

Flow: main.py (M4) and later web/app.py (M5) call build_report with the
outputs of read_events, collect_iocs, split_iocs, rank_iocs, enrich_ranked
and storylines.build_storylines. write_report saves the string.
"""

import html

NOT_A_VERDICT = ("Scores are policy numbers, not a verdict. Local scores order "
                 "the work; portal scores are shown beside them and are never "
                 "merged or averaged.")

OVER_CAP_PREFIX = "over the cap"
MAX_DEPTH = 50  # stops a malformed parent loop from recursing forever

STYLE = """
body { font-family: sans-serif; margin: 1.5em; line-height: 1.4; }
h1, h2 { margin-bottom: 0.3em; }
.note { border-left: 4px solid #b58900; background: #fdf6e3; padding: 0.5em 1em; }
table { border-collapse: collapse; }
td, th { border: 1px solid #ccc; padding: 2px 8px; text-align: left; vertical-align: top; }
details { margin-left: 1.2em; }
summary { cursor: pointer; }
code { background: #eee; padding: 0 3px; word-break: break-all; }
.fail { color: #b00020; }
.muted { color: #666; }
"""


def escape_text(value):
    """Make one value safe to put inside HTML.

    Input: any value (string, number or None) from the dump or the portals.
    Output: an escaped string; None becomes an empty string.
    Used by: every function in this file; the only escape point.
    """
    if value is None:
        return ""
    return html.escape(str(value))


def describe_portal(portal):
    """Return the portal answer for one IOC as escaped text.

    Input: portal, the common-shape dict from enrich.enrich_ranked, or the
    text "not requested" (set by storylines.attach_ioc_results).
    Output: HTML text: "portal 80 (bad)", with a partial flag when some
    sources failed; "NOT ENRICHED: reason" when there is no answer; or
    "not requested". A failed lookup is never shown as a low score.
    Used by: build_ioc_list.
    """
    if not isinstance(portal, dict):
        return '<span class="muted">%s</span>' % escape_text(portal)
    if portal["status"] == "not_enriched":
        reason = portal["reasons"][0] if portal["reasons"] else "no reason given"
        return '<span class="fail">NOT ENRICHED: %s</span>' % escape_text(reason)
    note = " [partial: some sources failed]" if portal["status"] == "partial" else ""
    return "portal %s (%s)%s" % (escape_text(portal["score_0_to_100"]),
                                 escape_text(portal["label"]), note)


def build_counts_section(stats, ranked, skipped, results, cap):
    """Build the block that says how many IOCs were found, skipped, etc.

    Input: stats {"ip": n, "dns": n, "hash": n} (unique IOCs found, from
    collect_iocs); ranked and skipped (scoring.rank_iocs, filters.split_iocs);
    results (enrich.enrich_ranked, or [] when enrichment was not run); cap,
    the lookup cap.
    Output: an HTML string. Looked up = enriched or partial. Failed = no
    answer. Over the cap = left alone because of the cap.
    Used by: build_report.
    """
    found = stats["ip"] + stats["dns"] + stats["hash"]
    rows = [
        ("IOCs found", "%d (IPs %d, DNS names %d, hashes %d)"
         % (found, stats["ip"], stats["dns"], stats["hash"])),
        ("Skipped by the filter (never sent anywhere)", len(skipped)),
        ("Ranked locally", len(ranked)),
    ]
    if results:
        looked_up = 0
        over_cap = 0
        failed = 0
        for result in results:
            if result["status"] != "not_enriched":
                looked_up += 1
            elif result["reasons"] and result["reasons"][0].startswith(OVER_CAP_PREFIX):
                over_cap += 1
            else:
                failed += 1
        rows.append(("Looked up on the portals", looked_up))
        rows.append(("Lookup failed (not enriched)", failed))
        rows.append(("Not looked up: over the cap of %d" % cap, over_cap))
    else:
        rows.append(("Portal lookups", "not requested"))

    lines = ["<h2>Counts</h2>", "<table>"]
    for label, value in rows:
        lines.append("<tr><th>%s</th><td>%s</td></tr>"
                     % (escape_text(label), escape_text(value)))
    lines.append("</table>")
    return "\n".join(lines)


def build_ioc_list(iocs):
    """Render the IOCs attached to one process as a list.

    Input: iocs, the "iocs" list of a process entry (built by
    storylines.attach_ioc_results): type, value, local_score, local_reasons
    and portal.
    Output: an HTML <ul>, or an empty string when the list is empty. The
    local score and the portal answer sit side by side, never merged.
    Used by: build_process_node.
    """
    if not iocs:
        return ""
    lines = ["<ul>"]
    for ioc in iocs:
        reasons = "; ".join(escape_text(r) for r in ioc["local_reasons"])
        lines.append("<li>%s <code>%s</code>: local score %s | %s"
                     % (escape_text(ioc["type"]), escape_text(ioc["value"]),
                        escape_text(ioc["local_score"]),
                        describe_portal(ioc["portal"])))
        if reasons:
            lines.append('<br><span class="muted">%s</span>' % reasons)
        lines.append("</li>")
    lines.append("</ul>")
    return "\n".join(lines)


def build_list_line(label, items):
    """Return '<div>label: <code>a</code>, <code>b</code></div>' or ''.

    Input: a label and a list of strings (IPs, names, paths, registry keys).
    Output: one escaped HTML line, or an empty string for an empty list.
    Used by: build_process_node.
    """
    if not items:
        return ""
    codes = ", ".join("<code>%s</code>" % escape_text(i) for i in items)
    return "<div>%s: %s</div>" % (escape_text(label), codes)


def build_process_node(table, guid, is_open=True, depth=0):
    """Render one process and, recursively, its children.

    Input: table from storylines.build_storylines; guid, the process;
    is_open, whether the block starts expanded; depth, the nesting so far.
    Output: a nested <details> block with image, command line, user, parent,
    IPs, DNS names, files, registry writes, IOCs, then the children.
    A root whose parent is not in the dump says so. Stops at MAX_DEPTH.
    Used by: build_storyline_section.
    """
    entry = table[guid]
    name = entry["image"] or "unknown process"
    lines = ["<details%s>" % (" open" if is_open else ""),
             "<summary><code>%s</code></summary>" % escape_text(name)]
    if entry["command_line"]:
        lines.append("<div>command line: <code>%s</code></div>"
                     % escape_text(entry["command_line"]))
    if entry["user"]:
        lines.append("<div>user: %s</div>" % escape_text(entry["user"]))
    if entry["parent_image"] and entry["parent_guid"] not in table:
        lines.append('<div class="muted">parent: <code>%s</code> '
                     "(orphan: parent started before the capture)</div>"
                     % escape_text(entry["parent_image"]))
    lines.append(build_list_line("IPs contacted", entry["ips"]))
    lines.append(build_list_line("DNS names queried", entry["dns"]))
    lines.append(build_list_line("files written", entry["files"]))
    lines.append(build_list_line("registry writes", entry["registry"]))
    lines.append(build_ioc_list(entry["iocs"]))
    if depth >= MAX_DEPTH and entry["children"]:
        lines.append('<div class="muted">(deeper children not shown)</div>')
    else:
        for child in entry["children"]:
            lines.append(build_process_node(table, child, True, depth + 1))
    lines.append("</details>")
    return "\n".join(line for line in lines if line != "")


def build_storyline_section(table, storyline, number):
    """Render one ranked storyline.

    Input: table; storyline, one dict from build_storylines()["storylines"];
    number, its 1-based rank.
    Output: a heading with rank, score and tree size, the reasons, and the
    process tree. A storyline with score 0 starts collapsed.
    Used by: build_report.
    """
    root = table[storyline["root"]]
    name = root["image"] or "unknown process"
    lines = ["<h3>#%d score %s: <code>%s</code> (%d processes)</h3>"
             % (number, escape_text(storyline["score"]), escape_text(name),
                storyline["size"])]
    if storyline["reasons"]:
        lines.append("<ul>")
        for reason in storyline["reasons"]:
            lines.append("<li>%s</li>" % escape_text(reason))
        lines.append("</ul>")
    lines.append(build_process_node(table, storyline["root"],
                                    storyline["score"] != 0))
    return "\n".join(lines)


def build_skipped_table(skipped):
    """Render the audit table of IOCs the filter skipped.

    Input: skipped from filters.split_iocs; each item has type, value,
    reason (a code) and record (with "count").
    Output: an HTML table sorted by reason, type, value; "none" when empty.
    Lets the analyst check the filter (design.md section 9, rule 4).
    Used by: build_report.
    """
    lines = ["<h2>Skipped IOCs (never sent to any portal)</h2>"]
    if not skipped:
        lines.append("<p>none</p>")
        return "\n".join(lines)
    lines.append("<table><tr><th>reason</th><th>type</th><th>value</th>"
                 "<th>sightings</th></tr>")
    for item in sorted(skipped, key=lambda s: (s["reason"], s["type"], s["value"])):
        lines.append("<tr><td>%s</td><td>%s</td><td><code>%s</code></td><td>%s</td></tr>"
                     % (escape_text(item["reason"]), escape_text(item["type"]),
                        escape_text(item["value"]),
                        escape_text(item["record"]["count"])))
    lines.append("</table>")
    return "\n".join(lines)


def build_report(path, iocs, skipped, ranked, results, cap, storylines):
    """Assemble the whole report page.

    Input: path, the .evtx file name; iocs from collect_iocs; skipped from
    split_iocs; ranked from rank_iocs; results from enrich_ranked ([] when
    not run); cap, the lookup cap; storylines, the dict from
    storylines.build_storylines.
    Output: one complete HTML document as a string: title, the fixed
    not-a-verdict note, the counts, the ranked storylines, the skipped table.
    Used by: main.py (M4) and web/app.py (M5).
    """
    stats = {"ip": len(iocs["ip"]), "dns": len(iocs["dns"]),
             "hash": len(iocs["hash"])}
    table = storylines["table"]
    parts = [
        "<!DOCTYPE html>",
        '<html lang="en"><head><meta charset="utf-8">',
        "<title>Sysmon summary: %s</title>" % escape_text(path),
        "<style>%s</style></head><body>" % STYLE,
        "<h1>Sysmon summary</h1>",
        "<p>File: <code>%s</code></p>" % escape_text(path),
        '<p class="note">%s</p>' % escape_text(NOT_A_VERDICT),
        build_counts_section(stats, ranked, skipped, results, cap),
        "<h2>Process storylines, highest score first</h2>",
    ]
    if not storylines["storylines"]:
        parts.append("<p>none</p>")
    for number, storyline in enumerate(storylines["storylines"], 1):
        parts.append(build_storyline_section(table, storyline, number))
    if storylines["events_without_guid"]:
        parts.append('<p class="muted">%d events had no process ID and are not in '
                     "any storyline.</p>" % storylines["events_without_guid"])
    parts.append(build_skipped_table(skipped))
    parts.append("</body></html>")
    return "\n".join(parts)


def write_report(html_text, out_path):
    """Save the report to disk as UTF-8.

    Input: html_text from build_report; out_path, where to write.
    Output: out_path, so the caller can tell the analyst where it went.
    Used by: main.py.
    """
    with open(out_path, "w", encoding="utf-8") as handle:
        handle.write(html_text)
    return out_path
