"""Row builders: turn ranked IOCs, skipped IOCs and results into the plain dicts
the tables show, plus the small text helpers those tables use.
"""

from scoring.paths import file_name
from web.config import NOT_ENRICHABLE_TEXT, SEEN_IN_NAMES
from web.reasons import portal_text, why_lines


def make_ioc_rows(ranked, results, table):
    """Build the rows of the ranked IOC table.

    Input: ranked (scoring.rank_iocs, in rank order); results, the portal
    answers so far (state["results"], copied by the caller); table, the
    process table from storylines.build_chains (state["chains"]["table"]).
    Output: a list of dicts {rank, type, value, score, why, full_why,
    seen_in, seen_in_full, portal, action, not_enrichable}, one per ranked
    IOC, in rank order. why is a list of short lines, one per process
    (why_lines); full_why holds every original reason (shown on hover).
    seen_in and seen_in_full come from touched_by. action is "Look up" when
    not requested, "Retry" when the lookup failed, else "" (ioc_action).
    An IOC tagged not_enrichable shows the plain reason (for example "not
    sent: internal name") as its portal text, no button, and
    not_enrichable True (drawn muted).
    Used by: build_ioc_rows (the grid draws the first rows).
    """
    answers = answers_by_ioc(results)
    rows = []
    for rank, item in enumerate(ranked, 1):
        portal = answers.get((item["type"], item["value"]), "not requested")
        action = ioc_action(item, portal)
        if item["not_enrichable"]:
            portal = NOT_ENRICHABLE_TEXT.get(item["not_enrichable"], "not sent")
        seen_in, seen_in_full = touched_by(item, table)
        rows.append({"rank": rank, "type": item["type"], "value": item["value"],
                     "score": item["score"], "why": why_lines(item["reasons"]),
                     "full_why": "\n".join(item["reasons"]),
                     "seen_in": seen_in, "seen_in_full": seen_in_full,
                     "portal": portal_text(portal), "action": action,
                     "not_enrichable": bool(item["not_enrichable"])})
    return rows


def touched_by(item, table):
    """Name the processes that touched one IOC.

    Input: item, a ranked IOC (its record["process_guids"] comes from
    iocs.collect_iocs, in first-seen order); table, the process table from
    storylines.build_chains, which holds every process, flagged or not.
    Output: (short_text, full_text). short_text lists up to SEEN_IN_NAMES
    distinct image names in first-seen order, then "+N more" for the rest,
    for example "chrome.exe, svchost.exe +4 more". full_text has every
    name with its process count ("chrome.exe ×12"), one per line, for the
    hover. A guid missing from the table, or with no image, is "unknown
    process".
    Used by: make_ioc_rows (the Seen in column).
    """
    counts = {}
    order = []
    for guid in item["record"]["process_guids"]:
        entry = table.get(guid)
        name = (file_name(entry["image"]) if entry else "") or "unknown process"
        if name not in counts:
            counts[name] = 0
            order.append(name)
        counts[name] += 1
    short_text = ", ".join(order[:SEEN_IN_NAMES])
    if len(order) > SEEN_IN_NAMES:
        short_text += " +%d more" % (len(order) - SEEN_IN_NAMES)
    full_text = "\n".join("%s ×%d" % (name, counts[name]) for name in order)
    return short_text, full_text


def ioc_action(item, portal):
    """Choose the button an IOC gets, the same on every tab.

    Input: item, a ranked IOC dict (scoring.rank_iocs, with its
    not_enrichable tag from filters); portal, its answer so far: a
    common-shape dict from state["results"], or the text "not requested".
    Output: "" when the IOC is never sent (not_enrichable) or already has a
    good answer, "Retry" after a "not_enriched" answer, "Look up" when it
    has not been asked about yet.
    Used by: make_ioc_rows (IOCs tab) and storyline_summary.ioc_details
    (chain cards), so both show the same button for the same IOC.
    """
    if item["not_enrichable"]:
        return ""
    if not isinstance(portal, dict):
        return "Look up"
    if portal["status"] == "not_enriched":
        return "Retry"
    return ""


def answers_by_ioc(results):
    """Index the portal answers by IOC.

    Input: results, the portal answers so far (state["results"], copied by
    the caller).
    Output: {(type, value): common-shape dict}.
    Used by: make_ioc_rows and web.storyline_summary.ioc_details.
    """
    answers = {}
    for result in results:
        answers[(result["type"], result["value"])] = result
    return answers


def make_skipped_rows(ranked):
    """Build the rows of the not-enrichable audit table.

    Input: ranked (scoring.rank_iocs); only items with a not_enrichable tag
    are used.
    Output: a list of dicts {reason, type, value, count} sorted by reason,
    type, value, so the analyst can audit the rules. reason is the plain
    text from NOT_ENRICHABLE_TEXT. Used by: build_skipped_tab.
    """
    blocked = [item for item in ranked if item["not_enrichable"]]
    rows = []
    for item in sorted(blocked, key=lambda s: (s["not_enrichable"], s["type"], s["value"])):
        rows.append({"reason": NOT_ENRICHABLE_TEXT.get(item["not_enrichable"],
                                                       item["not_enrichable"]),
                     "type": item["type"], "value": item["value"],
                     "count": item["record"]["count"]})
    return rows


def make_counts_rows(state, results):
    """Build the counts shown on the Overview tab.

    Input: state (an UPLOADS entry: iocs, ranked); results, the portal
    answers so far (one per IOC: store_result never duplicates).
    Output: a list of {item, value}: IOCs found, not enrichable (never sent
    anywhere), enrichable, looked up, lookup failed, and not requested.
    Used by: build_overview_tab and refresh_view.
    """
    iocs = state["iocs"]
    found = len(iocs["ip"]) + len(iocs["dns"]) + len(iocs["hash"])
    looked_up = 0
    failed = 0
    for result in results:
        if result["status"] == "not_enriched":
            failed += 1
        else:
            looked_up += 1
    blocked = len([item for item in state["ranked"] if item["not_enrichable"]])
    enrichable = len(state["ranked"]) - blocked
    pairs = [
        ("IOCs found (%d IPs, %d DNS names, %d hashes)"
         % (len(iocs["ip"]), len(iocs["dns"]), len(iocs["hash"])), found),
        ("Not enrichable (never sent anywhere)", blocked),
        ("Enrichable", enrichable),
        ("Looked up on the portals", looked_up),
        ("Lookup failed (not enriched)", failed),
        ("Not requested", max(enrichable - len(results), 0)),
    ]
    return [{"item": label, "value": str(value)} for label, value in pairs]


def count_text(number, word, plural):
    """Return "1 process" or "3 processes". Used by summary_caption."""
    return "%d %s" % (number, word if number == 1 else plural)
