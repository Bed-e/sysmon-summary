"""Row builders: turn ranked IOCs, skipped IOCs and results into the plain dicts
the tables show, plus the small text helpers those tables use.
"""

from web.config import N_CHOICES
from web.reasons import portal_text, short_why


def make_ioc_rows(ranked, results):
    """Build the rows of the ranked IOC table.

    Input: ranked (scoring.rank_iocs, in rank order); results, the portal
    answers so far (state["results"], copied by the caller).
    Output: a list of dicts {rank, type, value, score, why, full_why,
    portal, action}, one per ranked IOC, in rank order. why is the short
    text; full_why holds every original reason (shown on hover). action is
    "Look up" when not requested, "Retry" when the lookup failed, else "".
    Used by: build_ioc_rows (the grid draws the first rows).
    """
    answers = {}
    for result in results:
        answers[(result["type"], result["value"])] = result
    rows = []
    for rank, item in enumerate(ranked, 1):
        portal = answers.get((item["type"], item["value"]), "not requested")
        if not isinstance(portal, dict):
            action = "Look up"
        elif portal["status"] == "not_enriched":
            action = "Retry"
        else:
            action = ""
        rows.append({"rank": rank, "type": item["type"], "value": item["value"],
                     "score": item["score"], "why": short_why(item["reasons"]),
                     "full_why": "\n".join(item["reasons"]),
                     "portal": portal_text(portal), "action": action})
    return rows


def make_skipped_rows(skipped):
    """Build the rows of the skipped-IOC audit table.

    Input: skipped from filters.split_iocs (type, value, reason, record).
    Output: a list of dicts {reason, type, value, count} sorted by reason,
    type, value, so the analyst can audit the filter (design.md section 9,
    rule 4). Used by: build_skipped_tab.
    """
    rows = []
    for item in sorted(skipped, key=lambda s: (s["reason"], s["type"], s["value"])):
        rows.append({"reason": item["reason"], "type": item["type"],
                     "value": item["value"], "count": item["record"]["count"]})
    return rows


def make_counts_rows(state, results):
    """Build the counts shown on the Overview tab.

    Input: state (an UPLOADS entry: iocs, skipped, ranked); results, the
    portal answers so far (one per IOC: store_result never duplicates).
    Output: a list of {item, value}: IOCs found, skipped (never sent
    anywhere), ranked, looked up, lookup failed, and not requested.
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
    ranked = len(state["ranked"])
    pairs = [
        ("IOCs found (%d IPs, %d DNS names, %d hashes)"
         % (len(iocs["ip"]), len(iocs["dns"]), len(iocs["hash"])), found),
        ("Skipped by the filter (never sent anywhere)", len(state["skipped"])),
        ("Ranked locally", ranked),
        ("Looked up on the portals", looked_up),
        ("Lookup failed (not enriched)", failed),
        ("Not requested", max(ranked - len(results), 0)),
    ]
    return [{"item": label, "value": str(value)} for label, value in pairs]


def choose_n(text, ranked):
    """Turn the dropdown value into a number of IOCs.

    Input: text from the dropdown; ranked, the list.
    Output: an int (clamped to the list length), or None if text is not one
    of N_CHOICES. Used by: ask_enrich.
    """
    if text not in N_CHOICES:
        return None
    if text == "all":
        return len(ranked)
    return min(int(text), len(ranked))


def count_text(number, word, plural):
    """Return "1 process" or "3 processes". Used by summary_caption."""
    return "%d %s" % (number, word if number == 1 else plural)
