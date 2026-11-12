"""Row builders: turn ranked IOCs, skipped IOCs and results into the plain dicts
the tables show, plus the small text helpers those tables use.
"""

from web.config import NOT_ENRICHABLE_TEXT
from web.reasons import portal_text, short_why


def make_ioc_rows(ranked, results):
    """Build the rows of the ranked IOC table.

    Input: ranked (scoring.rank_iocs, in rank order); results, the portal
    answers so far (state["results"], copied by the caller).
    Output: a list of dicts {rank, type, value, score, why, full_why,
    portal, action}, one per ranked IOC, in rank order. why is the short
    text; full_why holds every original reason (shown on hover). action is
    "Look up" when not requested, "Retry" when the lookup failed, else "".
    An IOC tagged not_enrichable shows the plain reason (for example "not
    sent: internal name") and no button.
    Used by: build_ioc_rows (the grid draws the first rows).
    """
    answers = answers_by_ioc(results)
    rows = []
    for rank, item in enumerate(ranked, 1):
        portal = answers.get((item["type"], item["value"]), "not requested")
        if item["not_enrichable"]:
            portal = NOT_ENRICHABLE_TEXT.get(item["not_enrichable"], "not sent")
            action = ""
        elif not isinstance(portal, dict):
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
