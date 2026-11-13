"""Text for each chain card: its title, the one-line summary, and the IOC
details (local score and portal answer) looked up when the card is drawn.
"""

from scoring.paths import file_name
from web.config import NOT_ENRICHABLE_TEXT, PORTAL_HIT_LABELS
from web.reasons import portal_text, short_reason, short_why
from web.rows import answers_by_ioc, count_text, ioc_action


def chain_title(table, finding):
    """Name a chain by what made it suspicious, not by its root process.

    Input: table from storylines.build_chains; finding, the chain's
    "title_finding" (or None).
    Output: text such as "leaked_video.mp4.exe — has a double extension"
    or "powershell.exe → 1.2.3.4 — contacted by a program that rarely needs
    the network". The process is the one the finding belongs to; the arrow
    part appears only for an IP or DNS subject (a hash subject is the
    process's own file, so its long value is left out).
    Used by: build_chain_card (the card header) and timeline_data.slice_choices.
    """
    if finding is None:
        return "nothing flagged"
    entry = table.get(finding["guid"])
    name = file_name(entry["image"]) if entry else ""
    name = name or "unknown process"
    if finding["subject"] is not None and finding["subject"][0] != "hash":
        name = "%s → %s" % (name, finding["subject"][1])
    return "%s — %s" % (name, short_reason(finding["reason"]))


def ioc_details(state):
    """Gather what a chain card shows for each IOC.

    Input: state, an UPLOADS entry (reads "ranked" and "results"; results
    are copied first because the enrich thread may add to them).
    Output: {(type, value): {"rank", "score", "reasons", "portal",
    "action"}}. rank is the IOC's 1-based place in "ranked", so a chain's
    Look up button can call web.actions.lookup_one with a number the server
    made. portal is the portal's common-shape answer, the text "not
    requested", or the plain not-enrichable reason (for example "not sent:
    internal name"). action comes from rows.ioc_action ("Look up", "Retry"
    or "").
    Used by: build_chains_tab, worked out on every draw so new portal
    answers appear without rebuilding the chains.
    """
    answers = answers_by_ioc(list(state["results"]))
    details = {}
    for rank, item in enumerate(state["ranked"], 1):
        key = (item["type"], item["value"])
        portal = answers.get(key, "not requested")
        action = ioc_action(item, portal)
        if item["not_enrichable"]:
            portal = NOT_ENRICHABLE_TEXT.get(item["not_enrichable"], "not sent")
        details[key] = {"rank": rank, "score": item["score"],
                        "reasons": item["reasons"], "portal": portal,
                        "action": action}
    return details


def summarize_storyline(table, chain, process_scores, details):
    """Work out what is in one chain.

    Input: table and chain from storylines.build_chains; process_scores
    from scoring.build_process_scores; details from ioc_details.
    Output: {"processes": n, "flagged": [{name, score, why}] highest first,
    "ips": n, "dns": n, "files": n, "registry": n,
    "portal_hits": [text], "first": time text, "last": time text}.
    flagged are processes with a local score above 0; portal_hits are IOCs a
    portal labelled suspicious or worse.
    Used by: build_chain_card (caption and portal hits).
    """
    flagged = []
    ips = set()
    dns = set()
    files = 0
    registry = 0
    hits = []
    times = []
    for guid in chain["guids"]:
        entry = table[guid]
        if entry["time"]:
            times.append(entry["time"])
        process = process_scores.get(guid)
        if process is not None and process["score"] > 0:
            reasons = [finding["reason"] for finding in process["findings"]]
            flagged.append({"name": file_name(entry["image"]) or "unknown process",
                            "score": process["score"], "why": short_why(reasons)})
        ips.update(entry["ips"])
        dns.update(entry["dns"])
        files += len(entry["files"])
        registry += len(entry["registry"])
        for key in entry["iocs"]:
            portal = details.get(key, {}).get("portal")
            if isinstance(portal, dict) and portal["label"] in PORTAL_HIT_LABELS:
                text = "%s %s: %s" % (key[0], key[1], portal_text(portal))
                if text not in hits:
                    hits.append(text)
    flagged.sort(key=lambda f: -f["score"])
    return {"processes": len(chain["guids"]), "flagged": flagged,
            "ips": len(ips), "dns": len(dns), "files": files,
            "registry": registry, "portal_hits": hits,
            "first": min(times) if times else "",
            "last": max(times) if times else ""}


def summary_caption(summary):
    """Build the one-line summary shown under a collapsed chain.

    Input: summary from summarize_storyline.
    Output: text such as "9 processes · 2 flagged · 3 remote addresses ·
    1 DNS name · 120 files · 2 registry writes · 03:42–04:10". Zero counts
    (other than processes) are left out. Used by: build_chain_card.
    """
    parts = [count_text(summary["processes"], "process", "processes")]
    if summary["flagged"]:
        parts.append("%d flagged" % len(summary["flagged"]))
    if summary["portal_hits"]:
        parts.append(count_text(len(summary["portal_hits"]), "portal hit", "portal hits"))
    for key, word, plural in (("ips", "remote address", "remote addresses"),
                              ("dns", "DNS name", "DNS names"),
                              ("files", "file", "files"),
                              ("registry", "registry write", "registry writes")):
        if summary[key]:
            parts.append(count_text(summary[key], word, plural))
    if summary["first"]:
        start = summary["first"][11:16]
        end = summary["last"][11:16]
        parts.append(start if start == end else "%s–%s" % (start, end))
    return " · ".join(parts)
