"""The one-paragraph summary shown at the top of each storyline.
"""

from scoring.paths import file_name
from web.config import PORTAL_HIT_LABELS
from web.reasons import portal_text, short_why
from web.rows import count_text


def summarize_storyline(table, storyline, process_scores):
    """Work out what is in one storyline.

    Input: table and storyline from storylines.build_storylines (with the
    portal answers attached); process_scores from
    scoring.build_process_scores.
    Output: {"processes": n, "flagged": [{name, score, why}] highest first,
    "ips": n, "dns": n, "files": n, "registry": n,
    "portal_hits": [text], "first": time text, "last": time text}.
    flagged are processes with a local score above 0; portal_hits are IOCs a
    portal labelled suspicious or worse.
    Used by: summary_caption and build_storyline.
    """
    flagged = []
    ips = set()
    dns = set()
    files = 0
    registry = 0
    hits = []
    times = []
    for guid in storyline["guids"]:
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
        for ioc in entry["iocs"]:
            portal = ioc["portal"]
            if isinstance(portal, dict) and portal["label"] in PORTAL_HIT_LABELS:
                text = "%s %s: %s" % (ioc["type"], ioc["value"], portal_text(portal))
                if text not in hits:
                    hits.append(text)
    flagged.sort(key=lambda f: -f["score"])
    return {"processes": len(storyline["guids"]), "flagged": flagged,
            "ips": len(ips), "dns": len(dns), "files": files,
            "registry": registry, "portal_hits": hits,
            "first": min(times) if times else "",
            "last": max(times) if times else ""}


def summary_caption(summary):
    """Build the one-line summary shown under a collapsed storyline.

    Input: summary from summarize_storyline.
    Output: text such as "9 processes · 2 flagged · 3 remote addresses ·
    1 DNS name · 120 files · 2 registry writes · 03:42–04:10". Zero counts
    (other than processes) are left out. Used by: build_storyline.
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
