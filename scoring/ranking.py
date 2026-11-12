"""Step 6 (IOC part): rank the IOCs from the process findings.

IOCs have no scoring rules of their own. An IOC's score is built from the
findings worked out in steps 3 and 4 ("split inheritance", design.md
section 6):
  - every subject finding about this IOC, from any process that touched it
    (each distinct reason counted once, so a lookalike name queried by
    five processes is not counted five times), plus
  - the process findings of the touching process with the most
    process-wide points.
So a lookalike domain ranks high, but the other names the same browser
looked up do not inherit that clue.

The result of rank_iocs is a list, highest score first:
    [{"type": "ip", "value": "8.8.8.8", "score": 45,
      "reasons": ["+25 ...", "+20 process evil.exe: ..."], "record": {...}}, ...]
"""

from scoring.paths import file_name
from scoring.processes import process_wide_points


def score_ioc(item, process_scores):
    """Score one IOC by split inheritance.

    Input: item, {"type", "value", "record"} from filters.list_iocs (the
    record's "process_guids" lists every process that touched it);
    process_scores from processes.build_process_scores.
    Output: (score, reasons). reasons is a list of text such as
    "+30 process chrome.exe: looks like paypal.com" (about this IOC, named
    after the first process it was found in) and
    "+25 process evil.exe: document app started a program (...)"
    (inherited). Every reason names its process, so the IOC table can
    group them by process (web.reasons.why_lines). A subject reason found
    in several processes is counted once. A guid missing from
    process_scores is ignored.
    Used by: rank_iocs.
    """
    subject = (item["type"], item["value"])
    signals = []
    seen_reasons = set()
    best = None
    for guid in item["record"]["process_guids"]:
        process = process_scores.get(guid)
        if process is None:
            continue
        who = file_name(process["image"]) or "unknown process"
        for finding in process["findings"]:
            if finding["subject"] == subject and finding["reason"] not in seen_reasons:
                seen_reasons.add(finding["reason"])
                signals.append((finding["points"],
                                "process %s: %s" % (who, finding["reason"])))
        if best is None or process_wide_points(process) > process_wide_points(best):
            best = process

    if best is not None:
        who = file_name(best["image"]) or "unknown process"
        for finding in best["findings"]:
            if finding["kind"] == "process":
                signals.append((finding["points"],
                                "process %s: %s" % (who, finding["reason"])))

    score = sum(points for points, reason in signals)
    reasons = ["%+d %s" % (points, reason) for points, reason in signals]
    return score, reasons


def rank_iocs(to_rank, process_scores):
    """Score every IOC in `to_rank` and return them highest score first.

    Input: to_rank from filters.list_iocs (every IOC, each with a
    "not_enrichable" tag); process_scores from
    processes.build_process_scores (worked out once per dump).
    Output: a list of {"type", "value", "score", "reasons", "record",
    "not_enrichable"}. Ties: more sightings first, then earliest first seen.
    Used by: web.enrich_jobs.make_state. The IOC table and the enrich code
    read the result.
    """
    ranked = []
    for item in to_rank:
        score, reasons = score_ioc(item, process_scores)
        ranked.append({
            "type": item["type"],
            "value": item["value"],
            "score": score,
            "reasons": reasons,
            "record": item["record"],
            "not_enrichable": item.get("not_enrichable", ""),
        })

    ranked.sort(key=lambda r: (-r["score"], -r["record"]["count"],
                               r["record"]["first_seen"]))
    return ranked
