"""Enrichment jobs: pick the next IOCs, run the lookups in one background thread,
store the answers and describe the progress.

The thread is the only writer of a state's "results", "run" and "error"
(design.md section 7); pages only read them.
"""

import threading
import time

from enrich import enrich_one, not_enriched
from filters import list_iocs, load_config
from iocs import collect_iocs
from scoring.findings import find_findings
from scoring.processes import build_process_scores
from scoring.ranking import rank_iocs
from storylines import build_chains
from web.config import BUDGET_REASON, USAGE_PATH
from web.limits import add_daily_count, read_daily_count, seconds_to_wait
from web.runtime import LAST_HASH, START_LOCK


def next_items(state, n):
    """Pick the next n ranked IOCs that have not been tried yet.

    Input: state (an UPLOADS entry: ranked, results); n from choose_n.
    Output: up to n ranked dicts, in rank order, with no result yet. A failed
    lookup counts as tried, so "next" moves past it; its row has a Retry
    button instead. So with 5 already done, n=5 gives ranks 6 to 10. IOCs
    tagged not_enrichable are passed over.
    Used by: ask_enrich.
    """
    tried = set()
    for result in state["results"]:
        tried.add((result["type"], result["value"]))
    items = []
    for item in state["ranked"]:
        if len(items) >= n:
            break
        if item["not_enrichable"]:
            continue
        if (item["type"], item["value"]) not in tried:
            items.append(item)
    return items


def store_result(state, result):
    """Save one portal answer in the shared state.

    Input: state; result, a common-shape dict from enrich_one or
    not_enriched.
    Output: nothing. An earlier answer for the same IOC (a retry) is
    replaced, otherwise the answer is added, so no IOC is counted twice.
    state["version"] goes up by one so the page knows to redraw.
    Used by: run_enrichment (the only writer).
    """
    key = (result["type"], result["value"])
    replaced = False
    for index, old in enumerate(state["results"]):
        if (old["type"], old["value"]) == key:
            state["results"][index] = result
            replaced = True
            break
    if not replaced:
        state["results"].append(result)
    state["version"] += 1


def run_enrichment(state, items, urls, limits, usage_path=USAGE_PATH,
                   pause=time.sleep, clock=time.monotonic):
    """Look up the given IOCs one at a time. Runs in the thread.

    Input: state (an UPLOADS entry); items, the ranked dicts to look up (from
    next_items, or one row's item); urls from enrich.load_portal_urls;
    limits from load_limits; usage_path, the daily count file; pause and
    clock, replaceable so tests need no real waiting.
    Output: nothing. Each answer is saved with store_result and
    state["run_done"] goes up. Hash lookups wait for the per-minute spacing,
    are counted, and become "not enriched" once the daily budget is used up
    (a hard stop). A crash sets state["run"] = "failed" with the text in
    state["error"]; a normal end sets "done".
    Used by: start_enrichment (as the thread target). A plain sequential
    loop: one lookup at a time.
    """
    try:
        spacing = 60.0 / limits["hash_per_minute"]
        for item in items:
            if item["type"] == "hash":
                if read_daily_count(usage_path) >= limits["hash_per_day"]:
                    result = not_enriched(item, BUDGET_REASON)
                else:
                    wait = seconds_to_wait(LAST_HASH["time"], clock(), spacing)
                    if wait > 0:
                        pause(wait)
                    result = enrich_one(item, urls)
                    LAST_HASH["time"] = clock()
                    add_daily_count(usage_path)
            else:
                result = enrich_one(item, urls)
            store_result(state, result)
            state["run_done"] += 1
        state["run"] = "done"
    except Exception as error:
        state["error"] = "%s: %s" % (type(error).__name__, error)
        state["run"] = "failed"


def start_enrichment(state, items, urls, limits):
    """Start the one background thread, unless a run is already going.

    Input: state; items, the ranked dicts to look up; urls, limits as in
    run_enrichment.
    Output: True when a thread was started, False when one was already
    running (the press then does nothing). A lock makes the check and the
    start one step, so two quick presses cannot start two runs. Earlier
    results are kept: each run adds to them.
    Used by: begin_enrichment.
    """
    with START_LOCK:
        if state["run"] == "running":
            return False
        state["error"] = ""
        state["run_size"] = len(items)
        state["run_done"] = 0
        state["run"] = "running"
    thread = threading.Thread(target=run_enrichment,
                              args=(state, items, urls, limits), daemon=True)
    thread.start()
    return True


def status_text(state):
    """Return the one-line run status for the Overview tab.

    Input: state (run, run_done, run_size, results, ranked, error).
    Output: text such as "Running: 3 of 5 done." or "Run failed: ...".
    Used by: build_overview_tab and refresh_view.
    """
    run = state["run"]
    if run == "idle":
        return "No portal has been called yet."
    if run == "running":
        return "Running: %d of %d done." % (state["run_done"], state["run_size"])
    enrichable = len([item for item in state["ranked"] if not item["not_enrichable"]])
    tried = "%d of %d enrichable IOCs tried so far." % (len(state["results"]),
                                                         enrichable)
    if run == "done":
        return "Last run finished: %d looked up. %s" % (state["run_done"], tried)
    return "Run failed: %s. %s" % (state["error"], tried)


def make_state(name, parsed):
    """Rank a parsed dump locally and build its UPLOADS entry.

    Input: name, the uploaded file's base name (shown as a title only);
    parsed, the dict from parse.read_events.
    Output: the state dict {name, events, iocs, process_scores, chains,
    ranked, results, run, error, run_size, run_done, version}. Pipeline
    steps 2 to 6 run once here (collect, findings, process scores, chains,
    IOC rank with the enrichability tag) and every tab reads the result.
    Enrichment only ever adds to "results"; it never rebuilds the rest.
    No portal is called.
    Used by: upload_endpoint.
    """
    config = load_config()
    events = parsed["events"]
    iocs = collect_iocs(events)
    process_scores = build_process_scores(events, find_findings(events, iocs, config))
    chains = build_chains(events, iocs, process_scores)
    ranked = rank_iocs(list_iocs(iocs, config), process_scores)
    return {"name": name, "events": events, "iocs": iocs,
            "process_scores": process_scores, "chains": chains,
            "ranked": ranked, "results": [], "run": "idle",
            "error": "", "run_size": 0, "run_done": 0, "version": 0}
