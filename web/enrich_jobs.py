"""Enrichment queue: add IOCs to one FIFO queue per upload, drain it in one
background thread one lookup at a time, store the answers and describe the
progress (design.md section 7).

The thread is the only writer of a state's "results"; pages only read them.
The queue fields ("queue", "queued", "queue_done", "queue_total", "worker",
"error") are changed only while QUEUE_LOCK is held.
"""

import threading
import time

from enrich import enrich_one, not_enriched
from filters import list_iocs, load_config
from iocs import collect_iocs
from scoring.findings import find_findings
from scoring.processes import build_process_scores
from scoring.ranking import rank_iocs
from chains import build_chains
from web.config import BUDGET_REASON, USAGE_PATH
from web.limits import add_daily_count, read_daily_count, seconds_to_wait
from web.runtime import LAST_HASH, QUEUE_LOCK


def add_to_queue(state, items, retry=False):
    """Put IOCs on the end of the upload's lookup queue.

    Input: state, an UPLOADS entry (made by make_state); items, ranked IOC
    dicts chosen by a button on the page (one IOC row, or a chain's IOCs
    from chain_items); retry, True when the analyst pressed Retry.
    Output: the number of IOCs added. Skipped without a word: IOCs tagged
    not_enrichable (they are never sent), IOCs already waiting or being
    looked up, and IOCs that already have an answer (unless retry, so a
    Retry can replace a failed answer). When the worker is not running and
    nothing is waiting, the progress numbers start again at 0, so the bar
    counts only this batch.
    Used by: web.actions.enqueue, which then calls start_worker.
    """
    answered = set()
    for result in list(state["results"]):
        answered.add((result["type"], result["value"]))
    added = 0
    with QUEUE_LOCK:
        if state["worker"] != "running" and not state["queue"]:
            state["queue_done"] = 0
            state["queue_total"] = 0
        for item in items:
            key = (item["type"], item["value"])
            if item["not_enrichable"] or key in state["queued"]:
                continue
            if key in answered and not retry:
                continue
            state["queue"].append(item)
            state["queued"].add(key)
            state["queue_total"] += 1
            added += 1
    return added


def lookup_item(item, urls, limits, usage_path=USAGE_PATH,
                pause=time.sleep, clock=time.monotonic):
    """Look up one IOC, keeping to the VirusTotal limits for hashes.

    Input: item, a ranked IOC dict taken off the queue by drain_queue; urls
    from enrich.load_portal_urls; limits from web.limits.load_limits;
    usage_path, the daily count file; pause and clock, replaceable so tests
    need no real waiting.
    Output: one common-shape answer (enrich.enrich_one or not_enriched).
    A hash waits for the per-minute spacing and adds 1 to today's count;
    once the daily budget is used up it is answered "not enriched: daily
    VirusTotal budget reached" without a call. IPs and DNS names are sent
    straight away.
    Used by: drain_queue; its answer goes to store_result.
    """
    if item["type"] != "hash":
        return enrich_one(item, urls)
    if read_daily_count(usage_path) >= limits["hash_per_day"]:
        return not_enriched(item, BUDGET_REASON)
    spacing = 60.0 / limits["hash_per_minute"]
    wait = seconds_to_wait(LAST_HASH["time"], clock(), spacing)
    if wait > 0:
        pause(wait)
    result = enrich_one(item, urls)
    LAST_HASH["time"] = clock()
    add_daily_count(usage_path)
    return result


def store_result(state, result):
    """Save one portal answer in the shared state.

    Input: state; result, a common-shape dict from lookup_item.
    Output: nothing. An earlier answer for the same IOC (a retry) is
    replaced, otherwise the answer is added, so no IOC is counted twice.
    state["version"] goes up by one so the page knows to redraw.
    Used by: drain_queue (the only writer).
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


def drain_queue(state, urls, limits, usage_path=USAGE_PATH,
                pause=time.sleep, clock=time.monotonic):
    """Look up the queued IOCs one at a time until the queue is empty.
    This is the background thread's job.

    Input: state, an UPLOADS entry; urls, limits, usage_path, pause and
    clock as in lookup_item (passed straight on).
    Output: nothing. A plain loop: take the first IOC off the queue (under
    the lock), look it up, save the answer with store_result, take it out of
    "queued" and add 1 to "queue_done". IOCs added by the page while this
    runs are picked up by the same loop. When the queue is empty, "worker"
    becomes "idle" and the thread ends. A crash sets "worker" to "failed",
    keeps the error text in "error", and empties the queue so the analyst
    can press again.
    Used by: start_worker (as the thread target).
    """
    try:
        while True:
            with QUEUE_LOCK:
                if not state["queue"]:
                    state["worker"] = "idle"
                    return
                item = state["queue"].pop(0)
            result = lookup_item(item, urls, limits, usage_path, pause, clock)
            store_result(state, result)
            with QUEUE_LOCK:
                state["queued"].discard((item["type"], item["value"]))
                state["queue_done"] += 1
    except Exception as error:
        with QUEUE_LOCK:
            state["error"] = "%s: %s" % (type(error).__name__, error)
            state["queue"].clear()
            state["queued"].clear()
            state["worker"] = "failed"


def start_worker(state, urls, limits):
    """Start the one background thread for this upload, if it is not running.

    Input: state; urls and limits as in drain_queue.
    Output: True when a thread was started, False when one was already
    running (it picks up the newly queued IOCs itself) or the queue is
    empty. The check and the start happen under the lock, so two quick
    presses cannot start two threads.
    Used by: web.actions.enqueue, right after add_to_queue.
    """
    with QUEUE_LOCK:
        if state["worker"] == "running" or not state["queue"]:
            return False
        state["worker"] = "running"
        state["error"] = ""
    thread = threading.Thread(target=drain_queue, args=(state, urls, limits),
                              daemon=True)
    thread.start()
    return True


def chain_items(state, number):
    """Pick the IOCs that "Enrich this chain" sends.

    Input: state (reads "chains" and "ranked"); number, the chain's 1-based
    position on the page, the only thing the browser sends.
    Output: the ranked IOC dicts touched by that chain's flagged processes,
    in rank order, each once. Not-enrichable IOCs are included here and
    dropped by add_to_queue. A number that is not a chain gives [].
    Used by: web.actions.enrich_chain.
    """
    chains = state["chains"]["chains"]
    if not isinstance(number, int) or number < 1 or number > len(chains):
        return []
    table = state["chains"]["table"]
    wanted = set()
    for guid in chains[number - 1]["flagged"]:
        wanted.update(table[guid]["iocs"])
    return [item for item in state["ranked"]
            if (item["type"], item["value"]) in wanted]


def progress_value(state):
    """Return how far the current batch has got, from 0.0 to 1.0.

    Input: state (queue_done, queue_total).
    Output: a float for the progress bar; 0.0 when nothing was queued.
    Used by: web.actions.refresh_view and report_page.
    """
    if state["queue_total"] == 0:
        return 0.0
    return state["queue_done"] / state["queue_total"]


def progress_text(state):
    """Return the one-line queue status shown beside the progress bar.

    Input: state (worker, queue_done, queue_total, error).
    Output: text such as "Looking up: 3 of 7 done.", "Done: 7 looked up."
    or "Lookups stopped: <error>. Press Look up or Retry to try again."
    Empty text when nothing has been queued yet (the bar is then hidden).
    Used by: web.actions.refresh_view and report_page.
    """
    worker = state["worker"]
    if worker == "failed":
        return ("Lookups stopped: %s. Press Look up or Retry to try again."
                % state["error"])
    if state["queue_total"] == 0:
        return ""
    if worker == "running":
        return "Looking up: %d of %d done." % (state["queue_done"],
                                               state["queue_total"])
    return "Done: %d looked up." % state["queue_done"]


def make_state(name, parsed):
    """Rank a parsed dump locally and build its UPLOADS entry.

    Input: name, the uploaded file's base name (shown as a title only);
    parsed, the dict from parse.read_events.
    Output: the state dict {name, events, iocs, process_scores, chains,
    ranked, results, version, parse} plus the queue fields {queue, queued,
    queue_done, queue_total, worker, error} (see add_to_queue). parse keeps
    read_events' dropped_counts, error_count and total for the Stats tab.
    Pipeline
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
            "ranked": ranked, "results": [], "version": 0,
            "parse": {"dropped_counts": dict(parsed["dropped_counts"]),
                      "error_count": parsed["error_count"],
                      "total": parsed["total"]},
            "queue": [], "queued": set(), "queue_done": 0, "queue_total": 0,
            "worker": "idle", "error": ""}
