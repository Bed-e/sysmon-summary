"""Step 7 (optional): ask the three local portals about one IOC.

One call per IOC; the web app's background thread calls enrich_one in a
plain loop. This is the only module that knows the three portal contracts
(design.md section 7).

Every answer, good or bad, becomes the same dict:
    {"type": "ip", "value": "8.8.8.8",
     "score_0_to_100": 12 or None, "label": "no_known_bad" or None,
     "reasons": [...], "status": "enriched", "partial" or "not_enriched",
     "local_score": 45, "local_reasons": [...]}

"partial" means the portal answered but some of its sources failed. A
lookup that failed, timed out or was never made is "not_enriched" with
the reason in "reasons". It is never shown as a low score. The scores are
policy numbers, not probabilities, and are never averaged across types.
Nothing here says "safe" or "clean".
"""

import os

import requests

# Environment variable that holds each portal's base URL.
URL_VARIABLES = {
    "ip": "IP_PORTAL_URL",
    "hash": "HASH_PORTAL_URL",
    "dns": "DNS_PORTAL_URL",
}

# URL path of each portal (design.md section 6).
URL_PATHS = {
    "ip": "/api/ip/",
    "hash": "/api/v1/hash/",
    "dns": "/api/v1/domain/",
}

# Seconds to wait for each portal. The IP portal asks sources in sequence
# (about 24 s worst case); the DNS portal can take about a minute.
TIMEOUTS = {"ip": 30, "hash": 30, "dns": 70}


def load_portal_urls():
    """Read the three portal base URLs from the environment.

    Input: nothing (reads IP_PORTAL_URL, HASH_PORTAL_URL, DNS_PORTAL_URL).
    Output: {"ip": url, "hash": url, "dns": url}. A variable that is not set
    gives "" and that type will be shown as not enriched.
    Used by: web.actions, before each enrichment run.
    """
    urls = {}
    for ioc_type, variable in URL_VARIABLES.items():
        urls[ioc_type] = os.environ.get(variable, "").strip().rstrip("/")
    return urls


def build_request_url(ioc_type, value, urls):
    """Build the full lookup URL for one IOC.

    Input: ioc_type ("ip", "hash" or "dns") and value, both from a ranked
    item made by scoring.rank_iocs; urls from load_portal_urls.
    Output: the URL string, or None when that portal has no base URL.
    Used by: enrich_one.
    """
    base = urls.get(ioc_type, "")
    if not base:
        return None
    return base + URL_PATHS[ioc_type] + value


def call_portal(url, timeout):
    """Make one GET request. The only function that uses the network.

    Input: url from build_request_url; timeout in seconds from TIMEOUTS.
    Output: tuple (status_code, json_or_None, error_text). On a timeout or
    connection error status_code is None and error_text says what happened.
    A reply that is not JSON gives json None.
    Used by: enrich_one. Tests replace this function with a fake.
    """
    try:
        response = requests.get(url, timeout=timeout)
    except requests.exceptions.Timeout:
        return None, None, "timed out after %d s" % timeout
    except requests.exceptions.RequestException as error:
        return None, None, "request failed: %s" % type(error).__name__
    try:
        body = response.json()
    except ValueError:
        body = None
    return response.status_code, body, ""


def make_result(item, score, label, reasons, status):
    """Build the common-shape dict for one IOC.

    Input: item (a ranked dict with type, value, score, reasons) and the
    portal's score, label, reasons and status.
    Output: the common-shape dict, with the local score and reasons beside
    the portal's, so both are always shown together.
    Used by: the normalize_* functions and not_enriched.
    """
    return {
        "type": item["type"],
        "value": item["value"],
        "score_0_to_100": score,
        "label": label,
        "reasons": reasons,
        "status": status,
        "local_score": item["score"],
        "local_reasons": item["reasons"],
    }


def not_enriched(item, reason):
    """Common shape for an IOC that has no portal answer.

    Input: item (ranked dict) and reason (text, e.g. "portal returned 503").
    Output: common-shape dict with score None, label None, status
    "not_enriched". Used by: enrich_one and web.enrich_jobs.
    """
    return make_result(item, None, None, [reason], "not_enriched")


def as_list(value):
    """Return value if it is a list, else an empty list (missing = unknown)."""
    if isinstance(value, list):
        return value
    return []


def status_for(failed):
    """Return "partial" when any source failed, else "enriched".

    Input: failed, a list of the names of sources that failed.
    Used by: the three normalize_* functions.
    """
    if failed:
        return "partial"
    return "enriched"


def failed_note(failed):
    """Return the list of reasons that names failed sources (empty if none)."""
    if failed:
        return ["sources that failed: %s" % ", ".join(failed)]
    return []


def normalize_ip_answer(item, body):
    """Convert an IP portal 200 answer to the common shape.

    Input: item (ranked dict) and body (verdict.level/score/reasons and
    sources, a LIST of {name, status}). level "not_applicable" means the
    portal did not judge the address (its score 0 is NOT "safe"), so it is
    "not_enriched". Sources with status "error" make the result "partial".
    Output: common-shape dict.
    """
    verdict = body.get("verdict") if isinstance(body.get("verdict"), dict) else {}
    score = verdict.get("score")
    if verdict.get("level") == "not_applicable":
        return not_enriched(item, "portal did not judge this address (not_applicable)")
    if score is None:
        return not_enriched(item, "portal gave no score")
    failed = []
    for source in as_list(body.get("sources")):
        if isinstance(source, dict) and source.get("status") == "error":
            failed.append(str(source.get("name", "source")))
    reasons = list(as_list(verdict.get("reasons"))) + failed_note(failed)
    return make_result(item, score, verdict.get("level"), reasons, status_for(failed))


def normalize_hash_answer(item, body):
    """Convert a hash portal 200 answer to the common shape.

    Input: item (ranked dict) and body (verdict.score/label/reasons/
    failed_sources, and sources, a DICT of {status}). When every source has
    status "error" the portal knows nothing, so the result is
    "not_enriched". Some failed sources make it "partial".
    Output: common-shape dict.
    """
    verdict = body.get("verdict") if isinstance(body.get("verdict"), dict) else {}
    sources = body.get("sources") if isinstance(body.get("sources"), dict) else {}
    statuses = [s.get("status") for s in sources.values() if isinstance(s, dict)]
    if statuses and all(status == "error" for status in statuses):
        return not_enriched(item, "every hash source failed")
    score = verdict.get("score")
    if score is None:
        return not_enriched(item, "portal gave no score")
    failed = [str(name) for name in as_list(verdict.get("failed_sources"))]
    reasons = list(as_list(verdict.get("reasons"))) + failed_note(failed)
    return make_result(item, score, verdict.get("label"), reasons, status_for(failed))


def normalize_dns_answer(item, body):
    """Convert a DNS portal 200 answer to the common shape.

    Input: item (ranked dict) and body (assessment.average/verdict/
    verdict_note/sources_used/sources_total, and sources, a DICT whose
    entries have status, score and score_reason). A null average
    (verdict "not_graded") is "not_enriched". Sources with status "error"
    are listed as failed and make the result "partial".
    Output: common-shape dict.
    """
    assessment = body.get("assessment") if isinstance(body.get("assessment"), dict) else {}
    score = assessment.get("average")
    if score is None:
        return not_enriched(item, assessment.get("verdict_note") or "no DNS source answered (not_graded)")

    reasons = []
    if assessment.get("verdict_note"):
        reasons.append(assessment["verdict_note"])
    failed = []
    sources = body.get("sources") if isinstance(body.get("sources"), dict) else {}
    for name, source in sources.items():
        if not isinstance(source, dict):
            continue
        if source.get("status") == "error":
            failed.append(str(name))
        elif source.get("score_reason"):
            reasons.append("%s: %s" % (name, source["score_reason"]))
    used = assessment.get("sources_used")
    total = assessment.get("sources_total")
    if not failed and isinstance(used, int) and isinstance(total, int) and used < total:
        failed.append("%d of %d sources did not score" % (total - used, total))
    reasons += failed_note(failed)
    return make_result(item, score, assessment.get("verdict"), reasons, status_for(failed))


NORMALIZERS = {
    "ip": normalize_ip_answer,
    "hash": normalize_hash_answer,
    "dns": normalize_dns_answer,
}


def enrich_one(item, urls):
    """Look up one ranked IOC and return its common-shape dict.

    Input: item, one entry of scoring.rank_iocs' list; urls from
    load_portal_urls. Output: common-shape dict. Not-enriched reasons:
    portal not configured, timeout or connection error, HTTP 400 (bad
    input), 503 (every source failed), any other status, or an answer that
    is not JSON. An item tagged not_enrichable (private IP, shared range,
    internal DNS name) is answered "not sent: <reason code>" without any
    call: the privacy check right before every lookup.
    Used by: web.enrich_jobs.run_enrichment.
    """
    if item.get("not_enrichable"):
        return not_enriched(item, "not sent: %s" % item["not_enrichable"])
    ioc_type = item["type"]
    url = build_request_url(ioc_type, item["value"], urls)
    if url is None:
        return not_enriched(item, "%s portal is not configured" % ioc_type)

    status, body, error = call_portal(url, TIMEOUTS[ioc_type])
    if status is None:
        return not_enriched(item, error)
    if status == 400:
        return not_enriched(item, "portal_rejected_input (400)")
    if status == 503:
        return not_enriched(item, "portal: every source failed (503)")
    if status != 200:
        return not_enriched(item, "portal returned HTTP %d" % status)
    if not isinstance(body, dict):
        return not_enriched(item, "portal answer was not JSON")
    return NORMALIZERS[ioc_type](item, body)
