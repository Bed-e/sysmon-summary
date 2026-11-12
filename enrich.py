"""Step 5: ask the three local portals about the highest-ranked IOCs.

One call per IOC, in rank order, in a plain for loop, up to a cap. This is
the only module that knows the three portal contracts (design.md section 6).

Every answer, good or bad, becomes the same dict:
    {"type": "ip", "value": "8.8.8.8",
     "score_0_to_100": 12 or None, "label": "no_known_bad" or None,
     "reasons": [...], "status": "ok" or "not_enriched",
     "local_score": 45, "local_reasons": [...]}

A lookup that failed, timed out or was never made is "not_enriched" with
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

DEFAULT_CAP = 25


def load_portal_urls():
    """Read the three portal base URLs from the environment.

    Input: nothing (reads IP_PORTAL_URL, HASH_PORTAL_URL, DNS_PORTAL_URL).
    Output: {"ip": url, "hash": url, "dns": url}. A variable that is not set
    gives "" and that type will be shown as not enriched.
    Used by: main.py once at start-up, then passed to enrich_ranked.
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
    "not_enriched". Used by: enrich_one and enrich_ranked.
    """
    return make_result(item, None, None, [reason], "not_enriched")


def as_list(value):
    """Return value if it is a list, else an empty list (missing = unknown)."""
    if isinstance(value, list):
        return value
    return []


def normalize_ip_answer(item, body):
    """Convert an IP portal 200 answer to the common shape.

    Input: item (ranked dict) and body (parsed JSON, has verdict.score,
    verdict.level, verdict.reasons). Output: common-shape dict. A missing
    score means "not enriched".
    """
    verdict = body.get("verdict") if isinstance(body.get("verdict"), dict) else {}
    score = verdict.get("score")
    if score is None:
        return not_enriched(item, "portal gave no score")
    return make_result(item, score, verdict.get("level"),
                       as_list(verdict.get("reasons")), "ok")


def normalize_hash_answer(item, body):
    """Convert a hash portal 200 answer to the common shape.

    Input: item (ranked dict) and body (verdict.score, verdict.label,
    verdict.reasons, verdict.failed_sources). Failed sources are added to
    the reasons so the analyst sees how complete the answer was.
    Output: common-shape dict.
    """
    verdict = body.get("verdict") if isinstance(body.get("verdict"), dict) else {}
    score = verdict.get("score")
    if score is None:
        return not_enriched(item, "portal gave no score")
    reasons = list(as_list(verdict.get("reasons")))
    failed = as_list(verdict.get("failed_sources"))
    if failed:
        reasons.append("sources that failed: %s" % ", ".join(str(f) for f in failed))
    return make_result(item, score, verdict.get("label"), reasons, "ok")


def normalize_dns_answer(item, body):
    """Convert a DNS portal 200 answer to the common shape.

    Input: item (ranked dict) and body (assessment.average,
    assessment.verdict, assessment.verdict_note, and a "sources" collection
    whose entries have status, score and score_reason). Sources with
    status "error" are listed as failed; the rest give their score_reason.
    Output: common-shape dict. A null average means "not enriched".
    """
    assessment = body.get("assessment") if isinstance(body.get("assessment"), dict) else {}
    score = assessment.get("average")
    if score is None:
        return not_enriched(item, assessment.get("verdict_note") or "portal gave no score")

    reasons = []
    if assessment.get("verdict_note"):
        reasons.append(assessment["verdict_note"])
    sources = body.get("sources")
    if isinstance(sources, dict):
        sources = [dict(entry, name=name) for name, entry in sources.items()
                   if isinstance(entry, dict)]
    failed = []
    for source in as_list(sources):
        if not isinstance(source, dict):
            continue
        name = source.get("name", "source")
        if source.get("status") == "error":
            failed.append(str(name))
        elif source.get("score_reason"):
            reasons.append("%s: %s" % (name, source["score_reason"]))
    if failed:
        reasons.append("sources that failed: %s" % ", ".join(failed))
    return make_result(item, score, assessment.get("verdict"), reasons, "ok")


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
    is not JSON.
    Used by: enrich_ranked.
    """
    ioc_type = item["type"]
    url = build_request_url(ioc_type, item["value"], urls)
    if url is None:
        return not_enriched(item, "%s portal is not configured" % ioc_type)

    status, body, error = call_portal(url, TIMEOUTS[ioc_type])
    if status is None:
        return not_enriched(item, error)
    if status == 400:
        return not_enriched(item, "portal rejected the input (400)")
    if status == 503:
        return not_enriched(item, "portal: every source failed (503)")
    if status != 200:
        return not_enriched(item, "portal returned HTTP %d" % status)
    if not isinstance(body, dict):
        return not_enriched(item, "portal answer was not JSON")
    return NORMALIZERS[ioc_type](item, body)


def enrich_ranked(ranked, urls, cap=DEFAULT_CAP):
    """Look up the ranked IOCs one at a time, highest local score first.

    Input: ranked, the list from scoring.rank_iocs (already in order);
    urls from load_portal_urls; cap, the most lookups to make this run.
    Output: a list of common-shape dicts in the same order as ranked. IOCs
    past the cap are "not_enriched" with the reason "over the cap of N", so
    they stay visible. A plain for loop: no threads.
    Used by: main.py, and later the report (M4).
    """
    results = []
    for position, item in enumerate(ranked):
        if position >= cap:
            results.append(not_enriched(item, "over the cap of %d lookups" % cap))
        else:
            results.append(enrich_one(item, urls))
    return results
