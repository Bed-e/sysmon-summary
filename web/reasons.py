"""Readable text for IOC reasons and portal answers.

scoring/ writes long reason sentences; these functions shorten them for the
IOC table and the chain summaries, and turn a portal result into words.
"""

from web.config import SHORT_REASONS


def portal_text(portal):
    """Return the portal answer for one IOC as plain text.

    Input: portal, the common-shape dict from enrich (status, score_0_to_100,
    label, reasons), or the text "not requested" when no lookup was made.
    Output: "not requested"; "NOT ENRICHED: reason" when there is no answer;
    or "portal 80 (label)" with " [partial: some sources failed]" added when
    some sources failed. A failed lookup is never shown as a low score.
    Plain text only: NiceGUI escapes it when it is drawn.
    Used by: make_ioc_rows and the Chains tab.
    """
    if not isinstance(portal, dict):
        return str(portal)
    if portal["status"] == "not_enriched":
        reason = portal["reasons"][0] if portal["reasons"] else "no reason given"
        return "NOT ENRICHED: %s" % reason
    note = " [partial: some sources failed]" if portal["status"] == "partial" else ""
    return "portal %s (%s)%s" % (portal["score_0_to_100"], portal["label"], note)


def bracket_detail(text):
    """Return the last " (...)" part of a reason, or "" when there is none.

    Example: "double extension (.mp4.exe)" gives " (.mp4.exe)".
    Used by: short_reason.
    """
    start = text.rfind(" (")
    if start == -1 or not text.endswith(")"):
        return ""
    return text[start:]


def reason_parts(text):
    """Split one scoring reason into (process name, short phrase).

    Input: text, one reason made by scoring/, for example
    "+20 process onedrivesetup.exe: file runs from a user-writable path
    (C:\\Users\\...)", or a process signal without the points and prefix.
    Output: ("onedrivesetup.exe", "runs from a user folder"); the name is ""
    when the reason is not about a process. Points and long paths are
    dropped; a short detail is kept where it helps (a port, a double
    extension). Unknown text falls back to itself without the points and
    the bracketed part.
    Used by: short_reason and short_why.
    """
    first, _, rest = text.partition(" ")
    if first[:1] in "+-" and first[1:].isdigit():
        text = rest
    who = ""
    if text.startswith("process ") and ": " in text:
        who, text = text[len("process "):].split(": ", 1)
        first, _, rest = text.partition(" ")  # some reasons put points here
        if first[:1] in "+-" and first[1:].isdigit():
            text = rest

    phrase = None
    for start, short, keep_detail in SHORT_REASONS:
        if text.startswith(start):
            phrase = short + (bracket_detail(text) if keep_detail else "")
            break
    if phrase is None and text.endswith("failed DNS lookups from one process"):
        phrase = "made %s failed DNS lookups" % text.split(" ")[0]
    if phrase is None and text.startswith("regular timing: "):
        phrase = "possible beaconing (%s)" % text[len("regular timing: "):]
    if phrase is None:
        detail = bracket_detail(text)
        phrase = text[:len(text) - len(detail)] if detail else text
    return who, phrase


def short_reason(text):
    """Turn one scoring reason into one short phrase.

    Input: text, one reason (see reason_parts).
    Output: e.g. "onedrivesetup.exe runs from a user folder".
    Used by: tests and anywhere a single reason is shown.
    """
    who, phrase = reason_parts(text)
    if who:
        return "%s %s" % (who, phrase)
    return phrase


def short_why(reasons):
    """Join the short phrases for a list of reasons into one line.

    Input: reasons, a list of scoring texts (see why_lines).
    Output: the why_lines joined with " · ".
    Used by: summarize_chain and make_suspicious_rows (one-line
    summaries of a process's findings).
    """
    return " · ".join(why_lines(reasons))


def why_lines(reasons):
    """Group the short phrases for a list of reasons, one line per process.

    Input: reasons, a list of scoring texts: an IOC's "reasons" from
    scoring.rank_iocs (each starts "process <name>: ..."), or the reason
    texts of a process's findings (no process name).
    Output: a list of lines in first-seen order. Phrases about the same
    process share a line ("a.exe: runs from a user folder and sets an
    autorun registry key"); a phrase with no process is a line of its own;
    repeated phrases appear once.
    Used by: short_why, and make_ioc_rows (the IOCs tab draws one line
    each).
    """
    order = []       # parts in first-seen order: ("process", name) or ("phrase", text)
    by_process = {}  # process name -> its phrases
    for reason in reasons:
        who, phrase = reason_parts(reason)
        if who:
            if who not in by_process:
                by_process[who] = []
                order.append(("process", who))
            if phrase not in by_process[who]:
                by_process[who].append(phrase)
        elif ("phrase", phrase) not in order:
            order.append(("phrase", phrase))
    parts = []
    for kind, text in order:
        if kind == "process":
            parts.append("%s: %s" % (text, " and ".join(by_process[text])))
        else:
            parts.append(text)
    return parts
