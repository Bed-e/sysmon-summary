"""Hash lookup limits: the limits file, the daily counter and the pacing maths.

Only hash lookups reach VirusTotal, so only they are counted and paced
(design.md section 7). These functions read and write small text files and do
plain arithmetic; they never touch the network or the UI.
"""

import datetime

from web.config import BUDGET_REASON, DEFAULT_LIMITS, LIMITS_PATH, USAGE_PATH


def load_limits(path=LIMITS_PATH):
    """Read the hash lookup limits file.

    Input: path of data/api_limits.txt (lines "name=value"; "#" starts a
    comment). Written by the analyst by hand.
    Output: {"hash_per_minute": int, "hash_per_day": int}. A missing file,
    a missing line or a value that is not a whole number above 0 falls back
    to the default (4 and 500).
    Used by: the enrich route and run_enrichment.
    """
    limits = dict(DEFAULT_LIMITS)
    try:
        with open(path, encoding="utf-8") as handle:
            lines = handle.read().splitlines()
    except OSError:
        return limits
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        name = name.strip()
        value = value.strip()
        if name in limits and value.isdigit() and int(value) > 0:
            limits[name] = int(value)
    return limits


def today_text():
    """Return today's date as "YYYY-MM-DD". Used by the daily counter."""
    return datetime.date.today().isoformat()


def read_daily_count(path=USAGE_PATH, today=None):
    """Return how many hash lookups were made today.

    Input: path of data/hash_usage.txt (one line "YYYY-MM-DD count",
    written by add_daily_count); today, a date text (default: real today).
    Output: the count, or 0 when the file is missing, garbled or from
    another day.
    Used by: the enrich route (warning) and run_enrichment (hard stop).
    """
    today = today or today_text()
    try:
        with open(path, encoding="utf-8") as handle:
            parts = handle.read().split()
    except OSError:
        return 0
    if len(parts) == 2 and parts[0] == today and parts[1].isdigit():
        return int(parts[1])
    return 0


def add_daily_count(path=USAGE_PATH, today=None):
    """Add 1 to today's hash lookup count and save it.

    Input: path and today as in read_daily_count.
    Output: the new count. A new day starts again at 1.
    Used by: run_enrichment, after every hash call (cached or not).
    """
    today = today or today_text()
    count = read_daily_count(path, today) + 1
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("%s %d\n" % (today, count))
    return count

def count_hashes(items):
    """Count the hash IOCs among the items about to be looked up.

    Input: items, ranked dicts (from next_items, or one row's item).
    Output: an integer. Used by: needs_warning.
    """
    total = 0
    for item in items:
        if item["type"] == "hash":
            total += 1
    return total


def needs_warning(items, limits, used_today):
    """Say whether looking up these items would go over the hash limits.

    Input: items, the ranked dicts about to be sent (see count_hashes);
    limits from load_limits; used_today from read_daily_count.
    Output: a list of warning lines, empty when all is fine. Lines give the
    time the per-minute rate needs and the share of the daily budget.
    Used by: confirm_and_start, which shows the dialog when the list is not
    empty.
    """
    hashes = count_hashes(items)
    per_minute = limits["hash_per_minute"]
    per_day = limits["hash_per_day"]
    lines = []
    if hashes > per_minute:
        minutes = -(-hashes // per_minute)  # round up
        lines.append("%d hash lookups at %d per minute need about %d minutes; "
                     "they are spaced out, so this run will be slow."
                     % (hashes, per_minute, minutes))
    if hashes > 0 and used_today + hashes > per_day:
        left = max(per_day - used_today, 0)
        lines.append("Daily budget: %d of %d used today and this run needs %d "
                     "more. Only %d can be sent; the rest will show 'not "
                     "enriched: %s'." % (used_today, per_day, hashes, left,
                                          BUDGET_REASON))
    return lines


def seconds_to_wait(last_time, now, spacing):
    """Return how long to wait before the next hash lookup.

    Input: last_time and now, clock readings in seconds; spacing, seconds
    between hash lookups (60 / hash_per_minute).
    Output: seconds to wait, 0 or more. Used by: run_enrichment.
    """
    wait = last_time + spacing - now
    if wait < 0:
        return 0
    return wait
