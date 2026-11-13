"""Hash lookup limits: the limits file, the daily counter and the pacing maths.

Only hash lookups reach VirusTotal, so only they are counted and paced
(design.md section 7). These functions read and write small text files and do
plain arithmetic; they never touch the network or the UI.
"""

import datetime

from web.config import DEFAULT_LIMITS, LIMITS_PATH, USAGE_PATH


def load_limits(path=LIMITS_PATH):
    """Read the hash lookup limits file.

    Input: path of data/api_limits.txt (lines "name=value"; "#" starts a
    comment). Written by the analyst by hand.
    Output: {"hash_per_minute": int, "hash_per_day": int}. A missing file,
    a missing line or a value that is not a whole number above 0 falls back
    to the default (4 and 500).
    Used by: web.actions.enqueue (passed on to the queue thread).
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
    Used by: web.enrich_jobs.lookup_item (the daily hard stop).
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
    Used by: web.enrich_jobs.lookup_item, after every hash call (cached or not).
    """
    today = today or today_text()
    count = read_daily_count(path, today) + 1
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("%s %d\n" % (today, count))
    return count

def seconds_to_wait(last_time, now, spacing):
    """Return how long to wait before the next hash lookup.

    Input: last_time and now, clock readings in seconds; spacing, seconds
    between hash lookups (60 / hash_per_minute).
    Output: seconds to wait, 0 or more. Used by: web.enrich_jobs.lookup_item.
    """
    wait = last_time + spacing - now
    if wait < 0:
        return 0
    return wait
