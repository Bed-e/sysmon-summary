"""Fixed settings for the web app: file paths, limits, column layouts, colours.

Nothing here runs code or holds changing state. Every other web module imports
its constants from here, so a setting is changed in exactly one place.
"""

import os

LIMITS_PATH = os.path.join("data", "api_limits.txt")
USAGE_PATH = os.path.join("data", "hash_usage.txt")
UPLOAD_DIR = "uploads"

DEFAULT_LIMITS = {"hash_per_minute": 4, "hash_per_day": 500}
REFRESH_SECONDS = 2
MAX_DEPTH = 50  # deepest process nesting drawn; stops a malformed parent loop

# Plain words for filters.not_enrichable_reason codes, shown instead of a
# Look up button (design.md section 6).
NOT_ENRICHABLE_TEXT = {
    "ip_not_public": "not sent: private or reserved address",
    "ip_known_shared_range": "not sent: shared CDN or cloud address",
    "dns_internal": "not sent: internal name",
}
SHOW_STEP = 10  # rows (or storylines) shown at first, and added per "Show more"
MAX_UPLOAD_BYTES = 200 * 1024 * 1024
EVTX_MAGIC = b"ElfFile\x00"
BUDGET_REASON = "daily VirusTotal budget reached"

# Fixed messages for the upload page. The endpoint redirects with a code, so
# nothing the user typed is ever echoed back.
UPLOAD_ERRORS = {
    "none": "Choose a .evtx file first.",
    "type": "Only .evtx files are accepted.",
    "magic": "That file is not a Windows .evtx log.",
    "size": "That file is too large.",
    "read": "Could not read that file.",
}

UPLOAD_FORM = (
    '<form class="upload-form" method="post" action="/upload" '
    'enctype="multipart/form-data">'
    '<label class="upload-drop">'
    '<span class="upload-drop-title">Choose a Sysmon .evtx file</span>'
    '<input type="file" name="file" accept=".evtx"></label>'
    '<button class="upload-button" type="submit">Upload and rank</button></form>'
)

# The IOC table is a plain grid (so each row can hold a Look up button).
IOC_HEADERS = ["Rank", "Type", "Value", "Local score", "Why", "Portal"]
IOC_GRID_COLUMNS = ("3em 3.5em minmax(9em, 16em) 4.5em minmax(14em, 1fr) "
                    "minmax(12em, 20em)")

SKIPPED_COLUMNS = [
    {"name": "reason", "label": "Reason", "field": "reason", "align": "left"},
    {"name": "type", "label": "Type", "field": "type", "align": "left"},
    {"name": "value", "label": "Value", "field": "value", "align": "left",
     "style": "white-space: normal; word-break: break-all"},
    {"name": "count", "label": "Sightings", "field": "count", "align": "left"},
]
SUSPICIOUS_COLUMNS = [
    {"name": "time", "label": "First seen (UTC)", "field": "time", "align": "left"},
    {"name": "process", "label": "Process", "field": "process", "align": "left"},
    {"name": "score", "label": "Local score", "field": "score", "align": "left"},
    {"name": "why", "label": "Why", "field": "why", "align": "left",
     "style": "white-space: normal"},
]

# Short phrases for the reasons scoring/ writes (see short_reason).
# (text the reason starts with, short phrase, keep the bracketed detail?)
SHORT_REASONS = [
    ("file runs from a user-writable path", "runs from a user folder", False),
    ("double extension", "has a double extension", True),
    ("document app started a program", "was started by a document app", True),
    ("explorer started a program from Temp", "was started by explorer from Temp", False),
    ("service started a program from a user-writable path",
     "was started by a service from a user folder", False),
    ("writes an autorun registry key", "sets an autorun registry key", False),
    ("connection from a program that rarely needs the network",
     "contacted by a program that rarely needs the network", False),
    ("unusual destination port", "unusual port", True),
    ("very long label", "very long DNS label", False),
    ("high-entropy label", "random-looking DNS label", False),
    ("registry references this file's path", "an autorun key points to this file", False),
    ("burst of discovery commands", "started a burst of discovery commands", True),
]

# Portal labels that count as a "portal hit" in a storyline summary.
PORTAL_HIT_LABELS = ["malicious", "suspicious", "likely_malware", "definitely_malware"]

# Timeline: one row per process, a bar for its lifetime, dots for events.
EVENT_LANES = {1: "Process start", 3: "Network", 22: "DNS", 11: "File",
               12: "Registry", 13: "Registry", 14: "Registry"}
EVENT_TYPE_COLORS = [  # (event type, dot colour), in legend order
    ("Process start", "#3b6fd6"),
    ("Network", "#14a3a3"),
    ("DNS", "#8a4fd6"),
    ("File", "#6b6b6b"),
    ("Registry", "#c9a227"),
]
HIGH_SCORE = 40  # a process score at or above this is shown red
DETAIL_LENGTH = 110  # longest hover text for one event
SCORE_BARS = [  # (score level, legend label, bar colour)
    ("normal", "Process, score 0", "#cfcfcf"),
    ("flagged", "Process, score 1-%d" % (HIGH_SCORE - 1), "#f0a020"),
    ("high", "Process, score %d+" % HIGH_SCORE, "#d62020"),
]
STORYLINE_CHOICES = 20  # storylines offered in the timeline dropdown
ROWS_VISIBLE = 40       # rows shown at once; more rows get a scroll slider
ROW_HEIGHT = 24         # pixels per process row
LABEL_WIDTH = 260       # pixels for the left-aligned process names
INDENT = "   "  # non-breaking spaces: ECharts keeps them


NOT_A_VERDICT = ("Scores are policy numbers, not a verdict. Local scores order "
                 "the work; portal scores are shown beside them and are never "
                 "merged or averaged.")
