"""Shared, changing state of the running web app (design.md section 7).

These are the only module-level mutable objects. They live here, apart from
the constants in config.py, so it is obvious what the enrich thread and the
pages share.
"""

import threading

# Shared state (design.md section 7): upload id -> state dict. Only the
# enrich thread writes "results", "run" and "error"; pages only read them.
UPLOADS = {}
# Time of the last hash lookup, so pacing also holds across two runs.
LAST_HASH = {"time": 0.0}
START_LOCK = threading.Lock()
