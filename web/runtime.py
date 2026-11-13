"""Shared, changing state of the running web app (design.md section 7).

These are the only module-level mutable objects. They live here, apart from
the constants in config.py, so it is obvious what the enrich thread and the
pages share.
"""

import threading

# Shared state (design.md section 7): upload id -> state dict. Only the
# enrich thread writes "results"; pages only read them.
UPLOADS = {}
# Time of the last hash lookup, so pacing also holds across two uploads.
LAST_HASH = {"time": 0.0}
# Held while a state's queue fields are read and changed together
# (web.enrich_jobs: add_to_queue, drain_queue, start_worker).
QUEUE_LOCK = threading.Lock()
