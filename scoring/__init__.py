"""Step 4: give every IOC that was not skipped a local risk score.

Scoring only decides the ORDER in which IOCs are looked up. It never means
"safe" or "malicious", and a low score is not a verdict.

A "signal" is a tuple (points, reason). Every signal function returns a
list of signals, empty when nothing fires. A field that is missing ("")
is unknown and never fires a signal.

Process-level signals (odd parent pair, user-writable path, registry autorun
write, burst of failed DNS lookups) are scored once per ProcessGuid. An IOC
inherits the points of the single highest-scoring process that touched it
(not the sum, so a widely used IOC does not pile up points).

The result of rank_iocs is a list, highest score first:
    [{"type": "ip", "value": "8.8.8.8", "score": 45,
      "reasons": ["+25 ...", "-15 ..."], "record": {...}}, ...]


The package is split by kind of signal:
    config      weights, thresholds and word lists
    paths       file name and parent/child process signals
    processes   registry and DNS-burst signals; build_process_scores
    network     connection signals and beaconing
    domains     DNS name signals
    ranking     item scoring and rank_iocs (the entry point)
"""
