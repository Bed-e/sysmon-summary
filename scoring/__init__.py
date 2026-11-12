"""Steps 3, 4 and the IOC part of step 6: local clues, process scores and IOC rank.

A "signal" is a tuple (points, reason). Every signal function returns a
list of signals, empty when nothing fires. A field that is missing ("")
is unknown and never fires a signal.

A "finding" is one signal tied to one process, with a kind ("process" or
"subject") and, for subject findings, the IOC it is about. See findings.py.

Flow:
    events, iocs, config -> findings.find_findings      -> findings
    events, findings     -> processes.build_process_scores -> process_scores
    to_rank, process_scores -> ranking.rank_iocs         -> ranked IOCs

The package is split by kind of signal:
    config      weights, thresholds and word lists
    paths       file name and parent/child process signals
    processes   registry and DNS-burst signals; build_process_scores
    network     connection signals and beaconing
    domains     DNS name signals
    findings    every finding function and find_findings (the entry point)
    ranking     IOC scoring by split inheritance and rank_iocs
"""
