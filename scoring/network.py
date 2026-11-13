"""Network signals: programs that rarely need the network, unusual ports and
beaconing timing.
"""

from datetime import datetime

from scoring.config import (BEACON_MAX_SPREAD, BEACON_MIN_COUNT,
    BEACON_MIN_MEAN_GAP, NORMAL_PORTS, RARE_NETWORK_PROCESSES,
    WEIGHT_BEACONING, WEIGHT_RARE_NETWORK_PROCESS, WEIGHT_UNUSUAL_PORT)
from scoring.paths import name_without_exe


def network_signals(ip_events):
    """Judge the outbound connections one process made to one IP.

    Input: ip_events, the event 3 records for one (process, IP) pair, from
    findings.network_findings. Inbound connections (Initiated=false) are
    ignored.
    Output: a list of (points, reason). It fires when the program is in
    RARE_NETWORK_PROCESSES (powershell, rundll32, certutil, ...: programs
    attackers use to download or call home), and when a port other than
    80, 443 or 53 is used. Each fires at most once. A program not on the
    list (a browser, OneDrive, svchost) never fires the first check.
    Used by: findings.network_findings.
    """
    signals = []
    rare = ""
    odd_port = ""

    for event in ip_events:
        if event["Initiated"].strip().lower() == "false":
            continue
        image = event["Image"]
        if image != "" and name_without_exe(image) in RARE_NETWORK_PROCESSES:
            rare = rare or image
        port = event["DestinationPort"].strip()
        if port != "" and port not in NORMAL_PORTS:
            odd_port = odd_port or port

    if rare:
        signals.append((WEIGHT_RARE_NETWORK_PROCESS,
                        "connection from a program that rarely needs the "
                        "network (%s)" % rare))
    if odd_port:
        signals.append((WEIGHT_UNUSUAL_PORT,
                        "unusual destination port (%s)" % odd_port))
    return signals


def parse_time(text):
    """Turn Sysmon's time text into a datetime, or None if it cannot be read."""
    try:
        return datetime.fromisoformat(text.strip().rstrip("Z")[:26])
    except ValueError:
        return None


def beaconing_signal(times):
    """Regular gaps between connections. `times` is a list of time texts.
    Needs BEACON_MIN_COUNT readable times. Fires when the largest gap minus
    the smallest gap is within BEACON_MAX_SPREAD of the mean gap.
    """
    moments = []
    for text in times:
        moment = parse_time(text)
        if moment is not None:
            moments.append(moment)
    if len(moments) < BEACON_MIN_COUNT:
        return []

    moments.sort()
    gaps = []
    for index in range(1, len(moments)):
        gaps.append((moments[index] - moments[index - 1]).total_seconds())
    mean = sum(gaps) / len(gaps)
    if mean < BEACON_MIN_MEAN_GAP:
        return []

    if max(gaps) - min(gaps) <= BEACON_MAX_SPREAD * mean:
        return [(WEIGHT_BEACONING,
                 "regular timing: %d connections about %.0f s apart"
                 % (len(moments), mean))]
    return []
