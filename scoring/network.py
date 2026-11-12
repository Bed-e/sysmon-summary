"""Network signals: unexpected processes, unusual ports and beaconing timing.
"""

from datetime import datetime

from scoring.config import (BEACON_MAX_SPREAD, BEACON_MIN_COUNT,
    BEACON_MIN_MEAN_GAP, KNOWN_NETWORK_PROCESSES, NORMAL_PORTS,
    WEIGHT_BEACONING, WEIGHT_UNEXPECTED_PROCESS, WEIGHT_UNUSUAL_PORT)
from scoring.paths import name_without_exe


def network_signals(ip_events):
    """From the event 3 records for one IP (outbound only): a process that is
    not a known browser or updater, and an unusual port. Each fires once.
    """
    signals = []
    unexpected = ""
    odd_port = ""

    for event in ip_events:
        if event["Initiated"].strip().lower() == "false":
            continue
        image = event["Image"]
        if image != "" and name_without_exe(image) not in KNOWN_NETWORK_PROCESSES:
            unexpected = unexpected or image
        port = event["DestinationPort"].strip()
        if port != "" and port not in NORMAL_PORTS:
            odd_port = odd_port or port

    if unexpected:
        signals.append((WEIGHT_UNEXPECTED_PROCESS,
                        "connection from an unexpected process (%s)" % unexpected))
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
