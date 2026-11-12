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
"""

import math
from datetime import datetime

from iocs import ip_from_event, normalize_ip

# ---- Weights (placeholders, tune freely) ----
WEIGHT_USER_WRITABLE_PATH = 20
WEIGHT_DOUBLE_EXTENSION = 50  # disguise has no benign use: heaviest single signal
WEIGHT_ODD_PARENT = 25
WEIGHT_REGISTRY_AUTORUN = 40
WEIGHT_FAILED_LOOKUPS = 15
WEIGHT_UNEXPECTED_PROCESS = 20
WEIGHT_UNUSUAL_PORT = 10
WEIGHT_BEACONING = 25
WEIGHT_ODD_DNS_LABEL = 20
WEIGHT_LOOKALIKE = 30
WEIGHT_REGISTRY_REFERENCE = 40
WEIGHT_TRUSTED_PATH = -15

# ---- Thresholds (placeholders) ----
FAILED_LOOKUP_MIN = 5          # failed lookups by one process
LONG_LABEL_LENGTH = 30         # a DNS label this long is odd
ENTROPY_MIN_LENGTH = 12        # entropy is only judged on labels this long
ENTROPY_THRESHOLD = 3.5        # bits per character
LOOKALIKE_MAX_DISTANCE = 2     # edits away from a well-known name
BEACON_MIN_COUNT = 5           # connections needed to judge timing
BEACON_MIN_MEAN_GAP = 1.0      # seconds; faster than this is just a busy link
BEACON_MAX_SPREAD = 0.2        # (largest gap - smallest gap) / mean gap

# ---- Lists (lowercase) ----
# One definition of "user-writable", used by path_signals and rule 3 of
# parent_child_signal.
USER_WRITABLE_MARKERS = ["\\temp\\", "\\downloads\\", "\\users\\"]

# A double extension is a document/media name followed by an executable one.
DECOY_EXTENSIONS = ["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt",
                    "rtf", "jpg", "jpeg", "png", "gif", "mp3", "mp4", "avi",
                    "zip"]
EXECUTABLE_EXTENSIONS = ["exe", "scr", "com", "bat", "cmd", "js", "vbs", "ps1"]

# Names (without .exe) that make outbound connections as a normal job.
KNOWN_NETWORK_PROCESSES = ["chrome", "msedge", "firefox", "iexplore", "brave",
                           "opera", "googleupdate", "microsoftedgeupdate"]

DOCUMENT_VIEWERS = ["winword", "excel", "powerpnt", "outlook", "acrord32",
                    "acrobat", "foxitreader"]
SCRIPT_HOSTS = ["cmd", "powershell", "wscript", "cscript", "mshta"]

# A registry key containing one of these is an autorun location.
AUTORUN_MARKERS = ["\\currentversion\\run",
                   "\\windows nt\\currentversion\\winlogon\\shell",
                   "\\windows nt\\currentversion\\winlogon\\userinit"]

# Image File Execution Options is only a hijack when a Debugger value is
# set (other values there, such as AuditLevel, are normal settings).
IFEO_MARKER = "\\image file execution options\\"
IFEO_HIJACK_VALUE = "\\debugger"

NORMAL_PORTS = ["80", "443", "53"]
REGISTRY_EVENT_IDS = [12, 13, 14]


# ---- Small helpers ----

def lower_path(path):
    """Lowercase a path and use backslashes, so matching is predictable."""
    return path.lower().replace("/", "\\")


def file_name(path):
    """Lowercased last part of a path: 'C:\\A\\Word.EXE' gives 'word.exe'."""
    return lower_path(path).split("\\")[-1]


def name_without_exe(path):
    """Like file_name but without a trailing .exe: 'winword'."""
    name = file_name(path)
    if name.endswith(".exe"):
        name = name[:-4]
    return name


def is_user_writable(path):
    """True if the lowercased path contains a user-writable marker."""
    lowered = lower_path(path)
    return any(marker in lowered for marker in USER_WRITABLE_MARKERS)


def is_registry_write(event):
    """True for a registry event (12, 13, 14) that is not a delete."""
    if event["event_id"] not in REGISTRY_EVENT_IDS:
        return False
    return not event.get("EventType", "").lower().startswith("delete")


# ---- Process-level signals ----

def path_signals(path):
    """User-writable location and double extension (e.g. report.pdf.exe)."""
    signals = []
    if path == "":
        return signals

    if is_user_writable(path):
        signals.append((WEIGHT_USER_WRITABLE_PATH,
                        "file runs from a user-writable path (%s)" % path))

    parts = file_name(path).split(".")
    if len(parts) >= 3 and parts[-1] in EXECUTABLE_EXTENSIONS \
            and parts[-2] in DECOY_EXTENSIONS:
        signals.append((WEIGHT_DOUBLE_EXTENSION,
                        "double extension (.%s.%s)" % (parts[-2], parts[-1])))
    return signals


def parent_child_signal(parent_image, image):
    """Odd parent-to-child pairs. Matches on lowercased file names.
    1. A document viewer / Office app starts any .exe or a script host.
    2. explorer.exe starts something from a Temp folder.
    3. services.exe starts something from a user-writable path.
    An empty parent or child fires nothing.
    """
    if parent_image == "" or image == "":
        return []

    parent = name_without_exe(parent_image)
    child_file = file_name(image)
    child = name_without_exe(image)
    shown = "%s -> %s" % (file_name(parent_image), child_file)
    signals = []

    if parent in DOCUMENT_VIEWERS and (child_file.endswith(".exe")
                                       or child in SCRIPT_HOSTS):
        signals.append((WEIGHT_ODD_PARENT,
                        "document app started a program (%s)" % shown))
    elif parent == "explorer" and "\\temp\\" in lower_path(image):
        signals.append((WEIGHT_ODD_PARENT,
                        "explorer started a program from Temp (%s)" % shown))
    elif parent == "services" and is_user_writable(image):
        signals.append((WEIGHT_ODD_PARENT,
                        "service started a program from a user-writable "
                        "path (%s)" % shown))
    return signals


def registry_persistence_signal(event):
    """A registry write (not a delete) to an autorun location."""
    if not is_registry_write(event):
        return []
    key = event["TargetObject"].lower()
    is_autorun = any(marker in key for marker in AUTORUN_MARKERS)
    is_ifeo_hijack = IFEO_MARKER in key and key.endswith(IFEO_HIJACK_VALUE)
    if is_autorun or is_ifeo_hijack:
        return [(WEIGHT_REGISTRY_AUTORUN,
                 "writes an autorun registry key (%s)" % event["TargetObject"])]
    return []


def failed_lookup_signal(count):
    """A burst of failed DNS lookups from one process."""
    if count >= FAILED_LOOKUP_MIN:
        return [(WEIGHT_FAILED_LOOKUPS,
                 "%d failed DNS lookups from one process" % count)]
    return []


def build_process_scores(events):
    """Score every ProcessGuid once. Returns
        {guid: {"image": path, "signals": [(points, reason)], "score": int}}
    Path comes from any event with that guid, the parent pair from event 1,
    autorun from registry events, failed lookups from event 22. Each kind is
    counted once per process.
    """
    table = {}
    path_done = set()
    parent_done = set()
    registry_done = set()
    failures = {}

    for event in events:
        guid = event.get("ProcessGuid", "")
        if guid == "":
            continue
        entry = table.setdefault(guid, {"image": event.get("Image", ""),
                                        "signals": [], "score": 0})
        if entry["image"] == "":
            entry["image"] = event.get("Image", "")

        if guid not in path_done and event.get("Image", "") != "":
            path_done.add(guid)
            entry["signals"].extend(path_signals(event["Image"]))

        if event["event_id"] == 1 and guid not in parent_done:
            parent_done.add(guid)
            entry["signals"].extend(
                parent_child_signal(event["ParentImage"], event["Image"]))

        if guid not in registry_done:
            found = registry_persistence_signal(event)
            if found:
                registry_done.add(guid)
                entry["signals"].extend(found)

        if event["event_id"] == 22 and event["QueryStatus"] not in ("", "0"):
            failures[guid] = failures.get(guid, 0) + 1

    for guid, count in failures.items():
        table[guid]["signals"].extend(failed_lookup_signal(count))

    for entry in table.values():
        entry["score"] = sum(points for points, reason in entry["signals"])
    return table


# ---- IP signals ----

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


# ---- DNS signals ----

def entropy(text):
    """Shannon entropy in bits per character. Empty text gives 0.0."""
    if text == "":
        return 0.0
    total = len(text)
    result = 0.0
    for character in set(text):
        share = text.count(character) / total
        result -= share * math.log2(share)
    return result


def levenshtein(a, b):
    """Fewest single-character edits (insert, delete, replace) from a to b."""
    previous = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        current = [i]
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            current.append(min(previous[j] + 1,
                               current[j - 1] + 1,
                               previous[j - 1] + cost))
        previous = current
    return previous[len(b)]


def dns_signals(name, well_known):
    """A very long or high-entropy label, and a lookalike of a well-known
    name. The lookalike check compares the last two labels and ignores real
    well-known names and their subdomains.
    """
    signals = []
    labels = name.split(".")

    for label in labels:
        if len(label) >= LONG_LABEL_LENGTH:
            signals.append((WEIGHT_ODD_DNS_LABEL,
                            "very long label (%d characters)" % len(label)))
            break
        if len(label) >= ENTROPY_MIN_LENGTH and entropy(label) >= ENTROPY_THRESHOLD:
            signals.append((WEIGHT_ODD_DNS_LABEL,
                            "high-entropy label (%s)" % label))
            break

    genuine = any(name == known or name.endswith("." + known)
                  for known in well_known)
    if not genuine:
        registered = ".".join(labels[-2:])
        for known in well_known:
            if levenshtein(registered, known) <= LOOKALIKE_MAX_DISTANCE:
                signals.append((WEIGHT_LOOKALIKE,
                                "looks like %s" % known))
                break
    return signals


# ---- Hash signals ----

def hash_persistence_signal(images, registry_events, own_guids=()):
    """A registry write to an autorun location (the same test as
    registry_persistence_signal) whose TargetObject or Details contains the
    file's full path (lowercased plain substring). A bare filename never
    matches, and neither does a path that merely appears in some other key
    (for example a Windows application inventory entry).
    Writes made by the file's own processes (`own_guids`) are ignored: a
    process that sets its own autorun key is already scored once as a
    process-level signal, so counting it here would be the same evidence
    twice.
    """
    for image in images:
        needle = lower_path(image)
        if needle == "":
            continue
        for event in registry_events:
            if not registry_persistence_signal(event):
                continue
            if event["ProcessGuid"] in own_guids:
                continue
            text = lower_path(event["TargetObject"] + " " + event.get("Details", ""))
            if needle in text:
                return [(WEIGHT_REGISTRY_REFERENCE,
                         "registry references this file's path (%s)" % image)]
    return []


def trusted_path_adjustment(images, trusted_paths):
    """Take points off when EVERY path for the hash is in a protected
    location. Weak evidence: it only lowers the order.
    """
    if not images or not trusted_paths:
        return []
    for image in images:
        lowered = image.lower()
        if not any(lowered.startswith(prefix) for prefix in trusted_paths):
            return []
    return [(WEIGHT_TRUSTED_PATH,
             "all copies run from protected system paths (weak evidence)")]


# ---- Putting it together ----

def score_ioc(item, process_scores, ip_events, registry_events, config):
    """Score one IOC. Returns (score, reasons) where reasons is a list of
    text like '+25 document app started a program (...)'.
    """
    ioc_type = item["type"]
    value = item["value"]
    record = item["record"]
    signals = []

    if ioc_type == "ip":
        events = ip_events.get(value, [])
        signals.extend(network_signals(events))
        signals.extend(beaconing_signal([event["time"] for event in events]))
    elif ioc_type == "dns":
        signals.extend(dns_signals(value, config["well_known"]))
    elif ioc_type == "hash":
        images = record.get("images", [])
        signals.extend(hash_persistence_signal(images, registry_events,
                                               record["process_guids"]))
        signals.extend(trusted_path_adjustment(images, config["trusted_paths"]))

    # Inherit from the single highest-scoring process that touched it.
    best = None
    for guid in record["process_guids"]:
        process = process_scores.get(guid)
        if process is not None and (best is None or process["score"] > best["score"]):
            best = process
    if best is not None:
        who = file_name(best["image"]) or "unknown process"
        for points, reason in best["signals"]:
            signals.append((points, "process %s: %s" % (who, reason)))

    score = sum(points for points, reason in signals)
    reasons = ["%+d %s" % (points, reason) for points, reason in signals]
    return score, reasons


def group_ip_events(events):
    """Group event 3 records by their remote IPv4: {ip: [events]}."""
    table = {}
    for event in events:
        if event["event_id"] != 3:
            continue
        ip = normalize_ip(ip_from_event(event))
        if ip is not None:
            table.setdefault(ip, []).append(event)
    return table


def rank_iocs(to_rank, events, config):
    """Score every IOC in `to_rank` and return them highest score first
    (ties: more sightings first, then earliest first seen).
    """
    process_scores = build_process_scores(events)
    ip_events = group_ip_events(events)
    registry_events = [e for e in events if e["event_id"] in REGISTRY_EVENT_IDS]

    ranked = []
    for item in to_rank:
        score, reasons = score_ioc(item, process_scores, ip_events,
                                   registry_events, config)
        ranked.append({
            "type": item["type"],
            "value": item["value"],
            "score": score,
            "reasons": reasons,
            "record": item["record"],
        })

    ranked.sort(key=lambda r: (-r["score"], -r["record"]["count"],
                               r["record"]["first_seen"]))
    return ranked
