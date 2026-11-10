"""Step 2: collect unique IOCs (IPs, DNS names, file hashes) from events.

Nothing is skipped or scored here. Skipping is filters.py (M2) and
ranking is scoring.py (M2). This step only de-duplicates and counts.

The result of collect_iocs looks like:
    {"ip":   {"8.8.8.8": record, ...},
     "dns":  {"example.com": record, ...},
     "hash": {"ab12...": record, ...},
     "stats": {"ipv6_seen": 0, ...}}

A record looks like:
    {"count": 4, "first_seen": "...", "last_seen": "...",
     "hosts": ["PC1"], "process_guids": ["{...}"]}
A hash record also has "algorithm" and "images" (every full file path
that ran with that hash).
"""

import ipaddress

from parse import parse_hashes

# Order of preference when an event carries more than one hash.
HASH_PREFERENCE = ["sha256", "sha1", "md5"]

# Length in hex characters of each hash type.
HASH_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64}


def collect_iocs(events):
    """Go through the events once and return the unique IOCs plus stats.

    - Event 3 (network connection) gives an IP. Not event 22 answers.
    - Event 22 (DNS query) gives a DNS name.
    - Event 1 (process created) gives one hash per file.
    - Every other event ID is ignored here (registry events stay in the
      event list for M2 and M4).
    """
    iocs = {
        "ip": {},
        "dns": {},
        "hash": {},
        "stats": {
            "ipv6_seen": 0,
            "event3_without_ipv4": 0,
            "event22_without_name": 0,
            "event1_without_hash": 0,
        },
    }
    stats = iocs["stats"]

    for event in events:
        event_id = event["event_id"]

        if event_id == 3:
            text = ip_from_event(event)
            ip = normalize_ip(text)
            if ip is not None:
                add_sighting(iocs["ip"], ip, event)
            elif ":" in text:
                stats["ipv6_seen"] += 1
            else:
                stats["event3_without_ipv4"] += 1

        elif event_id == 22:
            name = normalize_dns(event["QueryName"])
            if name is not None:
                add_sighting(iocs["dns"], name, event)
            else:
                stats["event22_without_name"] += 1

        elif event_id == 1:
            picked = pick_hash(parse_hashes(event["Hashes"]))
            if picked is not None:
                algorithm, value = picked
                record = add_sighting(iocs["hash"], value, event)
                record["algorithm"] = algorithm
                record.setdefault("images", [])
                add_unique(record["images"], event["Image"])
            else:
                stats["event1_without_hash"] += 1

    return iocs


def add_sighting(table, key, event):
    """Create the record for `key` if it is new, then update it with this
    event: count, first/last seen, hosts and ProcessGuids. Returns the record.
    """
    record = table.get(key)
    if record is None:
        record = {
            "count": 0,
            "first_seen": "",
            "last_seen": "",
            "hosts": [],
            "process_guids": [],
        }
        table[key] = record

    record["count"] += 1

    # Times are sortable text, so plain < and > work. "" is smaller than any time.
    time = event["time"]
    if time:
        if record["first_seen"] == "" or time < record["first_seen"]:
            record["first_seen"] = time
        if time > record["last_seen"]:
            record["last_seen"] = time

    add_unique(record["hosts"], event["computer"])
    add_unique(record["process_guids"], event["ProcessGuid"])
    return record


def add_unique(items, value):
    """Append value to the list if it is not empty and not already there."""
    if value and value not in items:
        items.append(value)


def ip_from_event(event):
    """Return the remote IP text of a network event (not yet checked).

    For an outbound connection the remote side is DestinationIp. Only an
    explicit Initiated=false means inbound, and then the remote side is
    SourceIp.
    """
    if event["Initiated"].strip().lower() == "false":
        return event["SourceIp"]
    return event["DestinationIp"]


def normalize_ip(text):
    """Return the IPv4 address as a clean string, or None.
    IPv6 and garbage both give None. This does not check whether the address
    is private; that is the filter's job (M2).
    """
    try:
        address = ipaddress.ip_address(text.strip())
    except ValueError:
        return None
    if address.version != 4:
        return None
    return str(address)


def normalize_dns(text):
    """Lowercase the name, strip spaces and one trailing dot.
    Returns None if nothing is left. Internal names are kept here; skipping
    them is the filter's job (M2).
    """
    name = text.strip().lower()
    if name.endswith("."):
        name = name[:-1]
    if name == "":
        return None
    return name


def pick_hash(hash_dict):
    """Pick one hash: sha256, then sha1, then md5.
    Returns (algorithm, value), or None if no valid hash is present.
    Other fields such as imphash are never used.
    """
    for algorithm in HASH_PREFERENCE:
        value = hash_dict.get(algorithm, "")
        if is_valid_hash(algorithm, value):
            return algorithm, value
    return None


def is_valid_hash(algorithm, value):
    """True if value has the right length for the algorithm and is all
    lowercase hex. This matches what the hash portal accepts.
    """
    if len(value) != HASH_LENGTHS.get(algorithm, -1):
        return False
    return all(character in "0123456789abcdef" for character in value)
