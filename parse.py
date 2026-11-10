"""Step 1: read a Sysmon .evtx file and return a list of event dicts.

Only Sysmon event IDs 1, 3, 11, 12, 13, 14 and 22 are kept. Every other
ID is counted and dropped.

An event dict looks like:
    {"event_id": 3, "time": "...", "computer": "...", "Image": "...", ...}
Fields keep Sysmon's own names. A field the event does not carry is "".
"""

import xml.etree.ElementTree as ET

from Evtx.Evtx import Evtx

# Windows event XML lives in this namespace. Every lookup below uses it.
NS_URL = "http://schemas.microsoft.com/win/2004/08/events/event"
NS = {"e": NS_URL}

# The fields we keep for each event ID. This is the one place to edit
# if a later milestone needs another field.
WANTED_FIELDS = {
    # process created
    1: ["Image", "CommandLine", "ParentImage", "ParentCommandLine",
        "ProcessGuid", "ParentProcessGuid", "User", "Hashes",
        "CurrentDirectory"],
    # network connection
    3: ["Image", "ProcessGuid", "User", "Protocol", "Initiated",
        "SourceIp", "SourcePort", "DestinationIp", "DestinationHostname",
        "DestinationPort"],
    # file created
    11: ["Image", "ProcessGuid", "TargetFilename"],
    # registry: object created/deleted, value set, key/value renamed
    12: ["EventType", "Image", "ProcessGuid", "TargetObject"],
    13: ["EventType", "Image", "ProcessGuid", "TargetObject", "Details"],
    14: ["EventType", "Image", "ProcessGuid", "TargetObject", "NewName"],
    # DNS query
    22: ["Image", "ProcessGuid", "QueryName", "QueryStatus", "QueryResults"],
}


def read_events(path):
    """Read an .evtx file and return a dict:
        {"events": [event dicts],
         "dropped_counts": {event_id: how many were dropped},
         "error_count": records that could not be parsed,
         "total": every record in the file}
    kept + dropped + errors always adds up to total.
    """
    events = []
    dropped_counts = {}
    error_count = 0
    total = 0

    with Evtx(path) as log:
        for record in log.records():
            total += 1
            try:
                event_id, event = parse_record(record.xml())
            except Exception:
                # One damaged record must not stop the whole run.
                error_count += 1
                continue

            if event is None:
                dropped_counts[event_id] = dropped_counts.get(event_id, 0) + 1
            else:
                events.append(event)

    return {
        "events": events,
        "dropped_counts": dropped_counts,
        "error_count": error_count,
        "total": total,
    }


def parse_record(xml_text):
    """Turn one record's XML into (event_id, event_dict).
    event_dict is None when we do not keep that event ID.
    Raises an error if the XML is broken or has no EventID.
    """
    root = ET.fromstring(xml_text)
    system = get_system_fields(root)
    event_id = system["event_id"]

    # Stop early for IDs we do not want. This keeps big dumps fast.
    if event_id not in WANTED_FIELDS:
        return event_id, None

    data = get_data_fields(root)
    event = dict(system)
    event.update(keep_wanted_fields(event_id, data))
    return event_id, event


def get_system_fields(root):
    """Read EventID, time and computer from the <System> block."""
    event_id_element = root.find("e:System/e:EventID", NS)
    time_element = root.find("e:System/e:TimeCreated", NS)
    computer_element = root.find("e:System/e:Computer", NS)

    time = ""
    if time_element is not None:
        time = time_element.get("SystemTime", "")

    computer = ""
    if computer_element is not None and computer_element.text:
        computer = computer_element.text.strip()

    return {
        "event_id": int(event_id_element.text),
        "time": time,
        "computer": computer,
    }


def get_data_fields(root):
    """Read every <Data Name="x">value</Data> into {"x": "value"}.
    An empty element becomes "".
    """
    data = {}
    for element in root.findall("e:EventData/e:Data", NS):
        name = element.get("Name")
        if name:
            data[name] = element.text or ""
    return data


def keep_wanted_fields(event_id, data):
    """Keep only the fields listed for this event ID.
    A wanted field that is missing is set to "" so later code can always
    read the key.
    """
    kept = {}
    for name in WANTED_FIELDS[event_id]:
        kept[name] = data.get(name, "")
    return kept


def parse_hashes(text):
    """Turn Sysmon's Hashes string into a dict of lowercase names and values.

    "SHA1=AB12,MD5=CD34" becomes {"sha1": "ab12", "md5": "cd34"}.
    Empty or malformed input gives {} or skips the bad piece.
    """
    result = {}
    for piece in text.split(","):
        if "=" not in piece:
            continue
        name, value = piece.split("=", 1)
        result[name.strip().lower()] = value.strip().lower()
    return result
