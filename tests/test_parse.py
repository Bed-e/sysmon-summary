"""Tests for parse.py. Events are small hand-written XML strings, so the
rules are tested against the Sysmon schema, not against any sample dump.
"""

import xml.etree.ElementTree as ET

import pytest

from parse import (
    NS_URL,
    get_data_fields,
    get_system_fields,
    keep_wanted_fields,
    parse_hashes,
    parse_record,
)


def make_xml(event_id, data, time="2024-05-01 10:00:00.123456", computer="PC1"):
    """Build the XML text of one event, shaped like python-evtx output."""
    data_xml = ""
    for name, value in data.items():
        data_xml += '<Data Name="%s">%s</Data>' % (name, value)
    return (
        '<Event xmlns="%s"><System><EventID>%s</EventID>'
        '<TimeCreated SystemTime="%s"/><Computer>%s</Computer></System>'
        "<EventData>%s</EventData></Event>"
    ) % (NS_URL, event_id, time, computer, data_xml)


# ---- parse_hashes ----

def test_parse_hashes_splits_and_lowercases():
    result = parse_hashes("SHA1=AB12,MD5=CD34,SHA256=EF56")
    assert result == {"sha1": "ab12", "md5": "cd34", "sha256": "ef56"}


def test_parse_hashes_empty_gives_empty_dict():
    assert parse_hashes("") == {}


def test_parse_hashes_skips_piece_without_equals():
    assert parse_hashes("garbage,MD5=ab") == {"md5": "ab"}


# ---- get_system_fields / get_data_fields ----

def test_get_system_fields_reads_id_time_computer():
    root = ET.fromstring(make_xml(3, {}, time="2024-01-02 03:04:05", computer="HOST9"))
    assert get_system_fields(root) == {
        "event_id": 3,
        "time": "2024-01-02 03:04:05",
        "computer": "HOST9",
    }


def test_get_system_fields_missing_time_and_computer_are_empty():
    xml = '<Event xmlns="%s"><System><EventID>1</EventID></System></Event>' % NS_URL
    fields = get_system_fields(ET.fromstring(xml))
    assert fields == {"event_id": 1, "time": "", "computer": ""}


def test_get_data_fields_empty_element_is_empty_string():
    xml = (
        '<Event xmlns="%s"><EventData><Data Name="A">x</Data>'
        '<Data Name="B"/></EventData></Event>' % NS_URL
    )
    assert get_data_fields(ET.fromstring(xml)) == {"A": "x", "B": ""}


def test_get_data_fields_no_event_data_gives_empty_dict():
    xml = '<Event xmlns="%s"><System/></Event>' % NS_URL
    assert get_data_fields(ET.fromstring(xml)) == {}


# ---- keep_wanted_fields ----

def test_keep_wanted_fields_drops_extras_and_fills_missing():
    kept = keep_wanted_fields(11, {"Image": "a.exe", "TargetFilename": "b.txt", "Other": "z"})
    assert kept == {"Image": "a.exe", "ProcessGuid": "", "TargetFilename": "b.txt"}


# ---- parse_record ----

def test_parse_record_keeps_wanted_event():
    xml = make_xml(22, {"QueryName": "example.com", "QueryStatus": "0", "Image": "c.exe"})
    event_id, event = parse_record(xml)
    assert event_id == 22
    assert event["event_id"] == 22
    assert event["computer"] == "PC1"
    assert event["QueryName"] == "example.com"
    assert event["ProcessGuid"] == ""  # not in the event, filled with ""


def test_parse_record_drops_unwanted_id_but_reports_it():
    event_id, event = parse_record(make_xml(5, {"Image": "x.exe"}))
    assert event_id == 5
    assert event is None


@pytest.mark.parametrize("event_id", [12, 13, 14])
def test_parse_record_keeps_registry_events(event_id):
    xml = make_xml(event_id, {"TargetObject": "HKLM\\Software\\X", "Image": "p.exe"})
    _, event = parse_record(xml)
    assert event["TargetObject"] == "HKLM\\Software\\X"


def test_parse_record_broken_xml_raises():
    with pytest.raises(Exception):
        parse_record("<Event><not closed")


def test_parse_record_without_event_id_raises():
    xml = '<Event xmlns="%s"><System/></Event>' % NS_URL
    with pytest.raises(Exception):
        parse_record(xml)
