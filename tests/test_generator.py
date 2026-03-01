import xml.etree.ElementTree as ET
from parser_studio.generator import generate_parser

BASIC_META = {
    "name": "TestParser", "scope": "enabled", "parser_type": "User",
    "vendor": "Acme", "model": "Firewall", "version": "ANY",
    "anchor": "ACME_FW",
}

BASIC_MAPPINGS = {
    "srcip": "srcIpAddr",
    "dstip": "destIpAddr",
    "action": "eventAction",
}

def test_generates_valid_xml():
    xml_str = generate_parser(BASIC_META, BASIC_MAPPINGS, "syslog+kv", [])
    # Must parse without error
    ET.fromstring(xml_str)

def test_has_event_parser_root():
    xml_str = generate_parser(BASIC_META, BASIC_MAPPINGS, "syslog+kv", [])
    root = ET.fromstring(xml_str)
    assert root.tag == "eventParser"
    assert root.attrib["name"] == "TestParser"

def test_has_device_type():
    xml_str = generate_parser(BASIC_META, BASIC_MAPPINGS, "syslog+kv", [])
    root = ET.fromstring(xml_str)
    vendor = root.find(".//Vendor")
    assert vendor is not None and vendor.text == "Acme"

def test_json_format_uses_correct_extraction():
    xml_str = generate_parser(BASIC_META, {"threatName": "msg"}, "syslog+json", [])
    assert "collectAndSetAttrByJSON" in xml_str

def test_kv_format_uses_correct_extraction():
    xml_str = generate_parser(BASIC_META, BASIC_MAPPINGS, "syslog+kv", [])
    assert "collectAndSetAttrByKeyValuePair" in xml_str

def test_xml_format_uses_xpath():
    xml_str = generate_parser(BASIC_META, {"Event.System.EventID": "winEventId"}, "syslog+xml", [])
    assert "collectFieldsByXPath" in xml_str

def test_no_double_dash_in_comments():
    xml_str = generate_parser(BASIC_META, BASIC_MAPPINGS, "syslog+kv", [])
    import re
    assert not re.search(r'<!--.*?--.*?-->', xml_str)

def test_has_event_severity_default():
    xml_str = generate_parser(BASIC_META, BASIC_MAPPINGS, "syslog+kv", [])
    assert 'attr="eventSeverity"' in xml_str

def test_has_event_type():
    xml_str = generate_parser(BASIC_META, BASIC_MAPPINGS, "syslog+kv", [])
    assert 'attr="eventType"' in xml_str
