from tests.conftest import SAMPLE_SYSLOG_JSON, SAMPLE_SYSLOG_KV, SAMPLE_PURE_JSON
from parser_studio.extractor import extract_fields

def test_extract_json_fields():
    fields = extract_fields([SAMPLE_SYSLOG_JSON], "syslog+json")
    assert "threatInfo.threatName" in fields
    assert "threatInfo.confidenceLevel" in fields
    assert "accountName" in fields
    assert "agentDetectionInfo.agentIp" in fields
    # Header fields should NOT appear in field list
    assert "_mon" not in fields

def test_extract_kv_fields():
    fields = extract_fields([SAMPLE_SYSLOG_KV], "syslog+kv")
    assert "srcip" in fields
    assert "dstip" in fields
    assert "action" in fields
    assert "proto" in fields

def test_extract_pure_json():
    fields = extract_fields([SAMPLE_PURE_JSON], "json")
    assert "srcIp" in fields
    assert "destIp" in fields
    assert "message" in fields

def test_fields_merged_across_samples():
    s1 = ('Jul 23 10:00:00 2025 h 1.2.3.4 TAG: {"fieldA":"v1"}')
    s2 = ('Jul 23 10:00:01 2025 h 1.2.3.4 TAG: {"fieldA":"v2","fieldB":"v3"}')
    fields = extract_fields([s1, s2], "syslog+json")
    assert "fieldA" in fields
    assert "fieldB" in fields

def test_optional_flag_for_missing_fields():
    s1 = ('Jul 23 10:00:00 2025 h 1.2.3.4 TAG: {"a":"1","b":"2"}')
    s2 = ('Jul 23 10:00:01 2025 h 1.2.3.4 TAG: {"a":"1"}')
    fields = extract_fields([s1, s2], "syslog+json")
    assert fields["a"]["optional"] is False
    assert fields["b"]["optional"] is True

def test_extract_xml_fields():
    sample = ('Jul 23 10:05:15 2025 host 1.2.3.4 FSM-WUA '
              '<Event><System><EventID>4624</EventID>'
              '<Channel>Security</Channel></System></Event>')
    fields = extract_fields([sample], "syslog+xml")
    assert "Event.System.EventID" in fields
    assert "Event.System.Channel" in fields
