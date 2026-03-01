from tests.conftest import SAMPLE_SYSLOG_JSON, SAMPLE_SYSLOG_KV, SAMPLE_PURE_JSON
from parser_studio.extractor import extract_fields, build_token_matrix

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


# === Token Matrix ===

def test_token_matrix_one_row_per_token():
    s1 = "Jan 15 10:00:00 host tag action=allow srcip=1.1.1.1"
    s2 = "Jan 16 11:00:00 host tag action=deny srcip=2.2.2.2"
    rows = build_token_matrix([s1, s2], "syslog+kv")
    names = [r["token"] for r in rows]
    assert "action" in names
    assert "srcip" in names

def test_token_matrix_values_per_sample():
    s1 = "Jan 15 10:00:00 host tag action=allow srcip=1.1.1.1"
    s2 = "Jan 16 11:00:00 host tag action=deny srcip=2.2.2.2"
    rows = build_token_matrix([s1, s2], "syslog+kv")
    action_row = next(r for r in rows if r["token"] == "action")
    assert action_row["values"] == ["allow", "deny"]

def test_token_matrix_consistent_flag():
    s1 = "Jan 15 10:00:00 host tag type=fw"
    s2 = "Jan 16 11:00:00 host tag type=fw"
    rows = build_token_matrix([s1, s2], "syslog+kv")
    type_row = next(r for r in rows if r["token"] == "type")
    assert type_row["consistent"] is True

def test_token_matrix_absent_token_is_empty_string():
    s1 = "Jan 15 10:00:00 host tag srcip=1.1.1.1 dstip=2.2.2.2"
    s2 = "Jan 16 11:00:00 host tag srcip=3.3.3.3"
    rows = build_token_matrix([s1, s2], "syslog+kv")
    dst_row = next(r for r in rows if r["token"] == "dstip")
    assert dst_row["values"][1] == ""  # absent in sample 2
    assert dst_row["consistent"] is True  # only one non-empty value
