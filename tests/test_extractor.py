from tests.conftest import SAMPLE_SYSLOG_JSON, SAMPLE_SYSLOG_KV, SAMPLE_PURE_JSON
from parser_studio.extractor import extract_fields, build_token_matrix, build_whitespace_matrix

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

def test_syslog_text_access_log_extracts_named_fields():
    sample = (
        "<142>Sep 17 13:27:37 example.com ApacheLog "
        '192.168.20.35 - - [17/Sep/2009:13:27:37 -0700] '
        '"GET /icons/apache_pb2.gif HTTP/1.1" 200 2414'
    )
    fields = extract_fields([sample], "syslog+text")
    assert "client_ip" in fields
    assert "request" in fields
    assert "status_code" in fields
    assert "_token0" not in fields   # no positional tokens


def test_syslog_text_error_log_extracts_named_fields():
    sample = (
        "<182>Mar 22 19:00:14 lab1.example.com Apache_ErrorLog: "
        "[Tue Mar 22 16:17:41.711593 2022] [proxy_http:error] "
        "[pid 12345] Connection refused"
    )
    fields = extract_fields([sample], "syslog+text")
    assert "log_level" in fields
    assert "message" in fields
    assert "_token0" not in fields


def test_syslog_text_access_log_with_leading_code():
    """FortiSIEM sometimes inserts a numeric code before the client IP."""
    sample = (
        "<142>Sep 17 13:27:37 example.com ApacheLog 0 "
        '192.168.20.35 - - [17/Sep/2009:13:27:37 -0700] '
        '"GET /index.html HTTP/1.1" 404 512'
    )
    fields = extract_fields([sample], "syslog+text")
    assert "client_ip" in fields
    assert fields["client_ip"]["values"][0] == "192.168.20.35"


def test_whitespace_matrix_splits_by_whitespace():
    s1 = "Jul 23 10:05:15  host  1.2.3.4"   # double spaces
    s2 = "Jul\t24\t10:06:00\thost\t5.6.7.8"  # tabs
    rows = build_whitespace_matrix([s1, s2])
    tokens = [r['token'] for r in rows]
    assert 'tok_0' in tokens
    assert 'tok_4' in tokens   # 5 tokens per sample
    assert len(rows) == 5


def test_whitespace_matrix_per_sample_values():
    s1 = "Jul 23 10:05:15 host 1.2.3.4"
    s2 = "Aug 24 11:06:00 host 5.6.7.8"
    rows = build_whitespace_matrix([s1, s2])
    tok4 = next(r for r in rows if r['token'] == 'tok_4')
    assert tok4['values'] == ['1.2.3.4', '5.6.7.8']
    assert tok4['consistent'] is False


def test_whitespace_matrix_consistent_flag():
    s1 = "Jul 23 10:05:15 web01 1.2.3.4"
    s2 = "Aug 24 11:06:00 web01 5.6.7.8"
    rows = build_whitespace_matrix([s1, s2])
    hostname_row = next(r for r in rows if r['token'] == 'tok_3')
    assert hostname_row['values'] == ['web01', 'web01']
    assert hostname_row['consistent'] is True


def test_whitespace_matrix_empty_samples():
    assert build_whitespace_matrix([]) == []
    assert build_whitespace_matrix(['', '  ']) == []


def test_whitespace_matrix_unequal_lengths():
    s1 = "Jul 23 10:05:15 host"
    s2 = "Jul 23 10:05:15 host extra_token"
    rows = build_whitespace_matrix([s1, s2])
    tok4 = next(r for r in rows if r['token'] == 'tok_4')
    assert tok4['values'] == ['', 'extra_token']


def test_token_matrix_absent_token_is_empty_string():
    s1 = "Jan 15 10:00:00 host tag srcip=1.1.1.1 dstip=2.2.2.2"
    s2 = "Jan 16 11:00:00 host tag srcip=3.3.3.3"
    rows = build_token_matrix([s1, s2], "syslog+kv")
    dst_row = next(r for r in rows if r["token"] == "dstip")
    assert dst_row["values"][1] == ""  # absent in sample 2
    assert dst_row["consistent"] is True  # only one non-empty value
