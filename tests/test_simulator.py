import pytest
from parser_studio.simulator import simulate, test_against_library, _recognizer_matches
from parser_studio.generator import generate_parser
from parser_studio.db import init_db, save_parser

META  = {"name": "T", "vendor": "V", "model": "M", "version": "ANY", "anchor": "SENTINEL_TAG"}
META2 = {"name": "T2", "vendor": "V2", "model": "M2", "version": "ANY", "anchor": "OTHER_TAG"}
MAPPINGS = {"threatInfo.threatName": "msg", "accountName": "customer"}

SAMPLE_HIT = ('Jul 23 00:33:28 2025 host 1.2.3.4 SENTINEL_TAG: '
              '{"threatInfo":{"threatName":"Mimikatz"},"accountName":"LabCorp"}')
SAMPLE_MISS = ('Jul 23 00:33:28 2025 host 1.2.3.4 OTHER_TAG: '
               '{"id":"abc","type":"firewall"}')

# === single-parser simulate ===

def test_simulate_extracts_fields():
    xml_str = generate_parser(META, MAPPINGS, "syslog+json", [SAMPLE_HIT])
    results = simulate(xml_str, [SAMPLE_HIT])
    assert results[0]["fields"]["msg"] == "Mimikatz"
    assert results[0]["fields"]["customer"] == "LabCorp"

def test_simulate_sets_device_time():
    xml_str = generate_parser(META, MAPPINGS, "syslog+json", [SAMPLE_HIT])
    assert "deviceTime" in simulate(xml_str, [SAMPLE_HIT])[0]["fields"]

def test_simulate_event_type_and_severity():
    xml_str = generate_parser(META, MAPPINGS, "syslog+json", [SAMPLE_HIT])
    r = simulate(xml_str, [SAMPLE_HIT])[0]
    assert r["fields"].get("eventType") == "T-Event"
    assert r["fields"].get("eventSeverity") == "5"
    assert r["status"] == "pass"

def test_simulate_multiple_samples():
    xml_str = generate_parser(META, MAPPINGS, "syslog+json", [SAMPLE_HIT])
    assert len(simulate(xml_str, [SAMPLE_HIT, SAMPLE_HIT])) == 2

# === recognizer matching ===

def test_recognizer_matches_hit():
    xml_str = generate_parser(META, MAPPINGS, "syslog+json", [SAMPLE_HIT])
    assert _recognizer_matches(xml_str, SAMPLE_HIT) is True

def test_recognizer_matches_miss():
    xml_str = generate_parser(META, MAPPINGS, "syslog+json", [SAMPLE_HIT])
    assert _recognizer_matches(xml_str, SAMPLE_MISS) is False

# === library mode ===

def test_library_total_enabled(tmp_db):
    init_db(tmp_db)
    xml1 = generate_parser(META,  MAPPINGS, "syslog+json", [])
    xml2 = generate_parser(META2, {}, "syslog+json", [])
    save_parser(tmp_db, {"name":"T",  "scope":"enabled",  "parser_type":"User",
                         "vendor":"V", "model":"M", "version":"ANY",
                         "xml_content":xml1, "source":"studio", "file_path":None})
    save_parser(tmp_db, {"name":"T2", "scope":"disabled", "parser_type":"User",
                         "vendor":"V2","model":"M2","version":"ANY",
                         "xml_content":xml2, "source":"studio", "file_path":None})
    result = test_against_library([SAMPLE_HIT], tmp_db)
    assert result["total_enabled"] == 1   # disabled parser not counted

def test_library_first_match_wins(tmp_db):
    init_db(tmp_db)
    xml1 = generate_parser(META,  MAPPINGS, "syslog+json", [])
    xml2 = generate_parser(META2, {}, "syslog+json", [])
    save_parser(tmp_db, {"name":"T",  "scope":"enabled", "parser_type":"User",
                         "vendor":"V", "model":"M","version":"ANY",
                         "xml_content":xml1,"source":"studio","file_path":None})
    save_parser(tmp_db, {"name":"T2", "scope":"enabled", "parser_type":"User",
                         "vendor":"V2","model":"M2","version":"ANY",
                         "xml_content":xml2,"source":"studio","file_path":None})
    result = test_against_library([SAMPLE_HIT], tmp_db)
    sample_res = result["per_sample"][0]
    assert sample_res["first_match"] == "T"
    assert sample_res["matched_count"] == 1

def test_library_pass_fail_status(tmp_db):
    init_db(tmp_db)
    xml1 = generate_parser(META, MAPPINGS, "syslog+json", [])
    save_parser(tmp_db, {"name":"T", "scope":"enabled", "parser_type":"User",
                         "vendor":"V","model":"M","version":"ANY",
                         "xml_content":xml1,"source":"studio","file_path":None})
    result = test_against_library([SAMPLE_HIT], tmp_db)
    hit_parser = result["per_sample"][0]["parsers"][0]
    assert hit_parser["matched"] is True
    assert hit_parser["status"] == "pass"
    assert hit_parser["fields"].get("msg") == "Mimikatz"

def test_library_unmatched_shows_skip(tmp_db):
    init_db(tmp_db)
    xml1 = generate_parser(META, MAPPINGS, "syslog+json", [])
    save_parser(tmp_db, {"name":"T","scope":"enabled","parser_type":"User",
                         "vendor":"V","model":"M","version":"ANY",
                         "xml_content":xml1,"source":"studio","file_path":None})
    result = test_against_library([SAMPLE_MISS], tmp_db)
    parser_row = result["per_sample"][0]["parsers"][0]
    assert parser_row["matched"] is False
    assert parser_row["status"] == "skip"
    assert parser_row["fields"] == {}
