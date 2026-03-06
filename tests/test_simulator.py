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


# === context propagation (when/choose inherit parent attrs) ===

_APACHE_SAMPLE = (
    '192.168.5.142 - admin [04/Mar/2026:02:12:45 +0530] '
    '"POST /wp-login.php HTTP/1.1" 401 381 "-" '
    '"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"'
)
_APACHE_DASH_USER = (
    '192.168.5.142 - - [04/Mar/2026:02:12:45 +0530] '
    '"GET /index.html HTTP/1.1" 200 512 "-" '
    '"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"'
)
_APACHE_META = {
    "name": "ApacheAccess", "scope": "enabled", "parser_type": "User",
    "vendor": "Apache", "model": "HTTP", "version": "ANY", "anchor": "",
}
_APACHE_MAPPINGS = {
    "srcIpAddr": "srcIpAddr",
    "httpMethod": "httpMethod",
    "uriStem": "uriStem",
    "httpStatusCode": "httpStatusCode",
    "recvBytes64": "recvBytes64",
    "userAgent": "userAgent",
}


def test_when_inherits_switch_captures():
    """deviceTime must be set from _req_time captured by the switch case."""
    xml_str = generate_parser(_APACHE_META, _APACHE_MAPPINGS, "text", [_APACHE_SAMPLE])
    r = simulate(xml_str, [_APACHE_SAMPLE])[0]
    dt = r["fields"].get("deviceTime", "")
    # Should resolve to the actual timestamp string, not the literal '$_req_time'
    assert "$_req_time" not in dt, f"deviceTime still unresolved: {dt!r}"
    assert "04/Mar/2026" in dt or "02:12:45" in dt, f"deviceTime value unexpected: {dt!r}"


def test_when_skips_dash_authuser():
    """user EAT must not be set when authuser is '-' placeholder."""
    xml_str = generate_parser(_APACHE_META, _APACHE_MAPPINGS, "text", [_APACHE_DASH_USER])
    r = simulate(xml_str, [_APACHE_DASH_USER])[0]
    # user should be absent (authuser '-' is a placeholder, not a real user)
    assert "user" not in r["fields"], f"user unexpectedly set: {r['fields'].get('user')!r}"


def test_when_sets_real_authuser():
    """user EAT must be set when authuser is a real username (not '-')."""
    xml_str = generate_parser(_APACHE_META, _APACHE_MAPPINGS, "text", [_APACHE_SAMPLE])
    r = simulate(xml_str, [_APACHE_SAMPLE])[0]
    assert r["fields"].get("user") == "admin"


def test_todatetime_two_arg_form_resolves_variable():
    """toDateTime($var, "format") must return the resolved variable value, not 'format'."""
    from parser_studio.simulator import _apply_function
    attrs = {"_req_time": "04/Mar/2026:02:12:45 +0530"}
    result = _apply_function('toDateTime($_req_time, "dd/MMM/yyyy:HH:mm:ss Z")', attrs)
    assert result == "04/Mar/2026:02:12:45 +0530"
    assert "dd/MMM" not in result


def test_todatetime_multiarg_form_joins_components():
    """toDateTime(mon, day, year, time) must join the resolved components."""
    from parser_studio.simulator import _apply_function
    attrs = {"_mon": "Mar", "_day": "4", "_year": "2026", "_time": "02:12:45"}
    result = _apply_function("toDateTime($_mon, $_day, $_year, $_time)", attrs)
    assert "Mar" in result and "2026" in result and "02:12:45" in result


# === HTTP status code → conditional eventType ===

_HTTP_SAMPLES = [
    '192.168.5.142 - - [04/Mar/2026:02:12:45 +0530] "POST /wp-login.php HTTP/1.1" 401 381 "-" "Mozilla/5.0"',
    '192.168.5.143 - - [05/Mar/2026:08:30:00 +0530] "GET /index.html HTTP/1.1" 200 2048 "-" "Googlebot"',
    '10.0.0.5 - - [05/Mar/2026:09:00:00 +0000] "GET /robots.txt HTTP/1.1" 404 0 "-" "curl/7.0"',
    '10.0.0.6 - - [05/Mar/2026:10:00:00 +0000] "GET /redir HTTP/1.1" 301 0 "-" "curl/7.0"',
    '10.0.0.7 - - [05/Mar/2026:11:00:00 +0000] "GET /crash HTTP/1.1" 500 0 "-" "curl/7.0"',
]
_HTTP_META = {**_APACHE_META, "name": "WebLog"}
_HTTP_MAPPINGS = {
    "srcIpAddr": "srcIpAddr", "httpMethod": "httpMethod",
    "uriStem": "uriStem", "httpStatusCode": "httpStatusCode",
}


def test_simulator_401_gets_access_denied_eventtype():
    xml_str = generate_parser(_HTTP_META, _HTTP_MAPPINGS, "text", _HTTP_SAMPLES)
    r = simulate(xml_str, [_HTTP_SAMPLES[0]])[0]
    assert r["fields"].get("eventType") == "WebLog-Web-Access-Denied"
    assert r["fields"].get("eventSeverity") == "5"


def test_simulator_200_gets_success_eventtype():
    xml_str = generate_parser(_HTTP_META, _HTTP_MAPPINGS, "text", _HTTP_SAMPLES)
    r = simulate(xml_str, [_HTTP_SAMPLES[1]])[0]
    assert r["fields"].get("eventType") == "WebLog-Web-Request-Success"
    assert r["fields"].get("eventSeverity") == "1"


def test_simulator_404_gets_client_error_eventtype():
    xml_str = generate_parser(_HTTP_META, _HTTP_MAPPINGS, "text", _HTTP_SAMPLES)
    r = simulate(xml_str, [_HTTP_SAMPLES[2]])[0]
    assert r["fields"].get("eventType") == "WebLog-Web-Client-Error"
    assert r["fields"].get("eventSeverity") == "4"


def test_simulator_301_gets_redirect_eventtype():
    xml_str = generate_parser(_HTTP_META, _HTTP_MAPPINGS, "text", _HTTP_SAMPLES)
    r = simulate(xml_str, [_HTTP_SAMPLES[3]])[0]
    assert r["fields"].get("eventType") == "WebLog-Web-Request-Redirect"
    assert r["fields"].get("eventSeverity") == "2"


def test_simulator_500_gets_server_error_eventtype():
    xml_str = generate_parser(_HTTP_META, _HTTP_MAPPINGS, "text", _HTTP_SAMPLES)
    r = simulate(xml_str, [_HTTP_SAMPLES[4]])[0]
    assert r["fields"].get("eventType") == "WebLog-Web-Server-Error"
    assert r["fields"].get("eventSeverity") == "7"


def test_simulator_multiple_status_codes_give_different_eventtypes():
    """Passing all 5 samples must produce 5 distinct eventTypes."""
    xml_str = generate_parser(_HTTP_META, _HTTP_MAPPINGS, "text", _HTTP_SAMPLES)
    results = simulate(xml_str, _HTTP_SAMPLES)
    types = [r["fields"].get("eventType") for r in results]
    assert len(set(types)) == 5, f"Expected 5 distinct eventTypes, got: {types}"
