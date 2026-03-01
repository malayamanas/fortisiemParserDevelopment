import pytest
from tests.conftest import (SAMPLE_SYSLOG_JSON, SAMPLE_SYSLOG_KV,
                             SAMPLE_SYSLOG_TEXT, SAMPLE_PURE_JSON)
from parser_studio.detector import detect_format

def test_detect_syslog_json():
    assert detect_format([SAMPLE_SYSLOG_JSON]) == "syslog+json"

def test_detect_syslog_kv():
    assert detect_format([SAMPLE_SYSLOG_KV]) == "syslog+kv"

def test_detect_syslog_text():
    assert detect_format([SAMPLE_SYSLOG_TEXT]) == "syslog+text"

def test_detect_pure_json():
    assert detect_format([SAMPLE_PURE_JSON]) == "json"

def test_majority_vote():
    # 2 JSON samples vs 1 KV -> JSON wins
    assert detect_format([SAMPLE_SYSLOG_JSON, SAMPLE_SYSLOG_JSON, SAMPLE_SYSLOG_KV]) == "syslog+json"

def test_detect_syslog_xml():
    sample = ('Jul 23 10:05:15 2025 host 1.2.3.4 FSM-WUA-WinLog '
              '<Event><System><EventID>4624</EventID></System></Event>')
    assert detect_format([sample]) == "syslog+xml"

def test_strip_syslog_header():
    from parser_studio.detector import strip_syslog_header
    log = 'Jul 23 00:33:28 2025 host 1.2.3.4 TAG: {"key":"val"}'
    hdr, body = strip_syslog_header(log)
    assert hdr is not None
    assert body.strip().startswith("{")
