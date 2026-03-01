# FortiSIEM Parser Studio — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a local Flask web app that ingests raw event log samples and generates a complete, importable FortiSIEM XML parser — with auto format detection, EAT field mapping, validation, simulation, and a SQLite parser library.

**Architecture:** Python 3 Flask backend serves a single Alpine.js page. Each core concern (detection, extraction, mapping, generation, simulation, import) lives in its own module under `parser_studio/`. SQLite (built-in `sqlite3`) persists device types, parsers, and test samples.

**Tech Stack:** Python 3.10+ · Flask · SQLite · Alpine.js (CDN) · pytest · `xml.etree.ElementTree`

**Reference:** `docs/plans/2026-03-01-fortisiem-parser-studio-design.md`

---

## Task 1: Project Scaffold

**Files:**
- Create: `requirements.txt`
- Create: `parser_studio/__init__.py`
- Create: `parser_studio/templates/index.html` (stub)
- Create: `parser_studio/static/style.css` (empty)
- Create: `parser_studio.py`
- Create: `tests/__init__.py`
- Create: `tests/conftest.py`

**Step 1: Create `requirements.txt`**

```
flask>=3.0
pytest>=8.0
```

**Step 2: Create `parser_studio/__init__.py`** (empty file)

```python
```

**Step 3: Create stub `parser_studio/templates/index.html`**

```html
<!DOCTYPE html>
<html><body><h1>FortiSIEM Parser Studio</h1></body></html>
```

**Step 4: Create empty `parser_studio/static/style.css`**

**Step 5: Create `parser_studio.py`**

```python
import os
from flask import Flask, render_template

app = Flask(__name__, template_folder="parser_studio/templates",
            static_folder="parser_studio/static")

@app.route("/")
def index():
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True, port=5000)
```

**Step 6: Create `tests/conftest.py`**

```python
import pytest
import tempfile
import os

SAMPLE_SYSLOG_JSON = (
    'Jul 23 00:33:28 2025 host.example.com 1.2.3.4 SENTINELONE_THREATS: '
    '{"threatInfo":{"threatName":"Mimikatz","confidenceLevel":"malicious",'
    '"mitigationStatus":"not_mitigated"},"agentDetectionInfo":{"agentIp":"10.0.0.1"},'
    '"accountName":"LabCorp"}'
)

SAMPLE_SYSLOG_KV = (
    'Jul 23 10:05:15 2025 fw01 192.168.1.1 '
    'srcip=10.0.0.5 dstip=8.8.8.8 action=deny proto=tcp sport=54321 dport=443'
)

SAMPLE_SYSLOG_TEXT = (
    'Jul 23 10:05:15 2025 apache01 192.168.1.2 '
    '192.168.0.1 - frank [10/Oct/2000:13:55:36 -0700] '
    '"GET /apache_pb.gif HTTP/1.0" 200 2326'
)

SAMPLE_SYSLOG_BRACKET_KV = (
    'Jul 23 10:05:15 2025 gw01 10.0.0.1 MORPHISEC_ATTACK '
    '{"Account Id":"[\"abc123\"]","Computer Name":"[\"WORKSTATION01\"]",'
    '"Protector IP":"[\"192.168.0.139\"]"}'
)

SAMPLE_PURE_JSON = (
    '{"id":"evt-001","type":"alert","severity":3,'
    '"srcIp":"10.0.0.5","destIp":"8.8.8.8","message":"Port scan detected"}'
)

@pytest.fixture
def tmp_db(tmp_path):
    """Returns path to a temporary SQLite database."""
    return str(tmp_path / "test.db")
```

**Step 7: Install dependencies**

```bash
pip install flask pytest
```

**Step 8: Verify Flask starts**

```bash
python3 parser_studio.py
# Expected: * Running on http://127.0.0.1:5000
# Ctrl+C to stop
```

**Step 9: Commit**

```bash
git add requirements.txt parser_studio/ parser_studio.py tests/
git commit -m "feat: scaffold parser studio project structure"
```

---

## Task 2: Database Module

**Files:**
- Create: `parser_studio/db.py`
- Create: `tests/test_db.py`

**Step 1: Write failing tests**

```python
# tests/test_db.py
import pytest
from parser_studio.db import init_db, add_device_type, get_device_types, save_parser, get_parsers, get_parser_by_id

def test_init_creates_tables(tmp_db):
    init_db(tmp_db)
    import sqlite3
    conn = sqlite3.connect(tmp_db)
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    assert "device_types" in tables
    assert "parsers" in tables
    assert "test_samples" in tables
    conn.close()

def test_seed_device_types(tmp_db):
    init_db(tmp_db)
    types = get_device_types(tmp_db)
    vendors = [t["vendor"] for t in types]
    assert "SentinelOne" in vendors
    assert "Microsoft" in vendors

def test_add_and_get_device_type(tmp_db):
    init_db(tmp_db)
    add_device_type(tmp_db, "Acme", "FirewallX", "v2")
    types = get_device_types(tmp_db)
    assert any(t["vendor"] == "Acme" and t["model"] == "FirewallX" for t in types)

def test_save_and_get_parser(tmp_db):
    init_db(tmp_db)
    pid = save_parser(tmp_db, {
        "name": "TestParser", "scope": "enabled", "parser_type": "User",
        "vendor": "Acme", "model": "FirewallX", "version": "ANY",
        "xml_content": "<eventParser/>", "source": "studio", "file_path": None
    })
    parsers = get_parsers(tmp_db)
    assert len(parsers) == 1
    assert parsers[0]["name"] == "TestParser"

def test_get_parser_by_id(tmp_db):
    init_db(tmp_db)
    pid = save_parser(tmp_db, {
        "name": "TestParser", "scope": "enabled", "parser_type": "User",
        "vendor": "Acme", "model": "FirewallX", "version": "ANY",
        "xml_content": "<eventParser/>", "source": "studio", "file_path": None
    })
    p = get_parser_by_id(tmp_db, pid)
    assert p["name"] == "TestParser"
    assert p["xml_content"] == "<eventParser/>"
```

**Step 2: Run tests to verify they fail**

```bash
pytest tests/test_db.py -v
# Expected: FAILED (ImportError: cannot import name 'init_db')
```

**Step 3: Implement `parser_studio/db.py`**

```python
import sqlite3
from contextlib import contextmanager

SEED_DEVICE_TYPES = [
    ("SentinelOne", "Singularity", "ANY"),
    ("Morphisec", "EPTP", "ANY"),
    ("Microsoft", "Windows", "ANY"),
    ("Palo Alto Networks", "PAN-OS", "ANY"),
    ("Cisco", "ASA", "ANY"),
    ("Cisco", "WLC", "ANY"),
    ("Fortinet", "FortiGate", "ANY"),
    ("Check Point", "NGFW", "ANY"),
    ("Blue Coat", "ProxySG", "ANY"),
    ("Aruba", "WLAN", "ANY"),
    ("Apache", "HTTP Server", "ANY"),
    ("ISC", "BIND DNS", "ANY"),
    ("Proofpoint", "Honeynet", "ANY"),
    ("Syslog-NG", "Syslog-NG", "ANY"),
]

@contextmanager
def _conn(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()

def init_db(db_path: str) -> None:
    with _conn(db_path) as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS device_types (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                vendor  TEXT NOT NULL,
                model   TEXT NOT NULL,
                version TEXT NOT NULL DEFAULT 'ANY'
            );
            CREATE TABLE IF NOT EXISTS parsers (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                name        TEXT NOT NULL,
                scope       TEXT NOT NULL DEFAULT 'enabled',
                parser_type TEXT NOT NULL DEFAULT 'User',
                vendor      TEXT,
                model       TEXT,
                version     TEXT,
                xml_content TEXT,
                source      TEXT NOT NULL DEFAULT 'studio',
                file_path   TEXT,
                created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS test_samples (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                parser_id  INTEGER REFERENCES parsers(id) ON DELETE CASCADE,
                label      TEXT,
                raw_log    TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        existing = conn.execute("SELECT COUNT(*) FROM device_types").fetchone()[0]
        if existing == 0:
            conn.executemany(
                "INSERT INTO device_types (vendor, model, version) VALUES (?,?,?)",
                SEED_DEVICE_TYPES
            )

def get_device_types(db_path: str) -> list[dict]:
    with _conn(db_path) as conn:
        rows = conn.execute("SELECT * FROM device_types ORDER BY vendor, model").fetchall()
        return [dict(r) for r in rows]

def add_device_type(db_path: str, vendor: str, model: str, version: str = "ANY") -> int:
    with _conn(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO device_types (vendor, model, version) VALUES (?,?,?)",
            (vendor, model, version)
        )
        return cur.lastrowid

def save_parser(db_path: str, data: dict) -> int:
    with _conn(db_path) as conn:
        cur = conn.execute(
            """INSERT INTO parsers
               (name, scope, parser_type, vendor, model, version, xml_content, source, file_path)
               VALUES (:name,:scope,:parser_type,:vendor,:model,:version,:xml_content,:source,:file_path)""",
            data
        )
        return cur.lastrowid

def get_parsers(db_path: str) -> list[dict]:
    with _conn(db_path) as conn:
        rows = conn.execute("SELECT * FROM parsers ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]

def get_parser_by_id(db_path: str, parser_id: int) -> dict | None:
    with _conn(db_path) as conn:
        row = conn.execute("SELECT * FROM parsers WHERE id=?", (parser_id,)).fetchone()
        return dict(row) if row else None

def save_samples(db_path: str, parser_id: int, samples: list[dict]) -> None:
    with _conn(db_path) as conn:
        conn.execute("DELETE FROM test_samples WHERE parser_id=?", (parser_id,))
        conn.executemany(
            "INSERT INTO test_samples (parser_id, label, raw_log) VALUES (?,?,?)",
            [(parser_id, s.get("label", f"Sample {i+1}"), s["raw_log"])
             for i, s in enumerate(samples)]
        )

def get_samples(db_path: str, parser_id: int) -> list[dict]:
    with _conn(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM test_samples WHERE parser_id=? ORDER BY id", (parser_id,)
        ).fetchall()
        return [dict(r) for r in rows]

def is_file_imported(db_path: str, file_path: str) -> bool:
    with _conn(db_path) as conn:
        row = conn.execute("SELECT id FROM parsers WHERE file_path=?", (file_path,)).fetchone()
        return row is not None
```

**Step 4: Run tests**

```bash
pytest tests/test_db.py -v
# Expected: 5 passed
```

**Step 5: Commit**

```bash
git add parser_studio/db.py tests/test_db.py
git commit -m "feat: add database module with schema and CRUD"
```

---

## Task 3: Format Detector

**Files:**
- Create: `parser_studio/detector.py`
- Create: `tests/test_detector.py`

**Step 1: Write failing tests**

```python
# tests/test_detector.py
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
```

**Step 2: Run tests to verify they fail**

```bash
pytest tests/test_detector.py -v
# Expected: FAILED (ImportError)
```

**Step 3: Implement `parser_studio/detector.py`**

```python
import re
import json
from collections import Counter

# Standard syslog: "Jul 23 00:33:28" or "Jul  3 00:33:28"
_SYSLOG_HDR = re.compile(
    r'^(?:\w{3}|\d{1,2})\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}'
    r'(?:\s+\d{4})?'            # optional year
    r'(?:\s+\S+)?'              # optional hostname
    r'(?:\s+\S+)?'              # optional source IP
    r'\s*'
)
# ISO timestamp header: "2025-07-23T10:05:15"
_ISO_HDR = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}')

_KV_PLAIN  = re.compile(r'\b\w[\w\s]{0,30}?=\S+')
_KV_BRACKET = re.compile(r'\[[\w\s]+?\]=')
_XML_TAG   = re.compile(r'<\w[\w:.-]*[\s>]')


def strip_syslog_header(raw: str) -> tuple[str | None, str]:
    """Return (header_matched, remaining_body). header is None if no match."""
    m = _SYSLOG_HDR.match(raw)
    if m:
        return m.group(0), raw[m.end():]
    m = _ISO_HDR.match(raw)
    if m:
        return m.group(0), raw[m.end():]
    return None, raw


def _classify_body(body: str) -> str:
    body = body.strip()
    if body.startswith("{") or body.startswith("["):
        try:
            json.loads(body)
            return "json"
        except ValueError:
            pass
    if _XML_TAG.search(body):
        return "xml"
    bracket_hits = len(_KV_BRACKET.findall(body))
    kv_hits = len(_KV_PLAIN.findall(body))
    if bracket_hits >= 2:
        return "bracket-kv"
    if kv_hits >= 3:
        return "kv"
    return "text"


def _classify_one(raw: str) -> str:
    hdr, body = strip_syslog_header(raw)
    body_type = _classify_body(body)
    if hdr is None:
        return body_type          # "json" | "kv" | "text"
    return f"syslog+{body_type}"  # "syslog+json" | "syslog+kv" | etc.


def detect_format(samples: list[str]) -> str:
    """Majority-vote format detection across all samples."""
    if not samples:
        return "syslog+text"
    counts = Counter(_classify_one(s) for s in samples if s.strip())
    return counts.most_common(1)[0][0]
```

**Step 4: Run tests**

```bash
pytest tests/test_detector.py -v
# Expected: 7 passed
```

**Step 5: Commit**

```bash
git add parser_studio/detector.py tests/test_detector.py
git commit -m "feat: add log format detector with majority-vote"
```

---

## Task 4: Field Extractor

**Files:**
- Create: `parser_studio/extractor.py`
- Create: `tests/test_extractor.py`

**Step 1: Write failing tests**

```python
# tests/test_extractor.py
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
```

**Step 2: Run tests to verify they fail**

```bash
pytest tests/test_extractor.py -v
# Expected: FAILED (ImportError)
```

**Step 3: Implement `parser_studio/extractor.py`**

```python
import re
import json
import xml.etree.ElementTree as ET
from parser_studio.detector import strip_syslog_header

_KV_PLAIN   = re.compile(r'(\b\w[\w\s]{0,20}?)=([^,\s"\']+)')
_KV_BRACKET = re.compile(r'\[([\w\s]+?)\]=([^\s,]+)')


def _flatten_json(obj, prefix="") -> dict[str, str]:
    """Recursively flatten a dict/list to dot-notation keys."""
    out = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else k
            if isinstance(v, (dict, list)):
                out.update(_flatten_json(v, key))
            else:
                out[key] = str(v) if v is not None else ""
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            out.update(_flatten_json(item, f"{prefix}[{i}]" if prefix else f"[{i}]"))
    return out


def _flatten_xml(elem, prefix="") -> dict[str, str]:
    """Recursively flatten XML element tree to dot-notation keys."""
    out = {}
    tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
    path = f"{prefix}.{tag}" if prefix else tag
    if elem.text and elem.text.strip():
        out[path] = elem.text.strip()
    for attr_name, attr_val in elem.attrib.items():
        out[f"{path}@{attr_name}"] = attr_val
    for child in elem:
        out.update(_flatten_xml(child, path))
    return out


def _extract_one(raw: str, fmt: str) -> dict[str, str]:
    """Extract fields from a single raw log line."""
    _, body = strip_syslog_header(raw)
    body = body.strip()

    if fmt in ("syslog+json", "json"):
        # Find JSON payload (first { to matching })
        start = body.find("{")
        if start == -1:
            return {}
        try:
            obj = json.loads(body[start:])
            return _flatten_json(obj)
        except ValueError:
            return {}

    if fmt in ("syslog+kv", "syslog+bracket-kv"):
        fields = {}
        for m in _KV_BRACKET.finditer(body):
            fields[m.group(1).strip()] = m.group(2)
        for m in _KV_PLAIN.finditer(body):
            key = m.group(1).strip()
            if key not in fields:
                fields[key] = m.group(2)
        return fields

    if fmt == "syslog+xml":
        start = body.find("<")
        if start == -1:
            return {}
        try:
            root = ET.fromstring(body[start:])
            return _flatten_xml(root)
        except ET.ParseError:
            return {}

    # syslog+text: tokenise — return positional suggestions only
    tokens = body.split()
    return {f"_token{i}": tok for i, tok in enumerate(tokens[:20])}


def extract_fields(samples: list[str], fmt: str) -> dict[str, dict]:
    """
    Extract and merge fields from all samples.
    Returns {field_name: {"values": [...], "optional": bool}}
    """
    total = len(samples)
    counts: dict[str, int] = {}
    values: dict[str, list[str]] = {}

    for raw in samples:
        seen = _extract_one(raw, fmt)
        for k, v in seen.items():
            counts[k] = counts.get(k, 0) + 1
            values.setdefault(k, [])
            if v and v not in values[k]:
                values[k].append(v)

    return {
        k: {
            "values": values[k][:3],          # up to 3 example values
            "optional": counts[k] < total,    # absent in at least one sample
        }
        for k in counts
    }
```

**Step 4: Run tests**

```bash
pytest tests/test_extractor.py -v
# Expected: 6 passed
```

**Step 5: Commit**

```bash
git add parser_studio/extractor.py tests/test_extractor.py
git commit -m "feat: add field extractor for JSON/KV/XML/text formats"
```

---

## Task 5: EAT Table + Mapper

**Files:**
- Create: `parser_studio/eat_table.py`
- Create: `parser_studio/mapper.py`
- Create: `tests/test_mapper.py`

**Step 1: Write failing tests**

```python
# tests/test_mapper.py
from parser_studio.mapper import suggest_mappings, ALL_EATS

def test_exact_match():
    result = suggest_mappings(["srcip"])
    assert result["srcip"][0]["eat"] == "srcIpAddr"
    assert result["srcip"][0]["score"] == 100

def test_alias_match():
    result = suggest_mappings(["sourceip"])
    assert result["sourceip"][0]["eat"] == "srcIpAddr"

def test_dot_notation_match():
    # "agentDetectionInfo.agentIp" → srcIpAddr
    result = suggest_mappings(["agentDetectionInfo.agentIp"])
    assert result["agentDetectionInfo.agentIp"][0]["eat"] == "srcIpAddr"

def test_unknown_field():
    result = suggest_mappings(["xyzCustomField999"])
    assert result["xyzCustomField999"][0]["score"] < 30

def test_returns_top3():
    result = suggest_mappings(["user"])
    assert len(result["user"]) <= 3

def test_all_eats_populated():
    assert "srcIpAddr" in ALL_EATS
    assert "destIpAddr" in ALL_EATS
    assert "eventType" in ALL_EATS
    assert "eventSeverity" in ALL_EATS
    assert len(ALL_EATS) > 20

def test_message_field():
    result = suggest_mappings(["threatName"])
    assert result["threatName"][0]["eat"] == "msg"

def test_hash_field():
    result = suggest_mappings(["md5"])
    assert result["md5"][0]["eat"] == "hashMD5"
```

**Step 2: Run tests to verify they fail**

```bash
pytest tests/test_mapper.py -v
# Expected: FAILED (ImportError)
```

**Step 3: Implement `parser_studio/eat_table.py`**

```python
# eat_table.py — keyword synonym table for EAT mapping
# Format: "normalised_field_keyword": "FortiSIEM_EAT"
# Normalisation: lowercase, remove spaces/underscores/dots

SYNONYMS: dict[str, str] = {
    # === Source IP ===
    "srcipaddr": "srcIpAddr", "srcip": "srcIpAddr", "sourceip": "srcIpAddr",
    "sourceipaddr": "srcIpAddr", "clientip": "srcIpAddr", "remoteip": "srcIpAddr",
    "agentip": "srcIpAddr", "protectorip": "srcIpAddr", "saddr": "srcIpAddr",
    "fromip": "srcIpAddr", "localip": "srcIpAddr", "reportedlocalhost": "srcIpAddr",
    "agentdetectioninfoagentip": "srcIpAddr", "detectagentip": "srcIpAddr",

    # === Destination IP ===
    "destipaddr": "destIpAddr", "destip": "destIpAddr", "dstip": "destIpAddr",
    "dst": "destIpAddr", "destinationip": "destIpAddr", "serverip": "destIpAddr",
    "externalip": "destIpAddr", "remotehost": "destIpAddr", "toip": "destIpAddr",
    "reportedremotehost": "destIpAddr", "agentdetectioninfoexternalip": "destIpAddr",

    # === Source Hostname ===
    "srchostname": "srcHostName", "hostname": "srcHostName", "computername": "srcHostName",
    "computername": "srcHostName", "agentcomputername": "srcHostName",
    "machinename": "srcHostName", "host": "srcHostName", "srchost": "srcHostName",
    "agentdetectioninfoagentcomputername": "srcHostName",

    # === Destination Hostname ===
    "destname": "destName", "desthostname": "destName", "servername": "destName",
    "dsthost": "destName",

    # === User ===
    "user": "user", "username": "user", "loginuser": "user",
    "loggedinusername": "user", "logonuser": "user", "loginname": "user",
    "agentlastloggedinusername": "user", "agentdetectioninfoagentlastloggedinusername": "user",
    "processuser": "user", "subject": "user",

    # === Target User ===
    "targetuser": "targetUser", "targetusername": "targetUser",
    "destuser": "targetUser", "targetaccount": "targetUser",

    # === Message ===
    "msg": "msg", "message": "msg", "threatname": "msg", "description": "msg",
    "reason": "msg", "detail": "msg", "info": "msg", "summary": "msg",
    "threatinfothreatname": "msg",

    # === Event Severity ===
    "eventseverity": "eventSeverity", "severity": "eventSeverity",
    "threatseverity": "eventSeverity", "level": "eventSeverity",
    "priority": "eventSeverity", "urgency": "eventSeverity",

    # === Hashes ===
    "sha1": "hashSHA1", "filecontenthash": "hashSHA1", "sha256": "hashSHA256",
    "md5": "hashMD5", "threatinfomd5": "hashMD5", "filehash": "hashSHA1",

    # === Process ===
    "procname": "procName", "processname": "procName", "process": "procName",
    "application": "procName", "app": "procName", "executable": "procName",
    "procid": "procId", "processid": "procId", "pid": "procId",
    "parentprocname": "parentProcName", "parentprocess": "parentProcName",
    "parentprocid": "parentProcId", "parentpid": "parentProcId",

    # === File ===
    "filename": "fileName", "filedisplayname": "fileName", "file": "fileName",
    "filepath": "filePath", "fullpath": "filePath", "path": "filePath",

    # === Network ===
    "ipproto": "ipProto", "proto": "ipProto", "protocol": "ipProto",
    "srcport": "srcIpPort", "sourceport": "srcIpPort", "sport": "srcIpPort",
    "destport": "destIpPort", "dstport": "destIpPort", "dport": "destIpPort",
    "destinationport": "destIpPort",

    # === Action ===
    "eventaction": "eventAction", "action": "eventAction",
    "mitigationstatus": "eventAction", "disposition": "eventAction",
    "verdict": "eventAction", "result": "eventAction",

    # === Customer / Account ===
    "customer": "customer", "accountname": "customer", "tenant": "customer",
    "tenantid": "customer", "org": "customer", "organization": "customer",

    # === Command ===
    "command": "command", "commandline": "command", "cmdline": "command",
    "cmd": "command", "execcommand": "command",

    # === Policy / Rule ===
    "policyname": "policyName", "policy": "policyName",
    "rulename": "ruleName", "rule": "ruleName", "signature": "ruleName",

    # === Virus / Threat ===
    "virusname": "virusName", "malwarename": "virusName",
    "threatlevel": "threatLevel", "riskLevel": "threatLevel",

    # === Session ===
    "sessionid": "sessionId", "connid": "sessionId", "flowid": "sessionId",

    # === Domain ===
    "domain": "domain", "workgroup": "domain", "realm": "domain",

    # === Classification ===
    "classification": "_classification", "category": "_classification",
    "threatcategory": "_classification",

    # === Confidence ===
    "confidencelevel": "_confidenceLevel", "confidence": "_confidenceLevel",

    # === Time ===
    "createdat": "eventTime", "timestamp": "eventTime", "eventtime": "eventTime",
    "attacktime": "eventTime",
}

ALL_EATS: list[str] = sorted({
    "srcIpAddr", "destIpAddr", "srcHostName", "destName", "srcName",
    "user", "targetUser", "domain", "customer",
    "msg", "command", "policyName", "ruleName", "connMode",
    "eventType", "eventSeverity", "eventTime", "deviceTime", "eventAction",
    "procName", "procId", "parentProcName", "parentProcId",
    "fileName", "filePath", "hashMD5", "hashSHA1", "hashSHA256",
    "ipProto", "srcIpPort", "destIpPort", "sessionId", "serviceName",
    "virusName", "threatLevel", "authenMethod",
    "winEventId", "winLogonType", "winLogonId",
    "_classification", "_confidenceLevel",
})
```

**Step 4: Implement `parser_studio/mapper.py`**

```python
import re
from parser_studio.eat_table import SYNONYMS, ALL_EATS

_STRIP = re.compile(r'[\s_.\-\[\](){}]')


def _normalise(name: str) -> str:
    """Lowercase and strip non-alphanumeric chars for fuzzy matching."""
    return _STRIP.sub("", name).lower()


def _score(field_norm: str, eat: str) -> int:
    """Return a match score 0-100 for (field_norm, eat) pair."""
    eat_norm = _normalise(eat)
    if field_norm == eat_norm:
        return 100
    if field_norm in SYNONYMS and SYNONYMS[field_norm] == eat:
        return 90
    # substring: eat keyword appears in field name
    eat_key = eat_norm.replace("ipaddr", "ip").replace("hostname", "host")
    if eat_key in field_norm or field_norm in eat_key:
        return 70
    # partial word match
    for part in re.split(r'(?=[A-Z])', eat):
        p = part.lower()
        if len(p) > 3 and p in field_norm:
            return 50
    return 0


def suggest_mappings(field_names: list[str]) -> dict[str, list[dict]]:
    """
    Returns {field_name: [{"eat": str, "score": int}, ...]} sorted by score desc.
    Top 3 suggestions per field. Fields with max score < 30 still return a
    suggestion but marked with score < 30.
    """
    result = {}
    for field in field_names:
        norm = _normalise(field)
        # Direct synonym lookup first
        if norm in SYNONYMS:
            best_eat = SYNONYMS[norm]
            suggestions = [{"eat": best_eat, "score": 100}]
            for eat in ALL_EATS:
                if eat != best_eat:
                    s = _score(norm, eat)
                    if s >= 50:
                        suggestions.append({"eat": eat, "score": s})
            suggestions = sorted(suggestions, key=lambda x: -x["score"])[:3]
        else:
            scores = [{"eat": eat, "score": _score(norm, eat)} for eat in ALL_EATS]
            scores.sort(key=lambda x: -x["score"])
            suggestions = scores[:3]
        result[field] = suggestions
    return result
```

**Step 5: Run tests**

```bash
pytest tests/test_mapper.py -v
# Expected: 8 passed
```

**Step 6: Commit**

```bash
git add parser_studio/eat_table.py parser_studio/mapper.py tests/test_mapper.py
git commit -m "feat: add EAT synonym table and field mapping scorer"
```

---

## Task 6: XML Parser Generator

**Files:**
- Create: `parser_studio/generator.py`
- Create: `tests/test_generator.py`

**Step 1: Write failing tests**

```python
# tests/test_generator.py
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
```

**Step 2: Run tests to verify they fail**

```bash
pytest tests/test_generator.py -v
# Expected: FAILED (ImportError)
```

**Step 3: Implement `parser_studio/generator.py`**

```python
import re
import xml.etree.ElementTree as ET
from xml.dom import minidom

_GPATTERNS = {
    "syslog_header": (
        r'<_mon:gPatMon>\s+<_day:gPatDay>\s+<_time:gPatTime>'
        r'(?:\s+<_year:gPatYear>)?(?:\s+<_devHost:gPatStr>)?'
        r'(?:\s+<:gPatIpAddr>)?'
    ),
}


def _indent(xml_str: str) -> str:
    """Pretty-print XML string."""
    try:
        dom = minidom.parseString(xml_str.encode())
        pretty = dom.toprettyxml(indent="  ")
        # Remove the XML declaration minidom adds (we add our own)
        lines = pretty.split("\n")
        return "\n".join(l for l in lines if l.strip() and not l.startswith("<?xml"))
    except Exception:
        return xml_str


def _safe_comment(text: str) -> str:
    """Ensure comment text never contains '--'."""
    return text.replace("--", "==")


def _extraction_element(fmt: str, mappings: dict[str, str]) -> str:
    """Return the appropriate extraction XML block."""
    lines = []
    if fmt in ("syslog+json", "json"):
        lines.append('    <collectAndSetAttrByJSON src="$_jsonBody">')
        for field, eat in mappings.items():
            if not eat or eat.startswith("_skip"):
                continue
            attr = eat if not eat.startswith("_") else eat
            lines.append(f'      <attrKeyMap attr="{attr}" key="{field}"/>')
        lines.append('    </collectAndSetAttrByJSON>')

    elif fmt in ("syslog+kv", "syslog+bracket-kv"):
        sep = '", "' if fmt == "syslog+bracket-kv" else ' '
        lines.append('    <collectAndSetAttrByKeyValuePair'
                     f' src="$_body" sep="{sep}">')
        for field, eat in mappings.items():
            if not eat or eat.startswith("_skip"):
                continue
            lines.append(f'      <attrKeyMap attr="{eat}" key="{field}"/>')
        lines.append('    </collectAndSetAttrByKeyValuePair>')

    elif fmt == "syslog+xml":
        lines.append('    <collectFieldsByXPath src="$_xmlBody">')
        for field, eat in mappings.items():
            if not eat or eat.startswith("_skip"):
                continue
            xpath = "/" + field.replace(".", "/")
            lines.append(f'      <attrKeyMap attr="{eat}" key="{xpath}"/>')
        lines.append('    </collectFieldsByXPath>')

    else:  # syslog+text — emit collectFieldsByRegex stub
        lines.append('    <!-- TODO: fill in regex pattern for this format -->')
        lines.append('    <collectFieldsByRegex src="$_body">')
        lines.append('      <regex><![CDATA[<!-- add your pattern here -->]]></regex>')
        lines.append('    </collectFieldsByRegex>')

    return "\n".join(lines)


def generate_parser(meta: dict, mappings: dict[str, str],
                    fmt: str, samples: list[str]) -> str:
    """
    Generate a complete FortiSIEM XML parser string.

    meta keys: name, scope, parser_type, vendor, model, version, anchor
    mappings: {json_field_or_key: fortisiem_eat}
    fmt: detected format string
    samples: raw log samples (used to derive anchor if meta["anchor"] is empty)
    """
    name    = meta.get("name", "CustomParser")
    vendor  = meta.get("vendor", "Unknown")
    model   = meta.get("model", "Unknown")
    version = meta.get("version", "ANY")
    anchor  = meta.get("anchor", name.upper().replace(" ", "_"))

    # Determine body variable name based on format
    body_var = {
        "syslog+json":       "_jsonBody",
        "syslog+kv":         "_body",
        "syslog+bracket-kv": "_body",
        "syslog+xml":        "_xmlBody",
        "syslog+text":       "_body",
        "json":              "_jsonBody",
    }.get(fmt, "_body")

    extraction = _extraction_element(fmt, mappings)

    # Recognizer pattern
    if fmt.startswith("syslog"):
        recognizer = (
            f"<:gPatMon>\\s+<:gPatDay>\\s+<:gPatTime>\\s+<:gPatYear>"
            f"\\s+<:gPatStr>\\s+<:gPatIpAddr>\\s+{anchor}"
        )
    else:
        recognizer = f'"type"\\s*:\\s*"'  # generic JSON anchor stub

    # Header regex
    if fmt.startswith("syslog"):
        header_regex = (
            f"<_mon:gPatMon>\\s+<_day:gPatDay>\\s+<_time:gPatTime>"
            f"\\s+<_year:gPatYear>\\s+<_devHost:gPatStr>\\s+<:gPatIpAddr>"
            f"\\s+{anchor}[:\\s]+<{body_var}:gPatMesgBody>"
        )
    else:
        header_regex = f"<{body_var}:gPatMesgBody>"

    xml_lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<!-- FortiSIEM Custom Parser: {name} -->',
        f'<!-- Vendor: {vendor} | Model: {model} | Generated by Parser Studio -->',
        f'<eventParser name="{name}">',
        '  <deviceType>',
        f'    <Vendor>{vendor}</Vendor>',
        f'    <Model>{model}</Model>',
        f'    <Version>{version}</Version>',
        '  </deviceType>',
        '',
        '  <patternDefinitions>',
        '    <!-- Add custom patterns here if needed -->',
        '  </patternDefinitions>',
        '',
        '  <eventFormatRecognizer>',
        f'    <![CDATA[{recognizer}]]>',
        '  </eventFormatRecognizer>',
        '',
        '  <parsingInstructions>',
        '',
        '    <!-- Step 1: Parse header and extract body -->',
        '    <collectFieldsByRegex src="$_rawmsg">',
        f'      <regex><![CDATA[{header_regex}]]></regex>',
        '    </collectFieldsByRegex>',
    ]

    if fmt.startswith("syslog"):
        xml_lines += [
            '',
            '    <!-- Step 2: Set deviceTime from syslog header -->',
            '    <setEventAttribute attr="deviceTime">'
            'toDateTime($_mon, $_day, $_year, $_time)</setEventAttribute>',
        ]

    xml_lines += [
        '',
        f'    <!-- Step 3: Extract fields ({fmt}) -->',
        extraction,
        '',
        '    <!-- Step 4: Set eventType -->',
        f'    <setEventAttribute attr="eventType">{name}-Event</setEventAttribute>',
        '',
        '    <!-- Step 5: Set eventSeverity (default 5; add <choose> block to refine) -->',
        '    <setEventAttribute attr="eventSeverity">5</setEventAttribute>',
        '',
        '  </parsingInstructions>',
        '</eventParser>',
    ]

    return "\n".join(xml_lines)
```

**Step 4: Run tests**

```bash
pytest tests/test_generator.py -v
# Expected: 9 passed
```

**Step 5: Commit**

```bash
git add parser_studio/generator.py tests/test_generator.py
git commit -m "feat: add XML parser generator for all supported formats"
```

---

## Task 7: Parser Simulator

**Files:**
- Create: `parser_studio/simulator.py`
- Create: `tests/test_simulator.py`

**Step 1: Write failing tests**

```python
# tests/test_simulator.py
from parser_studio.simulator import simulate
from parser_studio.generator import generate_parser

META = {"name": "T", "vendor": "V", "model": "M", "version": "ANY", "anchor": "SENTINELONE_THREATS"}
MAPPINGS = {"threatInfo.threatName": "msg", "accountName": "customer"}
SAMPLE = ('Jul 23 00:33:28 2025 host 1.2.3.4 SENTINELONE_THREATS: '
          '{"threatInfo":{"threatName":"Mimikatz"},"accountName":"LabCorp"}')

def test_simulate_extracts_fields():
    xml_str = generate_parser(META, MAPPINGS, "syslog+json", [SAMPLE])
    results = simulate(xml_str, [SAMPLE])
    assert len(results) == 1
    r = results[0]
    assert r["msg"] == "Mimikatz"
    assert r["customer"] == "LabCorp"

def test_simulate_sets_device_time():
    xml_str = generate_parser(META, MAPPINGS, "syslog+json", [SAMPLE])
    results = simulate(xml_str, [SAMPLE])
    assert "deviceTime" in results[0]

def test_simulate_event_type():
    xml_str = generate_parser(META, MAPPINGS, "syslog+json", [SAMPLE])
    results = simulate(xml_str, [SAMPLE])
    assert results[0].get("eventType") == "T-Event"

def test_simulate_event_severity():
    xml_str = generate_parser(META, MAPPINGS, "syslog+json", [SAMPLE])
    results = simulate(xml_str, [SAMPLE])
    assert results[0].get("eventSeverity") == "5"

def test_simulate_multiple_samples():
    xml_str = generate_parser(META, MAPPINGS, "syslog+json", [SAMPLE])
    results = simulate(xml_str, [SAMPLE, SAMPLE])
    assert len(results) == 2
```

**Step 2: Run tests to verify they fail**

```bash
pytest tests/test_simulator.py -v
# Expected: FAILED (ImportError)
```

**Step 3: Implement `parser_studio/simulator.py`**

```python
import re
import json
import xml.etree.ElementTree as ET
from parser_studio.extractor import _flatten_json
from parser_studio.detector import strip_syslog_header

_GPATTERNS = {
    "gPatMon":      r'\w{3}|\d{1,2}',
    "gPatDay":      r'\d{1,2}',
    "gPatTime":     r'\d{1,2}:\d{1,2}:\d{1,2}',
    "gPatYear":     r'\d{2,4}',
    "gPatStr":      r'[^\s]+',
    "gPatIpAddr":   r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
    "gPatIpPort":   r'\d{1,5}',
    "gPatInt":      r'\d+',
    "gPatWord":     r'\w+',
    "gPatMesgBody": r'.+',
    "gPatMesgBodyMin": r'.+?',
    "gPatHostName": r'[\w.\-]+',
    "gPatFqdn":     r'\w+(?:\.\w+)+',
}


def _fsm_regex_to_python(fsm_pattern: str) -> tuple[str, list[str]]:
    """Convert FSM <attr:gPat> capture syntax to Python named-group regex."""
    groups = []
    def replace_capture(m):
        attr = m.group(1)
        pat_name = m.group(2)
        py_pat = _GPATTERNS.get(pat_name, r'\S+')
        if attr:
            groups.append(attr)
            return f'(?P<{attr}>{py_pat})'
        return f'(?:{py_pat})'
    pattern = re.sub(r'<([^:>]*):(\w+)>', replace_capture, fsm_pattern)
    return pattern, groups


def _apply_function(func_str: str, attrs: dict) -> str:
    """Evaluate simple setEventAttribute function calls."""
    s = func_str.strip()
    # Literal value (no function call)
    if not re.match(r'\w+\(', s):
        if s.startswith('$'):
            return attrs.get(s[1:], "")
        return s

    # toDateTime(mon, day, year, time)
    m = re.match(r'toDateTime\((.+)\)', s)
    if m:
        args = [a.strip().strip('"\'') for a in m.group(1).split(',')]
        parts = [attrs.get(a.lstrip('$'), a) for a in args[:4]]
        return " ".join(parts)

    # combineMsgId("prefix", $var, ...)
    m = re.match(r'combineMsgId\((.+)\)', s)
    if m:
        parts = []
        for tok in re.split(r',\s*', m.group(1)):
            tok = tok.strip().strip('"')
            if tok.startswith('$'):
                parts.append(attrs.get(tok[1:], tok))
            else:
                parts.append(tok)
        return "".join(parts)

    return s


def _simulate_one(instructions_elem: ET.Element, raw: str) -> dict:
    attrs: dict[str, str] = {"_rawmsg": raw}

    for elem in instructions_elem:
        tag = elem.tag

        if tag == "collectFieldsByRegex":
            src_var = elem.attrib.get("src", "$_rawmsg").lstrip('$')
            src_val = attrs.get(src_var, raw)
            regex_elem = elem.find("regex")
            if regex_elem is not None and regex_elem.text:
                py_pat, _ = _fsm_regex_to_python(regex_elem.text.strip())
                try:
                    m = re.search(py_pat, src_val, re.DOTALL)
                    if m:
                        attrs.update(m.groupdict())
                except re.error:
                    pass

        elif tag == "collectAndSetAttrByJSON":
            src_var = elem.attrib.get("src", "$_jsonBody").lstrip('$')
            src_val = attrs.get(src_var, "")
            start = src_val.find("{")
            if start != -1:
                try:
                    obj = json.loads(src_val[start:])
                    flat = _flatten_json(obj)
                    for km in elem.findall("attrKeyMap"):
                        attr = km.attrib["attr"]
                        key  = km.attrib["key"]
                        if key in flat:
                            attrs[attr] = flat[key]
                except (ValueError, KeyError):
                    pass

        elif tag == "collectAndSetAttrByKeyValuePair":
            src_var = elem.attrib.get("src", "$_body").lstrip('$')
            src_val = attrs.get(src_var, "")
            flat = {}
            for m in re.finditer(r'(\w[\w\s]{0,20}?)=([^\s,]+)', src_val):
                flat[m.group(1).strip()] = m.group(2)
            for km in elem.findall("attrKeyMap"):
                attr = km.attrib["attr"]
                key  = km.attrib["key"]
                if key in flat:
                    attrs[attr] = flat[key]

        elif tag == "setEventAttribute":
            attr = elem.attrib.get("attr", "")
            val  = _apply_function(elem.text or "", attrs)
            if attr:
                attrs[attr] = val

        elif tag == "when":
            test = elem.attrib.get("test", "")
            if _eval_test(test, attrs):
                nested = ET.Element("parsingInstructions")
                nested.extend(list(elem))
                sub = _simulate_one(nested, raw)
                attrs.update(sub)

        elif tag == "choose":
            for child in elem:
                if child.tag == "when":
                    if _eval_test(child.attrib.get("test", ""), attrs):
                        nested = ET.Element("parsingInstructions")
                        nested.extend(list(child))
                        attrs.update(_simulate_one(nested, raw))
                        break
                elif child.tag == "otherwise":
                    nested = ET.Element("parsingInstructions")
                    nested.extend(list(child))
                    attrs.update(_simulate_one(nested, raw))

    return attrs


def _eval_test(test: str, attrs: dict) -> bool:
    """Evaluate a simple FSM when-test expression."""
    test = test.strip()
    m = re.match(r'^exist\s+(\S+)$', test)
    if m:
        return m.group(1) in attrs and attrs[m.group(1)] != ""
    m = re.match(r'^not_exist\s+(\S+)$', test)
    if m:
        return m.group(1) not in attrs or attrs[m.group(1)] == ""
    m = re.match(r'^\$(\S+)\s*=\s*[\'"](.+)[\'"]$', test)
    if m:
        return attrs.get(m.group(1), "") == m.group(2)
    m = re.match(r'^\$(\S+)\s*!=\s*[\'"](.+)[\'"]$', test)
    if m:
        return attrs.get(m.group(1), "") != m.group(2)
    return False


def simulate(xml_str: str, samples: list[str]) -> list[dict]:
    """
    Simulate a generated parser XML against raw log samples.
    Returns list of attribute dicts (one per sample), filtered to EATs only.
    """
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return [{"_error": "Invalid XML"} for _ in samples]

    instructions = root.find("parsingInstructions")
    if instructions is None:
        return [{"_error": "No parsingInstructions"} for _ in samples]

    results = []
    for raw in samples:
        attrs = _simulate_one(instructions, raw)
        # Filter out private temp vars (starting with _) except useful ones
        public = {k: v for k, v in attrs.items()
                  if not k.startswith("_") or k in ("_rawmsg",)}
        results.append(public)
    return results
```

**Step 4: Run tests**

```bash
pytest tests/test_simulator.py -v
# Expected: 5 passed
```

**Step 5: Commit**

```bash
git add parser_studio/simulator.py tests/test_simulator.py
git commit -m "feat: add parser simulation engine"
```

---

## Task 8: Parser Importer

**Files:**
- Create: `parser_studio/importer.py`
- Create: `tests/test_importer.py`

**Step 1: Write failing tests**

```python
# tests/test_importer.py
import os, shutil, pytest
from parser_studio.db import init_db, get_parsers
from parser_studio.importer import sync_parsers

SAMPLE_XML = '''<?xml version="1.0" encoding="UTF-8"?>
<eventParser name="TestImport">
  <deviceType>
    <Vendor>TestVendor</Vendor>
    <Model>TestModel</Model>
    <Version>ANY</Version>
  </deviceType>
  <eventFormatRecognizer><![CDATA[TEST_ANCHOR]]></eventFormatRecognizer>
  <parsingInstructions></parsingInstructions>
</eventParser>'''

def test_sync_imports_xml_files(tmp_path, tmp_db):
    parsers_dir = tmp_path / "parsers"
    parsers_dir.mkdir()
    (parsers_dir / "TestImport.xml").write_text(SAMPLE_XML)
    init_db(tmp_db)
    count = sync_parsers(str(parsers_dir), tmp_db)
    assert count == 1
    parsers = get_parsers(tmp_db)
    assert any(p["name"] == "TestImport" for p in parsers)

def test_sync_skips_already_imported(tmp_path, tmp_db):
    parsers_dir = tmp_path / "parsers"
    parsers_dir.mkdir()
    (parsers_dir / "TestImport.xml").write_text(SAMPLE_XML)
    init_db(tmp_db)
    sync_parsers(str(parsers_dir), tmp_db)
    count = sync_parsers(str(parsers_dir), tmp_db)  # second sync
    assert count == 0  # nothing new

def test_sync_picks_up_new_files(tmp_path, tmp_db):
    parsers_dir = tmp_path / "parsers"
    parsers_dir.mkdir()
    (parsers_dir / "TestImport.xml").write_text(SAMPLE_XML)
    init_db(tmp_db)
    sync_parsers(str(parsers_dir), tmp_db)
    xml2 = SAMPLE_XML.replace('name="TestImport"', 'name="TestImport2"')
    (parsers_dir / "TestImport2.xml").write_text(xml2)
    count = sync_parsers(str(parsers_dir), tmp_db)
    assert count == 1

def test_sync_extracts_vendor_model(tmp_path, tmp_db):
    parsers_dir = tmp_path / "parsers"
    parsers_dir.mkdir()
    (parsers_dir / "TestImport.xml").write_text(SAMPLE_XML)
    init_db(tmp_db)
    sync_parsers(str(parsers_dir), tmp_db)
    parsers = get_parsers(tmp_db)
    p = next(p for p in parsers if p["name"] == "TestImport")
    assert p["vendor"] == "TestVendor"
    assert p["model"] == "TestModel"
    assert p["source"] == "imported"
```

**Step 2: Run tests to verify they fail**

```bash
pytest tests/test_importer.py -v
# Expected: FAILED (ImportError)
```

**Step 3: Implement `parser_studio/importer.py`**

```python
import os
import glob
import xml.etree.ElementTree as ET
from parser_studio.db import is_file_imported, save_parser


def _parse_xml_meta(xml_path: str) -> dict | None:
    """Extract name/vendor/model/version from an eventParser XML file."""
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        if root.tag != "eventParser":
            return None
        name    = root.attrib.get("name", os.path.splitext(os.path.basename(xml_path))[0])
        vendor  = root.findtext(".//Vendor") or "Unknown"
        model   = root.findtext(".//Model") or "Unknown"
        version = root.findtext(".//Version") or "ANY"
        xml_content = ET.tostring(root, encoding="unicode")
        return {"name": name, "vendor": vendor, "model": model,
                "version": version, "xml_content": xml_content}
    except ET.ParseError:
        return None


def sync_parsers(parsers_dir: str, db_path: str) -> int:
    """
    Scan parsers_dir for *.xml files and import any not already in the DB.
    Returns number of newly imported parsers.
    """
    imported = 0
    for xml_path in sorted(glob.glob(os.path.join(parsers_dir, "*.xml"))):
        rel_path = os.path.relpath(xml_path)
        if is_file_imported(db_path, rel_path):
            continue
        meta = _parse_xml_meta(xml_path)
        if meta is None:
            continue
        save_parser(db_path, {
            "name":        meta["name"],
            "scope":       "enabled",
            "parser_type": "User",
            "vendor":      meta["vendor"],
            "model":       meta["model"],
            "version":     meta["version"],
            "xml_content": meta["xml_content"],
            "source":      "imported",
            "file_path":   rel_path,
        })
        imported += 1
    return imported
```

**Step 4: Run tests**

```bash
pytest tests/test_importer.py -v
# Expected: 4 passed
```

**Step 5: Run all tests to check nothing broke**

```bash
pytest tests/ -v
# Expected: all pass
```

**Step 6: Commit**

```bash
git add parser_studio/importer.py tests/test_importer.py
git commit -m "feat: add parser importer with disk sync and duplicate detection"
```

---

## Task 9: Flask API Routes

**Files:**
- Modify: `parser_studio.py` (replace stub with full Flask app)

**Step 1: Replace `parser_studio.py` with full app**

```python
import os
from flask import Flask, render_template, request, jsonify, send_file
import io

from parser_studio.db import (init_db, get_device_types, add_device_type,
                               save_parser, get_parsers, get_parser_by_id,
                               save_samples, get_samples)
from parser_studio.detector import detect_format
from parser_studio.extractor import extract_fields
from parser_studio.mapper import suggest_mappings
from parser_studio.generator import generate_parser
from parser_studio.simulator import simulate
from parser_studio.importer import sync_parsers
import xml.etree.ElementTree as ET

DB_PATH      = os.environ.get("PARSER_STUDIO_DB", "parser_studio.db")
PARSERS_DIR  = "parsers"

app = Flask(__name__, template_folder="parser_studio/templates",
            static_folder="parser_studio/static")


@app.before_request
def startup():
    """Init DB and sync parsers on first request only."""
    if not hasattr(app, "_started"):
        init_db(DB_PATH)
        if os.path.isdir(PARSERS_DIR):
            sync_parsers(PARSERS_DIR, DB_PATH)
        app._started = True


@app.route("/")
def index():
    return render_template("index.html")


# === Device Types ===

@app.route("/api/device-types", methods=["GET"])
def api_get_device_types():
    return jsonify(get_device_types(DB_PATH))


@app.route("/api/device-types", methods=["POST"])
def api_add_device_type():
    data = request.get_json(force=True)
    add_device_type(DB_PATH, data["vendor"], data["model"],
                    data.get("version", "ANY"))
    return jsonify({"ok": True})


# === Analysis ===

@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    data    = request.get_json(force=True)
    samples = [s.strip() for s in data.get("samples", []) if s.strip()]
    if not samples:
        return jsonify({"error": "No samples provided"}), 400

    fmt    = detect_format(samples)
    fields = extract_fields(samples, fmt)
    mappings = suggest_mappings(list(fields.keys()))

    return jsonify({
        "format":   fmt,
        "fields":   fields,
        "mappings": mappings,
    })


# === Generate ===

@app.route("/api/generate", methods=["POST"])
def api_generate():
    data     = request.get_json(force=True)
    meta     = data.get("meta", {})
    mappings = data.get("mappings", {})   # {field: eat}
    fmt      = data.get("format", "syslog+text")
    samples  = data.get("samples", [])

    xml_str = generate_parser(meta, mappings, fmt, samples)
    return jsonify({"xml": xml_str})


# === Validate ===

@app.route("/api/validate", methods=["POST"])
def api_validate():
    data    = request.get_json(force=True)
    xml_str = data.get("xml", "")
    try:
        ET.fromstring(xml_str)
        return jsonify({"valid": True})
    except ET.ParseError as e:
        return jsonify({"valid": False, "error": str(e)})


# === Test / Simulate ===

@app.route("/api/test", methods=["POST"])
def api_test():
    data    = request.get_json(force=True)
    xml_str = data.get("xml", "")
    samples = data.get("samples", [])
    results = simulate(xml_str, samples)
    return jsonify({"results": results})


# === Save Parser ===

@app.route("/api/parsers/save", methods=["POST"])
def api_save_parser():
    data = request.get_json(force=True)
    pid  = save_parser(DB_PATH, {
        "name":        data["name"],
        "scope":       data.get("scope", "enabled"),
        "parser_type": data.get("parser_type", "User"),
        "vendor":      data.get("vendor"),
        "model":       data.get("model"),
        "version":     data.get("version", "ANY"),
        "xml_content": data.get("xml"),
        "source":      "studio",
        "file_path":   None,
    })
    if data.get("samples"):
        save_samples(DB_PATH, pid,
                     [{"raw_log": s, "label": f"Sample {i+1}"}
                      for i, s in enumerate(data["samples"])])
    return jsonify({"ok": True, "id": pid})


# === List Parsers ===

@app.route("/api/parsers", methods=["GET"])
def api_list_parsers():
    return jsonify(get_parsers(DB_PATH))


# === Download Parser ===

@app.route("/api/parsers/<int:pid>/download", methods=["GET"])
def api_download_parser(pid: int):
    p = get_parser_by_id(DB_PATH, pid)
    if not p:
        return jsonify({"error": "Not found"}), 404
    fname = f"{p['name']}.xml"
    return send_file(
        io.BytesIO(p["xml_content"].encode()),
        mimetype="application/xml",
        as_attachment=True,
        download_name=fname,
    )


# === Sync from disk ===

@app.route("/api/parsers/sync", methods=["POST"])
def api_sync_parsers():
    if not os.path.isdir(PARSERS_DIR):
        return jsonify({"imported": 0})
    count = sync_parsers(PARSERS_DIR, DB_PATH)
    return jsonify({"imported": count})


if __name__ == "__main__":
    app.run(debug=True, port=5000)
```

**Step 2: Smoke-test the API manually**

```bash
python3 parser_studio.py &
sleep 1

# Test device types
curl -s http://localhost:5000/api/device-types | python3 -m json.tool | head -20

# Test analyze endpoint
curl -s -X POST http://localhost:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"samples":["Jul 23 00:33:28 2025 host 1.2.3.4 TAG: {\"srcip\":\"10.0.0.1\",\"action\":\"deny\"}"]}' \
  | python3 -m json.tool

# Expected: {"format": "syslog+json", "fields": {...}, "mappings": {...}}
```

**Step 3: Stop background Flask and commit**

```bash
kill %1
git add parser_studio.py
git commit -m "feat: add full Flask API routes (analyze, generate, validate, test, save, sync)"
```

---

## Task 10: UI (HTML + Alpine.js)

**Files:**
- Modify: `parser_studio/templates/index.html` (replace stub)
- Modify: `parser_studio/static/style.css`

**Step 1: Replace `index.html` with full Alpine.js UI**

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>FortiSIEM Parser Studio</title>
  <script src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js" defer></script>
  <link rel="stylesheet" href="/static/style.css"/>
</head>
<body>
<div x-data="studioApp()" class="container">

  <header>
    <h1>FortiSIEM Parser Studio</h1>
    <button @click="syncFromDisk()" class="btn btn-secondary">&#8635; Sync from disk</button>
  </header>

  <!-- METADATA PANEL -->
  <section class="panel">
    <h2>Parser Metadata</h2>
    <div class="form-grid">
      <label>Name
        <input type="text" x-model="meta.name" placeholder="MyVendorParser"/>
      </label>
      <label>Scope
        <select x-model="meta.scope">
          <option value="enabled">Enabled</option>
          <option value="disabled">Disabled</option>
        </select>
      </label>
      <label>Type
        <select x-model="meta.parser_type">
          <option value="User">User</option>
          <option value="System">System</option>
        </select>
      </label>
      <label>Vendor
        <select x-model="meta.vendor" @change="updateModels()">
          <option value="">-- select vendor --</option>
          <template x-for="v in vendors" :key="v">
            <option :value="v" x-text="v"></option>
          </template>
        </select>
      </label>
      <label>Model
        <select x-model="meta.model">
          <option value="">-- select model --</option>
          <template x-for="m in filteredModels" :key="m">
            <option :value="m" x-text="m"></option>
          </template>
        </select>
      </label>
      <label>Version
        <input type="text" x-model="meta.version" placeholder="ANY"/>
      </label>
      <label>Anchor tag (unique string in log)
        <input type="text" x-model="meta.anchor" placeholder="VENDOR_LOGTAG"/>
      </label>
    </div>
  </section>

  <!-- SAMPLES PANEL -->
  <section class="panel">
    <h2>Event Log Samples
      <button @click="addSample()" class="btn btn-sm">+ Add Sample</button>
    </h2>
    <template x-for="(s, i) in samples" :key="i">
      <div class="sample-block">
        <div class="sample-header">
          <span x-text="'Sample ' + (i+1)"></span>
          <button x-show="samples.length > 1" @click="removeSample(i)" class="btn btn-danger btn-sm">✕</button>
        </div>
        <textarea x-model="samples[i]" rows="3" placeholder="Paste raw log line here..."></textarea>
      </div>
    </template>
    <button @click="analyze()" class="btn btn-primary" :disabled="analyzing">
      <span x-text="analyzing ? 'Analyzing...' : 'Analyze Samples →'"></span>
    </button>
    <p x-show="analyzeError" class="error" x-text="analyzeError"></p>
  </section>

  <!-- FIELD MAPPINGS PANEL -->
  <section class="panel" x-show="detectedFormat">
    <h2>Field Mappings
      <span class="badge" x-text="'Format: ' + detectedFormat"></span>
    </h2>
    <p class="hint">Confirm or adjust the EAT mapping for each extracted field. Fields marked ⚠ had no confident match.</p>
    <table class="mapping-table">
      <thead><tr><th>Field in Log</th><th>Sample Values</th><th>FortiSIEM EAT</th><th>Optional?</th></tr></thead>
      <tbody>
        <template x-for="(info, field) in fields" :key="field">
          <tr :class="confirmedMappings[field] === '_skip' ? 'skipped' : ''">
            <td x-text="field"></td>
            <td class="values" x-text="(info.values || []).join(', ')"></td>
            <td>
              <select x-model="confirmedMappings[field]">
                <option value="_skip">-- skip --</option>
                <template x-for="sug in (suggestions[field] || [])" :key="sug.eat">
                  <option :value="sug.eat"
                          x-text="sug.eat + (sug.score < 30 ? ' ⚠' : '')"></option>
                </template>
                <template x-for="eat in allEats" :key="eat">
                  <option :value="eat" x-text="eat"></option>
                </template>
              </select>
            </td>
            <td x-text="info.optional ? 'optional' : ''"></td>
          </tr>
        </template>
      </tbody>
    </table>
    <button @click="generateParser()" class="btn btn-primary">Generate Parser →</button>
  </section>

  <!-- GENERATED XML PANEL -->
  <section class="panel" x-show="generatedXml">
    <h2>Generated Parser XML</h2>
    <div class="toolbar">
      <button @click="validateXml()" class="btn btn-secondary">Validate</button>
      <button @click="showTestModal = true" class="btn btn-secondary">Test</button>
      <button @click="saveParser()" class="btn btn-secondary">Save</button>
      <button @click="downloadXml()" class="btn btn-primary">Download .xml</button>
      <span x-show="validateResult !== null"
            :class="validateResult ? 'badge badge-ok' : 'badge badge-err'"
            x-text="validateResult ? '✓ Valid XML' : '✗ ' + validateError"></span>
    </div>
    <pre class="xml-preview" x-text="generatedXml"></pre>
  </section>

  <!-- TEST MODAL -->
  <div class="modal-overlay" x-show="showTestModal" @click.self="showTestModal = false">
    <div class="modal">
      <div class="modal-header">
        <h3>Parser Test Results</h3>
        <button @click="showTestModal = false" class="btn btn-sm">✕</button>
      </div>
      <div class="modal-body">
        <button @click="runTest()" class="btn btn-primary" :disabled="testing">
          <span x-text="testing ? 'Testing...' : 'Run Test'"></span>
        </button>
        <template x-if="testResults.length > 0">
          <div>
            <template x-for="(result, i) in testResults" :key="i">
              <div class="test-result">
                <h4 x-text="'Sample ' + (i+1)"></h4>
                <table class="result-table">
                  <tr><th>EAT</th><th>Value</th></tr>
                  <template x-for="[k, v] in Object.entries(result)" :key="k">
                    <tr><td x-text="k"></td><td x-text="v"></td></tr>
                  </template>
                </table>
              </div>
            </template>
          </div>
        </template>
      </div>
    </div>
  </div>

  <!-- PARSER LIBRARY -->
  <section class="panel">
    <h2>Parser Library</h2>
    <table class="library-table">
      <thead><tr><th>Name</th><th>Vendor</th><th>Model</th><th>Source</th><th>Actions</th></tr></thead>
      <tbody>
        <template x-for="p in parserLibrary" :key="p.id">
          <tr>
            <td x-text="p.name"></td>
            <td x-text="p.vendor"></td>
            <td x-text="p.model"></td>
            <td><span class="badge" x-text="p.source"></span></td>
            <td>
              <a :href="'/api/parsers/' + p.id + '/download'" class="btn btn-sm">Download</a>
            </td>
          </tr>
        </template>
      </tbody>
    </table>
  </section>

</div>

<script>
function studioApp() {
  return {
    // Metadata
    meta: { name: '', scope: 'enabled', parser_type: 'User',
            vendor: '', model: '', version: 'ANY', anchor: '' },
    deviceTypes: [], vendors: [], filteredModels: [],

    // Samples
    samples: [''],

    // Analysis results
    analyzing: false, analyzeError: '',
    detectedFormat: '', fields: {}, suggestions: {},

    // Mappings
    confirmedMappings: {},
    allEats: [
      'srcIpAddr','destIpAddr','srcHostName','destName','user','targetUser',
      'msg','command','customer','domain','eventType','eventSeverity','eventTime',
      'deviceTime','eventAction','procName','procId','parentProcName','parentProcId',
      'fileName','filePath','hashMD5','hashSHA1','hashSHA256','ipProto',
      'srcIpPort','destIpPort','sessionId','serviceName','virusName','threatLevel',
      'policyName','ruleName','winEventId','connMode','authenMethod',
    ],

    // Generated XML
    generatedXml: '',
    validateResult: null, validateError: '',

    // Test modal
    showTestModal: false, testing: false, testResults: [],

    // Parser library
    parserLibrary: [],

    async init() {
      await this.loadDeviceTypes();
      await this.loadParserLibrary();
    },

    async loadDeviceTypes() {
      const res = await fetch('/api/device-types');
      this.deviceTypes = await res.json();
      this.vendors = [...new Set(this.deviceTypes.map(d => d.vendor))].sort();
    },

    updateModels() {
      this.filteredModels = this.deviceTypes
        .filter(d => d.vendor === this.meta.vendor)
        .map(d => d.model);
      this.meta.model = '';
    },

    addSample() { this.samples.push(''); },
    removeSample(i) { this.samples.splice(i, 1); },

    async analyze() {
      this.analyzing = true; this.analyzeError = '';
      try {
        const res = await fetch('/api/analyze', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ samples: this.samples }),
        });
        const data = await res.json();
        if (data.error) { this.analyzeError = data.error; return; }
        this.detectedFormat = data.format;
        this.fields = data.fields;
        this.suggestions = data.mappings;
        // Pre-fill confirmed mappings with top suggestion
        this.confirmedMappings = {};
        for (const [field, sugs] of Object.entries(data.mappings)) {
          this.confirmedMappings[field] = sugs[0]?.eat || '_skip';
        }
      } finally { this.analyzing = false; }
    },

    async generateParser() {
      const mappings = {};
      for (const [f, eat] of Object.entries(this.confirmedMappings)) {
        if (eat !== '_skip') mappings[f] = eat;
      }
      const res = await fetch('/api/generate', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          meta: this.meta, mappings,
          format: this.detectedFormat, samples: this.samples
        }),
      });
      const data = await res.json();
      this.generatedXml = data.xml;
      this.validateResult = null;
    },

    async validateXml() {
      const res = await fetch('/api/validate', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ xml: this.generatedXml }),
      });
      const data = await res.json();
      this.validateResult = data.valid;
      this.validateError = data.error || '';
    },

    async runTest() {
      this.testing = true;
      try {
        const res = await fetch('/api/test', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ xml: this.generatedXml, samples: this.samples }),
        });
        const data = await res.json();
        this.testResults = data.results;
      } finally { this.testing = false; }
    },

    async saveParser() {
      const res = await fetch('/api/parsers/save', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          ...this.meta, xml: this.generatedXml, samples: this.samples
        }),
      });
      if (res.ok) {
        await this.loadParserLibrary();
        alert('Parser saved!');
      }
    },

    downloadXml() {
      const blob = new Blob([this.generatedXml], {type: 'application/xml'});
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = (this.meta.name || 'parser') + '.xml';
      a.click();
    },

    async syncFromDisk() {
      const res = await fetch('/api/parsers/sync', { method: 'POST' });
      const data = await res.json();
      await this.loadParserLibrary();
      alert(`Synced: ${data.imported} new parser(s) imported.`);
    },

    async loadParserLibrary() {
      const res = await fetch('/api/parsers');
      this.parserLibrary = await res.json();
    },
  };
}
</script>
</body>
</html>
```

**Step 2: Write `parser_studio/static/style.css`**

```css
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

body { font-family: system-ui, sans-serif; background: #f0f2f5; color: #1a1a2e; }

.container { max-width: 1100px; margin: 0 auto; padding: 1.5rem; }

header { display: flex; justify-content: space-between; align-items: center;
         margin-bottom: 1.5rem; }
header h1 { font-size: 1.6rem; color: #1a1a2e; }

.panel { background: white; border-radius: 8px; padding: 1.5rem;
         margin-bottom: 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,.1); }
.panel h2 { font-size: 1.1rem; margin-bottom: 1rem;
            display: flex; align-items: center; gap: .5rem; }

.form-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px,1fr)); gap: 1rem; }
label { display: flex; flex-direction: column; gap: .3rem; font-size: .875rem; font-weight: 500; }
input, select, textarea { padding: .45rem .6rem; border: 1px solid #d1d5db;
                           border-radius: 6px; font-size: .875rem; width: 100%; }
textarea { resize: vertical; font-family: monospace; font-size: .8rem; }

.sample-block { margin-bottom: .75rem; }
.sample-header { display: flex; justify-content: space-between;
                 font-weight: 500; margin-bottom: .3rem; font-size: .875rem; }

.btn { padding: .45rem .9rem; border: none; border-radius: 6px;
       cursor: pointer; font-size: .875rem; font-weight: 500; }
.btn-primary { background: #3b82f6; color: white; }
.btn-primary:hover { background: #2563eb; }
.btn-secondary { background: #e5e7eb; color: #374151; }
.btn-secondary:hover { background: #d1d5db; }
.btn-danger { background: #fee2e2; color: #dc2626; }
.btn-sm { padding: .25rem .55rem; font-size: .8rem; }
.btn:disabled { opacity: .6; cursor: not-allowed; }

.badge { display: inline-block; padding: .2rem .5rem; border-radius: 4px;
         font-size: .75rem; font-weight: 600; background: #e5e7eb; color: #374151; }
.badge-ok { background: #d1fae5; color: #065f46; }
.badge-err { background: #fee2e2; color: #dc2626; }

.hint { font-size: .8rem; color: #6b7280; margin-bottom: .75rem; }
.error { color: #dc2626; font-size: .85rem; margin-top: .5rem; }

.mapping-table, .library-table, .result-table {
  width: 100%; border-collapse: collapse; font-size: .85rem; }
th, td { padding: .5rem .75rem; border: 1px solid #e5e7eb; text-align: left; }
th { background: #f9fafb; font-weight: 600; }
.values { color: #6b7280; max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
tr.skipped { opacity: .45; }

.toolbar { display: flex; gap: .5rem; align-items: center; flex-wrap: wrap; margin-bottom: 1rem; }

.xml-preview { background: #1e1e1e; color: #d4d4d4; padding: 1rem;
               border-radius: 6px; overflow-x: auto; font-size: .8rem;
               line-height: 1.5; max-height: 400px; white-space: pre-wrap; }

.modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,.4);
                 display: flex; align-items: center; justify-content: center; z-index: 100; }
.modal { background: white; border-radius: 10px; width: 90%; max-width: 800px;
         max-height: 80vh; display: flex; flex-direction: column; }
.modal-header { display: flex; justify-content: space-between; align-items: center;
                padding: 1rem 1.25rem; border-bottom: 1px solid #e5e7eb; }
.modal-body { padding: 1.25rem; overflow-y: auto; }
.test-result { margin-bottom: 1.25rem; }
.test-result h4 { margin-bottom: .5rem; font-size: .9rem; }
```

**Step 3: Verify the UI loads**

```bash
python3 parser_studio.py
# Open http://localhost:5000 in browser
# Expected: Parser Studio page with metadata form, sample textareas, and parser library table
```

**Step 4: Commit**

```bash
git add parser_studio/templates/index.html parser_studio/static/style.css
git commit -m "feat: add full Alpine.js UI with metadata, field mapping, XML preview, test modal"
```

---

## Task 11: End-to-End Smoke Test

**Step 1: Start the server**

```bash
python3 parser_studio.py
```

**Step 2: Open browser at `http://localhost:5000`**

**Step 3: Verify parser library is populated**

- The Parser Library table should show all parsers imported from `parsers/`
  (WinOSXMLParser, SentinelOneCompleteParser, etc.)

**Step 4: Test with a SentinelOne JSON sample**

Paste this into Sample 1:
```
Jul 23 00:33:28 2025 host.example.com 1.2.3.4 SENTINELONE_THREATS: {"threatInfo":{"threatName":"Mimikatz","confidenceLevel":"malicious","mitigationStatus":"not_mitigated"},"agentDetectionInfo":{"agentIp":"10.0.0.1","agentComputerName":"WORKSTATION01"},"accountName":"LabCorp"}
```

Click **Analyze Samples →**
- Expected: Format shows `syslog+json`
- Fields panel shows `threatInfo.threatName`, `accountName`, `agentDetectionInfo.agentIp`, etc.
- `threatInfo.threatName` → `msg`, `accountName` → `customer`, `agentDetectionInfo.agentIp` → `srcIpAddr`

Click **Generate Parser →**
- XML preview shows a complete `<eventParser>` block

Click **Validate**
- Badge shows `✓ Valid XML`

Click **Test**, then **Run Test**
- Results show `msg: Mimikatz`, `customer: LabCorp`, `srcIpAddr: 10.0.0.1`

Click **Download .xml**
- Browser downloads the XML file

**Step 5: Test the KV format**

Paste into a new sample:
```
Jul 23 10:05:15 2025 fw01 192.168.1.1 CHECKPOINT_FW srcip=10.0.0.5 dstip=8.8.8.8 action=deny proto=tcp sport=54321 dport=443
```

Repeat analyze + generate + validate + test flow.
Expected: Format `syslog+kv`, fields `srcip → srcIpAddr`, `dstip → destIpAddr`, `action → eventAction`.

**Step 6: Run full test suite**

```bash
pytest tests/ -v
# Expected: all tests pass
```

**Step 7: Final commit**

```bash
git add -A
git commit -m "feat: complete FortiSIEM Parser Studio v1"
```

---

## Summary

| Task | Module | Tests |
|---|---|---|
| 1 | Scaffold | manual |
| 2 | `db.py` | `test_db.py` (5 tests) |
| 3 | `detector.py` | `test_detector.py` (7 tests) |
| 4 | `extractor.py` | `test_extractor.py` (6 tests) |
| 5 | `eat_table.py` + `mapper.py` | `test_mapper.py` (8 tests) |
| 6 | `generator.py` | `test_generator.py` (9 tests) |
| 7 | `simulator.py` | `test_simulator.py` (5 tests) |
| 8 | `importer.py` | `test_importer.py` (4 tests) |
| 9 | Flask routes | manual curl |
| 10 | UI (`index.html` + CSS) | manual browser |
| 11 | End-to-end smoke test | manual + `pytest` |

**Total automated tests: 44**
