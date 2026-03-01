# FortiSIEM Parser Studio — Design Document
**Date:** 2026-03-01
**Status:** Approved, ready for implementation planning

---

## 1. Overview

A local web application that ingests multiple raw event log samples and generates a
complete, importable FortiSIEM XML parser. The tool guides the user through format
detection, field-to-EAT mapping confirmation, XML generation, validation, and testing
— all in one browser UI.

**Launch:** `python3 parser_studio.py` → `http://localhost:5000`

---

## 2. Scope

### Log formats supported
- Syslog header + JSON body (e.g. SentinelOne, Morphisec, PHGenAI)
- Syslog header + key=value pairs (e.g. Astaro, Checkpoint firewall, Aruba WLAN)
- Syslog header + bracket-KV `[key]=value` pairs (e.g. Checkpoint, PHGenAI)
- Syslog header + plain text / free-form regex (e.g. Apache, Cisco ASA, Bind DNS)
- Syslog header + embedded XML (e.g. Windows Event Log via FSM-WUA)
- Pure JSON (no syslog header) (e.g. PHJsonParser, API event feeds)

### User-configurable metadata
- Parser name
- Scope: enabled / disabled
- Type: System / User
- Device Type: Vendor / Model / Version (from SQLite, user-editable)

### Core actions
- Analyze samples → auto-detect format + suggest EAT mappings
- Confirm / adjust field-to-EAT mappings
- Generate FortiSIEM XML parser
- Validate XML (well-formedness check)
- Test parser against all loaded samples (simulation)
- Save parser + samples to local SQLite database
- Download generated `.xml` file

---

## 3. Architecture

### Stack
| Layer | Technology |
|---|---|
| Backend | Python 3, Flask |
| Database | SQLite (Python built-in `sqlite3`) |
| Frontend | Single HTML page, Alpine.js (CDN, no npm/build step) |
| XML validation | Python `xml.etree.ElementTree` (no external tools) |

### File Structure
```
FortiSIEM_Parser_Creation_Script/
├── parser_studio.py              # Flask app entry point
├── parser_studio/
│   ├── __init__.py
│   ├── db.py                     # SQLite schema, init, CRUD helpers
│   ├── detector.py               # Log format auto-detection engine
│   ├── extractor.py              # Field extraction (JSON/KV/XML/text)
│   ├── mapper.py                 # EAT keyword-match + scoring engine
│   ├── eat_table.py              # EAT synonym table (~150 entries)
│   ├── generator.py              # FortiSIEM XML parser builder
│   ├── simulator.py              # Parser simulation engine
│   ├── templates/
│   │   └── index.html            # Full UI (Alpine.js components)
│   └── static/
│       └── style.css
└── parser_studio.db              # SQLite database (auto-created on first run)
```

### Flask API Routes
| Method | Route | Purpose |
|---|---|---|
| GET | `/` | Serve the UI |
| POST | `/api/analyze` | Detect format + extract fields + return EAT suggestions |
| POST | `/api/generate` | Build XML from confirmed field mappings |
| POST | `/api/validate` | Check XML well-formedness |
| POST | `/api/test` | Simulate parser against samples, return parsed fields |
| GET | `/api/device-types` | List all device types |
| POST | `/api/device-types` | Add a new device type |
| POST | `/api/parsers/save` | Save parser + samples to SQLite |
| GET | `/api/parsers` | List saved parsers (studio-created + imported) |
| GET | `/api/parsers/<id>/download` | Download `.xml` file |
| POST | `/api/parsers/sync` | Re-scan `parsers/` directory and import new XML files |

---

## 4. Core Engine Modules

### 4.1 `detector.py` — Format Detection

Runs on all N samples; returns the majority-vote format label.

```
Detection order:
1. Syslog header present?
   MMM DD HH:MM:SS  →  ^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}
   ISO date          →  ^\d{4}-\d{2}-\d{2}T

2. Body after header:
   a. Starts with {           →  "syslog+json"
   b. Contains <\w+>          →  "syslog+xml"
   c. ≥3 key=value patterns   →  "syslog+kv"
   d. Otherwise               →  "syslog+text"

3. No syslog header:
   a. Valid JSON line          →  "json"
   b. KV patterns present      →  "kv"
   c. Otherwise                →  "text"
```

### 4.2 `extractor.py` — Field Extraction

| Format | Method | Example output |
|---|---|---|
| `syslog+json` | `json.loads()` + recursive flatten (dot notation) | `{"threatInfo.threatName": "Mimikatz"}` |
| `syslog+kv` | Regex `(\w[\w\s]*)=([^,\s]+)` and `\[(.+?)\]=(\S+)` (bracket-KV) | `{"srcip": "1.2.3.4"}` |
| `syslog+xml` | `xml.etree.ElementTree` + tag/attribute names + XPath predicates | `{"Event.System.EventID": "4624"}` |
| `syslog+text` | Tokenise by whitespace/punctuation; suggest gPat* per token | `{"_token1": "gPatIpAddr"}` |
| `json` | Same as `syslog+json` but applied to full line (no header strip) | `{"id": "abc", "type": "alert"}` |

Syslog header tokens (`_mon`, `_day`, `_time`, `_year`) are always pre-extracted and
auto-mapped to `deviceTime` — not shown in the field mapping panel.

Fields are merged across all samples. Fields absent in some samples are flagged
"optional" in the mapping panel.

### 4.3 `mapper.py` — EAT Suggestion Engine

Scores each extracted field name against `eat_table.py`:

| Score | Rule |
|---|---|
| 100 | Exact match (`"srcip"` → `srcIpAddr`) |
| 90 | Alias match (field in known synonym list) |
| 70 | Substring keyword match (`"ip"`, `"addr"` → IP-class EATs) |
| 50 | Semantic group match (looks like user/host/hash/time field) |
| < 30 | Flagged "unmapped — review manually" |

Returns top 3 suggestions per field. Highest-scored is pre-selected in the UI dropdown.

`eat_table.py` covers all standard FortiSIEM EATs with ~150 synonym entries grouped
by semantic category: IP, hostname, user, hash, timestamp, protocol, action, message,
severity, process, file, session.

### 4.4 `generator.py` — XML Parser Builder

Input: confirmed `{field → EAT}` mappings + parser metadata + detected format.

Output: complete `<eventParser>` XML ready for import into FortiSIEM.

Build sequence:
1. Write skeleton: `<?xml?>`, `<eventParser>`, `<deviceType>`, `<patternDefinitions>`
2. Build `<eventFormatRecognizer>` from the unique tag/anchor identified in samples
3. Build `<parsingInstructions>`:
   - Step 1: `collectFieldsByRegex` for syslog header → `deviceTime` via `toDateTime()`
   - Step 2: format-appropriate extraction element:
     - `syslog+json` / `json` → `collectAndSetAttrByJSON`
     - `syslog+kv` (plain)    → `collectAndSetAttrByKeyValuePair`
     - `syslog+kv` (bracket)  → `collectAndSetAttrBySymbol` (symStart=`[`, symEnd=`]=`)
     - `syslog+xml`           → `collectFieldsByXPath` (with `[@Name='key']` predicates)
     - `syslog+text`          → `collectFieldsByRegex` with suggested gPat* tokens
   - Step 3: `setEventAttribute` for each confirmed EAT mapping
   - Step 4: `eventType` stub — static literal if no classification field detected;
     `combineMsgId()` pattern if a classification/action field was mapped
   - Step 5: `eventSeverity` default (5) with `<choose>` stub if a severity field mapped
4. All strings XML-escaped; comments use `=` separators (never `--` inside comments)

### 4.5 `simulator.py` — Parser Test Engine

Walks the generated `<parsingInstructions>` XML and replays each step against the raw
sample using Python equivalents of gPat* patterns and FortiSIEM functions. Returns:
- All extracted field values per sample
- Which EATs resolved and to what value
- Whether `eventType` and `eventSeverity` resolved
- Any steps that produced no output (flagged as warnings)

Replaces the manual `test_parser.py` / `test_threat_parser.py` scripts — the studio
generates and runs the test automatically without any manual Python writing.

---

## 5. Database Schema (SQLite)

```sql
CREATE TABLE device_types (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    vendor  TEXT NOT NULL,
    model   TEXT NOT NULL,
    version TEXT NOT NULL DEFAULT 'ANY'
);

CREATE TABLE parsers (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    scope       TEXT NOT NULL DEFAULT 'enabled',   -- 'enabled' | 'disabled'
    parser_type TEXT NOT NULL DEFAULT 'User',       -- 'System' | 'User'
    vendor      TEXT,
    model       TEXT,
    version     TEXT,
    xml_content TEXT,
    source      TEXT NOT NULL DEFAULT 'studio',    -- 'studio' | 'imported'
    file_path   TEXT,                              -- original file path if imported
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE test_samples (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    parser_id  INTEGER REFERENCES parsers(id) ON DELETE CASCADE,
    label      TEXT,           -- e.g. "Sample 1", "Attack event", etc.
    raw_log    TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

Seed data: `device_types` is pre-populated with common vendors on first run
(SentinelOne, Morphisec, Palo Alto, Cisco, Fortinet, Microsoft Windows, etc.).
User can add/edit/delete via the UI Device Types panel.

### Parser Auto-Import from `parsers/` Directory

On every startup, Flask scans the `parsers/` directory for `*.xml` files and imports
any file not already tracked in the `parsers` table (matched by `file_path`). This
handles both the initial seed (existing parsers) and future additions the user drops in.

Import logic (in `db.py`):
1. Glob `parsers/*.xml`
2. For each file: check if `file_path` already in `parsers` table → skip if yes
3. Parse XML: extract `name` attribute from `<eventParser name="...">`, vendor/model
   from `<deviceType>`, store raw XML as `xml_content`
4. Insert row with `source='imported'`, `file_path=<relative path>`

The UI also exposes a **"Sync from disk"** button that re-triggers this scan without
restarting the server — useful after dropping new files into `parsers/`.

---

## 6. UI Flow

```
┌─────────────────────────────────────────────────────────────┐
│  FortiSIEM Parser Studio                                    │
├─────────────────────────────────────────────────────────────┤
│  PARSER METADATA                                            │
│  Name: [________________]  Scope: [Enabled ▼]              │
│  Type: [User ▼]   Device: [SentinelOne ▼] [Singularity ▼]  │
│                            [ANY          ▼]                 │
├─────────────────────────────────────────────────────────────┤
│  EVENT LOG SAMPLES                          [+ Add Sample]  │
│  ┌─ Sample 1 ──────────────────────────────────────────┐   │
│  │ <textarea: paste raw log here>                      │   │
│  └─────────────────────────────────────────────────────┘   │
│  ┌─ Sample 2 ──────────────────────────────────────── ✕ ┐  │
│  │ <textarea: paste raw log here>                      │   │
│  └─────────────────────────────────────────────────────┘   │
│                                     [Analyze Samples →]     │
├─────────────────────────────────────────────────────────────┤
│  DETECTED FORMAT: syslog+json                               │
│  FIELD MAPPINGS  (confirm or adjust before generating)      │
│  ┌──────────────────────┬─────────────────────────────┐    │
│  │ JSON Field           │ FortiSIEM EAT               │    │
│  ├──────────────────────┼─────────────────────────────┤    │
│  │ threatInfo.threatName│ [msg              ▼] ✓      │    │
│  │ agentDetection.agentIp│[srcIpAddr        ▼] ✓      │    │
│  │ accountName          │ [customer         ▼] ✓      │    │
│  │ unknownField123      │ [-- unmapped --   ▼] ⚠      │    │
│  └──────────────────────┴─────────────────────────────┘    │
│                                     [Generate Parser →]     │
├─────────────────────────────────────────────────────────────┤
│  GENERATED XML                     [Validate] [Test] [Save] │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ <?xml version="1.0" ...>                            │   │
│  │ <eventParser name="...">                            │   │
│  │   ...                                               │   │
│  └─────────────────────────────────────────────────────┘   │
│                                          [Download .xml]    │
└─────────────────────────────────────────────────────────────┘
```

**Test modal** (opened by [Test] button): shows each sample in a tab. For each sample,
displays a table of every extracted EAT and its resolved value, plus pass/fail for
`eventType` and `eventSeverity` resolution.

**Validate** checks XML well-formedness inline (no modal) — shows a green checkmark or
red error with line number.

---

## 7. Key Design Decisions

| Decision | Choice | Reason |
|---|---|---|
| No npm / build step | Alpine.js via CDN | Zero toolchain friction for a developer tool |
| XML validation | Python `xml.etree` (no xmllint) | Works on any OS without extra install |
| gPat* patterns | Hardcoded Python dict (from 7.5.0 docs) | Authoritative source already in memory |
| EAT synonym table | Hardcoded `eat_table.py` | Stable set; easy to extend without DB migration |
| Device types | SQLite table, seeded on first run | User-editable via UI; persists across sessions |
| XML comment style | `<!-- === section === -->` (never `--`) | FortiSIEM XML import rule |
| Severity default | Always emit `<setEventAttribute attr="eventSeverity">5</setEventAttribute>` first | FortiSIEM parser best practice |
| No LLM/AI | Pure rule-based keyword scoring | Deterministic, offline, no API key needed |

---

## 8. Parser Library — Imported Parsers

All XML files in `parsers/` are treated as the **parser library**. On first run and on
demand, they are imported into the `parsers` table with `source='imported'`.

**Parsers pre-seeded from `parsers/`:**

| File | Vendor | Format |
|---|---|---|
| WinOSXMLParser.xml | Microsoft Windows | Syslog+XML (XPath) |
| SyslogNGParser.xml | Syslog-NG | Syslog text |
| SentinelOneCompleteParser.xml | SentinelOne | Syslog+JSON |
| SentinelOneScript.xml | SentinelOne | Syslog+JSON |
| PHJsonParser.xml | Proofpoint Honeynet | Pure JSON |
| PHGenAIParser.xml | Proofpoint GenAI | Syslog+Symbol-KV |
| ApacheParser.xml | Apache | Syslog+text regex |
| ArubaWLANParser.xml | Aruba | Syslog+KV (SNMP) |
| AstaroSecureGwParser.xml | Astaro | Syslog+KV |
| BindDNSParser.xml | ISC BIND | Syslog+text regex |
| BlueCoatAuthParser.xml | Blue Coat | Syslog+positional |
| BlueCoatParser.xml | Blue Coat SGOS | Syslog+text regex |
| BluecoatWebProxyParser.xml | Blue Coat | Syslog+text regex |
| CheckpointParser.xml | Check Point | Syslog+bracket-KV |

Future files dropped into `parsers/` are auto-detected on next startup or via
**"Sync from disk"** button in the UI. No restart required for sync.

---

## 9. Out of Scope (v1)

- FortiSIEM REST API integration (live device type pull, direct import)
- CEF format support
- CSV lookup table generation (`collectFieldsByCsvFile`)
- Multi-line log support (`list="begin"/"continue"/"end"`)
- SNMP trap format (positional with nested separators — parser import works, generation not yet)
- User authentication (local tool, single user)
