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
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                parser_id   INTEGER REFERENCES parsers(id) ON DELETE CASCADE,
                sequence_no INTEGER NOT NULL DEFAULT 0,
                label       TEXT,
                raw_log     TEXT NOT NULL,
                created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS event_attributes (
                id                   INTEGER PRIMARY KEY AUTOINCREMENT,
                attribute_id         INTEGER,
                name                 TEXT NOT NULL UNIQUE,
                display_name         TEXT,
                value_type           TEXT,
                categories           TEXT,
                format_type          TEXT,
                special_type         TEXT,
                deprecated           INTEGER NOT NULL DEFAULT 0,
                used_by_rbac         INTEGER NOT NULL DEFAULT 0,
                description          TEXT,
                sys_defined          INTEGER NOT NULL DEFAULT 0,
                mandatory            INTEGER NOT NULL DEFAULT 0,
                es_attribute         TEXT,
                anonymize            INTEGER NOT NULL DEFAULT 0,
                allowed_incident_def INTEGER NOT NULL DEFAULT 1,
                event_codes          TEXT,
                natural_id_property  TEXT,
                natural_id           TEXT,
                audit_object_type    TEXT,
                port_attr            INTEGER NOT NULL DEFAULT 0,
                audit_object_value   TEXT,
                xml_id               TEXT,
                system_entity        INTEGER NOT NULL DEFAULT 1,
                last_modified        INTEGER,
                creation_time        INTEGER
            );
        """)
        # Migration: add sequence_no to existing test_samples tables
        try:
            conn.execute(
                "ALTER TABLE test_samples ADD COLUMN sequence_no INTEGER NOT NULL DEFAULT 0"
            )
        except Exception:
            pass  # column already exists

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
        rows = conn.execute("SELECT * FROM parsers ORDER BY id ASC").fetchall()
        return [dict(r) for r in rows]

def get_parser_by_id(db_path: str, parser_id: int) -> dict | None:
    with _conn(db_path) as conn:
        row = conn.execute("SELECT * FROM parsers WHERE id=?", (parser_id,)).fetchone()
        return dict(row) if row else None

def update_parser(db_path: str, parser_id: int, data: dict) -> None:
    """Update parser metadata and xml_content in the DB.

    Required keys in data: name, scope, vendor, model, version, xml_content.
    Raises ValueError if no parser with parser_id exists.
    Note: parser_type, source, file_path are intentionally not updated.
    """
    with _conn(db_path) as conn:
        cur = conn.execute(
            """UPDATE parsers
               SET name=:name, scope=:scope, vendor=:vendor, model=:model,
                   version=:version, xml_content=:xml_content
               WHERE id=:id""",
            {**data, "id": parser_id}
        )
        if cur.rowcount == 0:
            raise ValueError(f"No parser with id={parser_id}")

def sync_device_types(db_path: str, entries: list[tuple]) -> int:
    """Insert (vendor, model, version) tuples not already present. Returns count inserted."""
    with _conn(db_path) as conn:
        existing = {(r[0], r[1]) for r in
                    conn.execute("SELECT vendor, model FROM device_types").fetchall()}
        new = [e for e in entries if (e[0], e[1]) not in existing]
        if new:
            conn.executemany(
                "INSERT INTO device_types (vendor, model, version) VALUES (?,?,?)", new
            )
        return len(new)


def save_samples(db_path: str, parser_id: int, samples: list[dict]) -> None:
    """Replace all test samples for parser_id with the given list.

    sequence_no is set to the list index (0-based) so that retrieval order
    always matches the order they were provided, regardless of auto-increment IDs.
    """
    with _conn(db_path) as conn:
        conn.execute("DELETE FROM test_samples WHERE parser_id=?", (parser_id,))
        conn.executemany(
            "INSERT INTO test_samples (parser_id, sequence_no, label, raw_log) VALUES (?,?,?,?)",
            [(parser_id, i, s.get("label", f"Sample {i+1}"), s["raw_log"])
             for i, s in enumerate(samples)]
        )

def get_samples(db_path: str, parser_id: int) -> list[dict]:
    """Return test samples for parser_id ordered by sequence_no (then id for legacy rows)."""
    with _conn(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM test_samples WHERE parser_id=? ORDER BY sequence_no, id",
            (parser_id,)
        ).fetchall()
        return [dict(r) for r in rows]

def is_file_imported(db_path: str, file_path: str) -> bool:
    with _conn(db_path) as conn:
        row = conn.execute("SELECT id FROM parsers WHERE file_path=?", (file_path,)).fetchone()
        return row is not None


import json as _json
import time as _time

def sync_event_attributes(db_path: str, json_path: str) -> int:
    """Import EATs from a FortiSIEM Event Attributes JSON export.

    Skips entries whose name is already in the table.
    Returns count of newly inserted rows.
    """
    try:
        with open(json_path, encoding="utf-8") as f:
            records = _json.load(f)
    except (OSError, ValueError):
        return 0

    now_ms = int(_time.time() * 1000)
    inserted = 0

    with _conn(db_path) as conn:
        existing = {r[0] for r in conn.execute("SELECT name FROM event_attributes").fetchall()}
        rows = []
        for r in records:
            name = r.get("name")
            if not name or name in existing:
                continue
            rows.append((
                r.get("attributeId"),
                name,
                r.get("displayName"),
                r.get("valueType"),
                _json.dumps(r.get("categories")),
                r.get("formatType"),
                r.get("specialType"),
                int(bool(r.get("deprecated", False))),
                int(bool(r.get("usedByRbac", False))),
                r.get("description"),
                int(bool(r.get("sysDefined", False))),
                int(bool(r.get("mandatory", False))),
                r.get("esAttribute"),
                int(bool(r.get("anonymize", False))),
                int(bool(r.get("allowedIncidentDef", True))),
                _json.dumps(r.get("eventCodes", [])),
                r.get("naturalIdProperty"),
                r.get("naturalId"),
                r.get("auditObjectType"),
                int(bool(r.get("portAttr", False))),
                r.get("auditObjectValue"),
                r.get("xmlId"),
                int(bool(r.get("systemEntity", True))),
                r.get("lastModified", now_ms),
                r.get("creationTime", now_ms),
            ))
        if rows:
            conn.executemany(
                """INSERT INTO event_attributes
                   (attribute_id, name, display_name, value_type, categories,
                    format_type, special_type, deprecated, used_by_rbac, description,
                    sys_defined, mandatory, es_attribute, anonymize, allowed_incident_def,
                    event_codes, natural_id_property, natural_id, audit_object_type,
                    port_attr, audit_object_value, xml_id, system_entity,
                    last_modified, creation_time)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                rows,
            )
            inserted = len(rows)
    return inserted


def get_event_attributes(db_path: str, search: str = "",
                         value_type: str = "") -> list[dict]:
    """Return EATs filtered by optional name/displayName search and valueType."""
    sql = "SELECT * FROM event_attributes WHERE 1=1"
    params: list = []
    if search:
        sql += " AND (name LIKE ? OR display_name LIKE ?)"
        like = f"%{search}%"
        params += [like, like]
    if value_type:
        sql += " AND value_type = ?"
        params.append(value_type)
    sql += " ORDER BY name ASC"
    with _conn(db_path) as conn:
        rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]


def get_eat_value_types(db_path: str) -> list[str]:
    """Return sorted list of distinct valueType values in event_attributes."""
    with _conn(db_path) as conn:
        rows = conn.execute(
            "SELECT DISTINCT value_type FROM event_attributes "
            "WHERE value_type IS NOT NULL ORDER BY value_type"
        ).fetchall()
        return [r[0] for r in rows]


def get_eat_names(db_path: str) -> list[str]:
    """Return sorted list of all EAT names (for field-mapping dropdowns)."""
    with _conn(db_path) as conn:
        rows = conn.execute(
            "SELECT name FROM event_attributes ORDER BY name ASC"
        ).fetchall()
        return [r[0] for r in rows]
