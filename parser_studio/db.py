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
