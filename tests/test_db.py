import pytest
from parser_studio.db import (init_db, add_device_type, get_device_types,
                               save_parser, get_parsers, get_parser_by_id,
                               update_parser, save_samples, get_samples)

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

def test_update_parser(tmp_db):
    init_db(tmp_db)
    pid = save_parser(tmp_db, {
        "name": "Original", "scope": "enabled", "parser_type": "User",
        "vendor": "A", "model": "B", "version": "ANY",
        "xml_content": "<old/>", "source": "studio", "file_path": None,
    })
    update_parser(tmp_db, pid, {
        "name": "Updated", "scope": "disabled",
        "vendor": "X", "model": "Y", "version": "2.0",
        "xml_content": "<new/>",
    })
    p = get_parser_by_id(tmp_db, pid)
    assert p["name"] == "Updated"
    assert p["scope"] == "disabled"
    assert p["vendor"] == "X"
    assert p["xml_content"] == "<new/>"
    assert p["parser_type"] == "User"   # intentionally not updatable
    assert p["source"] == "studio"      # intentionally not updatable

def test_update_parser_not_found(tmp_db):
    init_db(tmp_db)
    with pytest.raises(ValueError, match="No parser with id=999"):
        update_parser(tmp_db, 999, {
            "name": "X", "scope": "enabled", "vendor": "V",
            "model": "M", "version": "ANY", "xml_content": "<x/>",
        })


# === Test Samples ===

def _make_parser(db):
    return save_parser(db, {
        "name": "S", "scope": "enabled", "parser_type": "User",
        "vendor": "V", "model": "M", "version": "ANY",
        "xml_content": "<patternDefinitions/>", "source": "studio", "file_path": None,
    })

def test_save_and_get_samples_preserves_order(tmp_db):
    init_db(tmp_db)
    pid = _make_parser(tmp_db)
    logs = ["alpha", "beta", "gamma", "delta"]
    save_samples(tmp_db, pid, [{"raw_log": s} for s in logs])
    rows = get_samples(tmp_db, pid)
    assert [r["raw_log"] for r in rows] == logs

def test_samples_sequence_no_stored(tmp_db):
    init_db(tmp_db)
    pid = _make_parser(tmp_db)
    save_samples(tmp_db, pid, [{"raw_log": "a"}, {"raw_log": "b"}, {"raw_log": "c"}])
    rows = get_samples(tmp_db, pid)
    assert [r["sequence_no"] for r in rows] == [0, 1, 2]

def test_save_samples_replaces_previous(tmp_db):
    init_db(tmp_db)
    pid = _make_parser(tmp_db)
    save_samples(tmp_db, pid, [{"raw_log": "old1"}, {"raw_log": "old2"}])
    save_samples(tmp_db, pid, [{"raw_log": "new1"}])
    rows = get_samples(tmp_db, pid)
    assert len(rows) == 1
    assert rows[0]["raw_log"] == "new1"

def test_resave_reordered_samples(tmp_db):
    """Re-saving with a different order must be reflected when loading."""
    init_db(tmp_db)
    pid = _make_parser(tmp_db)
    save_samples(tmp_db, pid, [{"raw_log": "alpha"}, {"raw_log": "beta"}, {"raw_log": "gamma"}])
    # Reorder: put gamma first
    save_samples(tmp_db, pid, [{"raw_log": "gamma"}, {"raw_log": "alpha"}])
    rows = get_samples(tmp_db, pid)
    assert [r["raw_log"] for r in rows] == ["gamma", "alpha"]

def test_get_samples_empty(tmp_db):
    init_db(tmp_db)
    pid = _make_parser(tmp_db)
    assert get_samples(tmp_db, pid) == []

def test_save_samples_sets_auto_label(tmp_db):
    init_db(tmp_db)
    pid = _make_parser(tmp_db)
    save_samples(tmp_db, pid, [{"raw_log": "x"}, {"raw_log": "y"}])
    rows = get_samples(tmp_db, pid)
    assert rows[0]["label"] == "Sample 1"
    assert rows[1]["label"] == "Sample 2"

def test_samples_cascade_deleted_with_parser(tmp_db):
    """Deleting a parser must cascade-delete its samples."""
    import sqlite3
    init_db(tmp_db)
    pid = _make_parser(tmp_db)
    save_samples(tmp_db, pid, [{"raw_log": "x"}])
    conn = sqlite3.connect(tmp_db)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("DELETE FROM parsers WHERE id=?", (pid,))
    conn.commit()
    conn.close()
    assert get_samples(tmp_db, pid) == []
