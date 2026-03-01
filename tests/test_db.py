import pytest
from parser_studio.db import init_db, add_device_type, get_device_types, save_parser, get_parsers, get_parser_by_id, update_parser

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
