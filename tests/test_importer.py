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
