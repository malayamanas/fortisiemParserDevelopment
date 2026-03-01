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
    Deduplication is by relative file_path.
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
