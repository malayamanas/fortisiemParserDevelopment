import os
import glob
import xml.etree.ElementTree as ET
from parser_studio.db import is_file_imported, save_parser


def _parse_xml_meta(xml_path: str) -> dict | None:
    """
    Extract metadata and definition fragment from a parser XML file.

    Supports two formats:

    1. Complete <eventParser> document (xml_path contains the full wrapper):
       - Name, vendor, model, version are read from the wrapper / <deviceType>.
       - Stored xml_content = inner children EXCEPT <deviceType> (the definition
         fragment: <patternDefinitions>, <eventFormatRecognizer>,
         <parsingInstructions>, etc.).

    2. <patternDefinitions> fragment (multiple sibling root elements, no wrapper):
       - Name derived from filename stem; vendor/model left as 'Unknown'.
       - Stored xml_content = raw file content as-is.

    Returns None if the file cannot be parsed or is not a recognised format.
    """
    try:
        with open(xml_path, encoding="utf-8", errors="replace") as f:
            raw = f.read().strip()

        # Strip leading XML declaration and comments to find the root tag
        import re as _re
        content = raw
        # Remove <?xml ...?> declaration
        content = _re.sub(r'^\s*<\?xml[^?]*\?>\s*', '', content)
        # Remove leading XML comments (<!-- ... -->)
        content = _re.sub(r'^\s*(<!--.*?-->)\s*', '', content, flags=_re.DOTALL)
        content = content.strip()

        if content.startswith("<eventParser"):
            # --- Complete <eventParser> format ---
            root = ET.fromstring(content)
            if root.tag != "eventParser":
                return None
            name    = root.attrib.get("name",
                       os.path.splitext(os.path.basename(xml_path))[0])
            vendor  = root.findtext(".//Vendor")  or "Unknown"
            model   = root.findtext(".//Model")   or "Unknown"
            version = root.findtext(".//Version") or "ANY"
            # Store only the definition children (drop <deviceType> — it's metadata)
            fragment = "".join(
                ET.tostring(child, encoding="unicode")
                for child in root
                if child.tag != "deviceType"
            )
            return {
                "name": name, "vendor": vendor, "model": model,
                "version": version, "xml_content": fragment,
            }

        # --- Fragment format (<patternDefinitions> … siblings) ---
        # Validate by wrapping; fail cleanly if the content is not XML at all.
        try:
            ET.fromstring(f"<root>{content}</root>")
        except ET.ParseError:
            return None
        name = os.path.splitext(os.path.basename(xml_path))[0]
        return {
            "name": name, "vendor": "Unknown", "model": "Unknown",
            "version": "ANY", "xml_content": content,
        }

    except (OSError, ET.ParseError):
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
