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
        # strip_syslog_header already advanced to '{' for syslog+json
        # For pure json the entire line is the body
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

    # syslog+text: tokenise — return positional token suggestions
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
