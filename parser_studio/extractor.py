import re
import json
import xml.etree.ElementTree as ET
from parser_studio.detector import strip_syslog_header

_KV_PLAIN   = re.compile(r'(\b\w[\w\s]{0,20}?)=([^,\s"\']+)')
_KV_BRACKET = re.compile(r'\[([\w\s]+?)\]=([^\s,]+)')

# syslog+text body structure patterns for structured extraction
# NCSA Combined Log Format: [optional-code] IP ident authuser [ts] "request" status bytes ["ref" "ua"]
_NCSA_ACCESS_LOG_RE = re.compile(
    r'^(?:\d+\s+)?'                              # optional leading code
    r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+' # client_ip
    r'(\S+)\s+(\S+)\s+'                          # ident, authuser
    r'\[([^\]]+)\]\s+'                           # req_time in brackets
    r'"([^"]*)"\s+'                              # request in quotes
    r'(\d+)\s+(\S+)'                             # status_code, bytes
    r'(?:\s+"([^"]*)"\s+"([^"]*)")?'             # optional: referer, user_agent
)
# Error log: [timestamp] [module:level] [pid NNN] message
_SYSLOG_TEXT_ERROR_RE = re.compile(
    r'^\[([^\]]+)\]\s+\[([^\]]*)\](?:\s+\[pid\s+(\d+)[^\]]*\])?\s*(.*)'
)


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

    # syslog+text: try structured body patterns before falling back to tokens
    m = _NCSA_ACCESS_LOG_RE.match(body)
    if m:
        fields: dict[str, str] = {
            "client_ip":   m.group(1),
            "ident":       m.group(2),
            "authuser":    m.group(3),
            "req_time":    m.group(4),
            "request":     m.group(5),
            "status_code": m.group(6),
            "bytes":       m.group(7),
        }
        # Break request into method + uri_stem
        req_parts = m.group(5).split(None, 2)
        if len(req_parts) >= 2:
            fields["http_method"] = req_parts[0]
            fields["uri_stem"]    = req_parts[1]
        # Combined Log Format optional referer + user-agent
        if m.group(8) is not None:
            fields["referer"]    = m.group(8)
        if m.group(9):
            fields["user_agent"] = m.group(9)
        return fields
    m = _SYSLOG_TEXT_ERROR_RE.match(body)
    if m:
        result: dict[str, str] = {
            "err_time":  m.group(1),
            "log_level": m.group(2),
        }
        if m.group(3):
            result["pid"] = m.group(3)
        msg = (m.group(4) or "").strip()
        if msg:
            result["message"] = msg
        return result
    # fallback: whitespace tokens
    tokens = body.split()
    return {f"_token{i}": tok for i, tok in enumerate(tokens[:20])}


def _smart_split(s: str) -> list[str]:
    """Tokenise a log line respecting quoted strings and bracket-enclosed fields.

    Priority order (first match wins at each position):
      1. "..."  — double-quoted string (e.g. HTTP request, referer, user-agent)
      2. [...]  — bracket-enclosed field (e.g. Apache timestamp)
      3. \S+    — plain non-whitespace token

    Examples
    --------
    '192.168.1.1 - - [01/Jan/2025:00:00:00 +0000] "GET /index HTTP/1.1" 200 512'
    → ['192.168.1.1', '-', '-', '[01/Jan/2025:00:00:00 +0000]',
       '"GET /index HTTP/1.1"', '200', '512']
    """
    return re.findall(r'"[^"]*"|\[[^\]]*\]|\S+', s)


def build_whitespace_matrix(samples: list[str]) -> list[dict]:
    """Split each sample into tokens, respecting quoted and bracket-delimited fields.

    Returns one row per token position with per-sample values.
    Each row: {token: 'tok_N', values: [str, ...], consistent: bool}
    """
    clean = [s.strip() for s in samples if s.strip()]
    per_sample = [_smart_split(s) for s in clean]
    max_pos = max((len(toks) for toks in per_sample), default=0)
    rows = []
    for pos in range(max_pos):
        values = [toks[pos] if pos < len(toks) else '' for toks in per_sample]
        non_empty = [v for v in values if v]
        consistent = len(set(non_empty)) <= 1
        rows.append({'token': f'tok_{pos}', 'values': values, 'consistent': consistent})
    return rows


def build_token_matrix(samples: list[str], fmt: str) -> list[dict]:
    """
    Return one row per unique token across all samples.

    Each row:
      {
        "token":      str,          # field/token name
        "values":     [str, ...],   # one entry per sample (empty string if absent)
        "consistent": bool,         # True when all non-empty values are identical
      }
    Rows are sorted alphabetically by token name.
    """
    clean = [s.strip() for s in samples if s.strip()]
    per_sample = [_extract_one(s, fmt) for s in clean]
    all_tokens = sorted({k for d in per_sample for k in d})
    rows = []
    for token in all_tokens:
        values = [d.get(token, "") for d in per_sample]
        non_empty = [v for v in values if v]
        consistent = len(set(non_empty)) <= 1
        rows.append({"token": token, "values": values, "consistent": consistent})
    return rows


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
