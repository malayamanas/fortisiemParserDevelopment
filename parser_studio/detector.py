import re
import json
from collections import Counter

# Standard syslog: "Jul 23 00:33:28" or "Jul  3 00:33:28"
_SYSLOG_HDR = re.compile(
    r'^(?:\w{3}|\d{1,2})\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}'
    r'(?:\s+\d{4})?'            # optional year
    r'(?:\s+\S+)?'              # optional hostname
    r'(?:\s+\S+)?'              # optional source IP
    r'\s*'
)
# ISO timestamp header: "2025-07-23T10:05:15"
_ISO_HDR = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}')

_KV_PLAIN   = re.compile(r'\b\w[\w\s]{0,30}?=\S+')
_KV_BRACKET = re.compile(r'\[[\w\s]+?\]=')
_XML_TAG    = re.compile(r'<\w[\w:.-]*[\s>]')


def strip_syslog_header(raw: str) -> tuple[str | None, str]:
    """Return (header_part, body_part). header is None if no syslog prefix found.

    For JSON payloads: advances past any log-type label (e.g. SENTINELONE_THREATS:)
    so the returned body starts at the first '{' character.
    For XML payloads: body starts at the first XML tag.
    For KV/text: body is everything after the standard syslog tokens.
    """
    m = _SYSLOG_HDR.match(raw) or _ISO_HDR.match(raw)
    if not m:
        return None, raw

    remainder = raw[m.end():]

    # Look for JSON body: find first { and validate
    brace_pos = remainder.find('{')
    if brace_pos >= 0:
        candidate = remainder[brace_pos:]
        try:
            json.loads(candidate)
            return raw[:m.end() + brace_pos], candidate
        except ValueError:
            pass

    # Look for XML body
    xml_m = _XML_TAG.search(remainder)
    if xml_m:
        return raw[:m.end() + xml_m.start()], remainder[xml_m.start():]

    # KV or text: return standard tokens as header, rest as body
    return m.group(0), remainder


def _classify_body(body: str) -> str:
    body = body.strip()
    # JSON: starts with { or [ (strip_syslog_header already advanced past any tag)
    if body.startswith("{") or body.startswith("["):
        try:
            json.loads(body)
            return "json"
        except ValueError:
            pass
    if _XML_TAG.search(body):
        return "xml"
    bracket_hits = len(_KV_BRACKET.findall(body))
    kv_hits = len(_KV_PLAIN.findall(body))
    if bracket_hits >= 2:
        return "bracket-kv"
    if kv_hits >= 3:
        return "kv"
    return "text"


def _classify_one(raw: str) -> str:
    hdr, body = strip_syslog_header(raw)
    body_type = _classify_body(body)
    if hdr is None:
        return body_type          # "json" | "kv" | "text"
    return f"syslog+{body_type}"  # "syslog+json" | "syslog+kv" | etc.


def detect_format(samples: list[str]) -> str:
    """Majority-vote format detection across all samples."""
    if not samples:
        return "syslog+text"
    counts = Counter(_classify_one(s) for s in samples if s.strip())
    return counts.most_common(1)[0][0]
