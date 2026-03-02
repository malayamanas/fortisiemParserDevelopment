import re
from collections import Counter

from parser_studio.detector import strip_syslog_header

_RE_ACCESS_LOG_BODY = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
_RE_ERROR_LOG_BODY  = re.compile(r'^\[')


def _has_syslog_pri(samples: list[str]) -> bool:
    """Return True if >=60% of non-empty samples start with a syslog PRI tag <NNN>."""
    non_empty = [s for s in samples if s.strip()]
    if not non_empty:
        return False
    matches = sum(1 for s in non_empty if re.match(r"^<\d{1,3}>", s))
    return (matches / len(non_empty)) >= 0.6


_LOG_TAG_RE = re.compile(r'^[A-Za-z][\w._-]*:?$')


def _detect_log_tag(samples: list[str], fmt: str) -> str | None:
    """Return the dominant log-type tag token from syslog samples, or None.

    For syslog formats, strip the syslog header from each sample using
    strip_syslog_header. The last whitespace-delimited token of the header
    portion is the program tag (e.g. 'ApacheLog' or 'Apache_ErrorLog:').
    If that token matches ^[A-Za-z][\\w._-]*:?$ and appears in >50% of
    non-empty samples, return it. Otherwise return None.

    For non-syslog formats, always returns None.
    """
    if not fmt.startswith("syslog"):
        return None

    non_empty = [s for s in samples if s.strip()]
    if not non_empty:
        return None

    tags: list[str] = []
    for sample in non_empty:
        hdr, _body = strip_syslog_header(sample)
        if hdr is None:
            continue
        hdr_tokens = hdr.split()
        if not hdr_tokens:
            continue
        candidate = hdr_tokens[-1]
        if _LOG_TAG_RE.match(candidate):
            tags.append(candidate)

    if not tags:
        return None

    counts = Counter(tags)
    most_common_tag, count = counts.most_common(1)[0]
    if count / len(tags) > 0.5:
        return most_common_tag
    return None


def _classify_body_structure(body: str) -> str:
    """Classify syslog body structure: 'access_log', 'error_log', or 'generic'."""
    body = body.strip()
    if _RE_ACCESS_LOG_BODY.match(body):
        return 'access_log'
    if _RE_ERROR_LOG_BODY.match(body):
        return 'error_log'
    return 'generic'


def _generate_switch_extraction(structures: list[str]) -> str:
    """Return switch/case XML for syslog+text based on detected body structures."""
    seen = []
    for s in structures:
        if s not in seen:
            seen.append(s)

    lines = ['    <switch>']
    for struct in seen:
        if struct == 'access_log':
            lines += [
                '      <case>',
                '        <!-- NCSA Combined Log Format: client ident user [ts] "method path proto" status bytes -->',
                '        <collectFieldsByRegex src="$_body">',
                '          <regex><![CDATA[<srcIpAddr:gPatIpAddr>\\s+<:gPatStr>\\s+<:gPatStr>\\s+\\[<:gPatMesgBodyMin>\\]\\s+"<:gPatStr>\\s+<:gPatStr>\\s+<:gPatStr>"\\s+<:gPatInt>\\s+<:gPatInt>]]></regex>',
                '        </collectFieldsByRegex>',
                '      </case>',
            ]
        elif struct == 'error_log':
            lines += [
                '      <case>',
                '        <!-- Error log: [timestamp] [module:level] message -->',
                '        <collectFieldsByRegex src="$_body">',
                '          <regex><![CDATA[\\[<:gPatMesgBodyMin>\\]\\s+\\[<:gPatStr>\\]\\s+<msg:gPatMesgBody>]]></regex>',
                '        </collectFieldsByRegex>',
                '      </case>',
            ]
        else:  # generic
            lines += [
                '      <case>',
                '        <!-- Generic text: fill in your regex pattern -->',
                '        <collectFieldsByRegex src="$_body">',
                '          <regex><![CDATA[<msg:gPatMesgBody>]]></regex>',
                '        </collectFieldsByRegex>',
                '      </case>',
            ]
    lines += ['      <default/>', '    </switch>']
    return '\n'.join(lines)


def _safe_comment(text: str) -> str:
    """Ensure comment text never contains '--'."""
    return text.replace("--", "==")


def _extraction_element(fmt: str, mappings: dict[str, str], samples: list[str] | None = None) -> str:
    """Return the appropriate extraction XML block for the given format."""
    lines = []
    if fmt in ("syslog+json", "json"):
        lines.append('    <collectAndSetAttrByJSON src="$_jsonBody">')
        for field, eat in mappings.items():
            if not eat or eat == "_skip":
                continue
            lines.append(f'      <attrKeyMap attr="{eat}" key="{field}"/>')
        lines.append('    </collectAndSetAttrByJSON>')

    elif fmt in ("syslog+kv", "syslog+bracket-kv"):
        lines.append('    <collectAndSetAttrByKeyValuePair src="$_body">')
        for field, eat in mappings.items():
            if not eat or eat == "_skip":
                continue
            lines.append(f'      <attrKeyMap attr="{eat}" key="{field}"/>')
        lines.append('    </collectAndSetAttrByKeyValuePair>')

    elif fmt == "syslog+xml":
        lines.append('    <collectFieldsByXPath src="$_xmlBody">')
        for field, eat in mappings.items():
            if not eat or eat == "_skip":
                continue
            xpath = "/" + field.replace(".", "/")
            lines.append(f'      <attrKeyMap attr="{eat}" key="{xpath}"/>')
        lines.append('    </collectFieldsByXPath>')

    else:  # syslog+text — generate switch/case scaffold
        bodies = []
        for s in (samples or []):
            if s.strip():
                _hdr, body = strip_syslog_header(s)
                if body:
                    bodies.append(body)
        structures = [_classify_body_structure(b) for b in bodies] or ['generic']
        lines += _generate_switch_extraction(structures).splitlines()

    return "\n".join(lines)


def generate_parser(meta: dict, mappings: dict[str, str],
                    fmt: str, samples: list[str]) -> str:
    """
    Generate a FortiSIEM parser definition fragment (no <eventParser> wrapper).

    The fragment starts with <patternDefinitions> and contains
    <eventFormatRecognizer> and <parsingInstructions>.
    Parser metadata (name, vendor, model, version) is stored separately
    in the database and reconstructed into a full <eventParser> on download.

    meta keys: name, scope, parser_type, vendor, model, version, anchor
    mappings: {log_field: fortisiem_eat}
    fmt: detected format string
    """
    name   = meta.get("name", "CustomParser")
    _fallback_anchor = name.upper().replace(" ", "_")
    anchor = meta.get("anchor") or _fallback_anchor

    # Auto-detect log-type tag from sample bodies when anchor is blank/fallback
    if fmt.startswith("syslog") and anchor == _fallback_anchor:
        detected = _detect_log_tag(samples, fmt)
        if detected is not None:
            anchor = detected

    # Body variable name per format
    body_var = {
        "syslog+json":       "_jsonBody",
        "syslog+kv":         "_body",
        "syslog+bracket-kv": "_body",
        "syslog+xml":        "_xmlBody",
        "syslog+text":       "_body",
        "json":              "_jsonBody",
    }.get(fmt, "_body")

    extraction = _extraction_element(fmt, mappings, samples)

    has_pri = _has_syslog_pri(samples)
    pri_prefix = "<:gPatSyslogPRI>\\s*" if has_pri else ""

    # eventFormatRecognizer pattern
    if fmt.startswith("syslog"):
        recognizer = (
            f"{pri_prefix}<:gPatMon>\\s+<:gPatDay>\\s+<:gPatTime>\\s+<:gPatYear>"
            f"\\s+<:gPatStr>\\s+<:gPatIpAddr>\\s+{anchor}"
        )
    else:
        recognizer = f'"type"\\s*:\\s*"'  # generic JSON anchor stub

    # Step-1 regex to extract the body variable
    if fmt.startswith("syslog"):
        anchor_token = anchor.rstrip(":")
        header_regex = (
            f"{pri_prefix}<_mon:gPatMon>\\s+<_day:gPatDay>\\s+<_time:gPatTime>"
            f"\\s+<_year:gPatYear>\\s+<_devHost:gPatStr>\\s+<:gPatIpAddr>"
            f"\\s+{anchor_token}:?\\s+<{body_var}:gPatMesgBody>"
        )
    else:
        header_regex = f"<{body_var}:gPatMesgBody>"

    xml_lines = [
        f'<eventFormatRecognizer><![CDATA[{recognizer}]]></eventFormatRecognizer>',
        '<patternDefinitions>',
        '  <!-- Add custom patterns here if needed -->',
        '</patternDefinitions>',
        '',
        '<parsingInstructions>',
        '',
        '  <!-- Step 1: Parse header and extract body -->',
        '  <collectFieldsByRegex src="$_rawmsg">',
        f'    <regex><![CDATA[{header_regex}]]></regex>',
        '  </collectFieldsByRegex>',
    ]

    if fmt.startswith("syslog"):
        xml_lines += [
            '',
            '  <!-- Step 2: Set deviceTime from syslog header -->',
            '  <setEventAttribute attr="deviceTime">'
            'toDateTime($_mon, $_day, $_year, $_time)</setEventAttribute>',
        ]

    xml_lines += [
        '',
        f'  <!-- Step 3: Extract fields ({_safe_comment(fmt)}) -->',
        extraction,
        '',
        '  <!-- Step 4: Set eventType -->',
        f'  <setEventAttribute attr="eventType">{name}-Event</setEventAttribute>',
        '',
        '  <!-- Step 5: Set eventSeverity (default 5; add choose block to refine) -->',
        '  <setEventAttribute attr="eventSeverity">5</setEventAttribute>',
        '',
        '</parsingInstructions>',
    ]

    return "\n".join(xml_lines)
