import re
from collections import Counter

from parser_studio.detector import strip_syslog_header
from parser_studio.extractor import extract_fields

_RE_ACCESS_LOG_BODY = re.compile(r'^(?:\d+\s+)?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
_RE_ERROR_LOG_BODY  = re.compile(r'^\[')

# Header structure detection helpers
_YEAR_RE = re.compile(r'^\d{4}$')
_IP_RE   = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
_PRI_RE      = re.compile(r'^<\d{1,3}>')
_TZ_TOKEN_RE = re.compile(r'^(?:Z|UTC|GMT|[+-]\d{1,2}:?\d{2})$')

# Body timestamp field detection
_TS_FIELD_NAMES = frozenset({
    'timestamp', 'time', 'ts', 'datetime', 'date',
    'created_at', 'createdat', 'event_time', 'eventtime',
    'log_time', 'logtime', '@timestamp',
    'createdAt', 'eventTime', 'deviceTime', 'startTime', 'endTime',
    'req_time',   # Apache NCSA access log body timestamp (e.g. 17/Sep/2009:13:27:37 -0700)
})

# (value_pattern, toDateTime format string or epoch sentinel, description)
_TS_VALUE_PATTERNS = [
    (re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$'),
     "yyyy-MM-dd'T'HH:mm:ss.SSSSSS'Z'", "ISO 8601 microseconds UTC"),
    (re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$'),
     "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", "ISO 8601 milliseconds UTC"),
    (re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$'),
     "yyyy-MM-dd'T'HH:mm:ss'Z'", "ISO 8601 UTC"),
    (re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:?\d{2}$'),
     "yyyy-MM-dd'T'HH:mm:ssXXX", "ISO 8601 with TZ offset"),
    (re.compile(r'^\d{1,2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s[+-]\d{4}$'),
     "dd/MMM/yyyy:HH:mm:ss Z", "Apache NCSA access log timestamp with TZ"),
    (re.compile(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$'),
     "yyyy-MM-dd HH:mm:ss", "space-separated datetime (no TZ; verify UTC assumption)"),
    (re.compile(r'^\d{13}$'), "epoch_ms", "epoch milliseconds (UTC)"),
    (re.compile(r'^\d{10}$'), "epoch_s", "epoch seconds (UTC)"),
]


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


def _detect_header_structure(samples: list[str]) -> dict:
    """Return {'has_year': bool, 'has_ip': bool, 'has_tz': bool} from syslog header analysis.

    Examines tokens after the timestamp to determine whether year, source IP,
    and/or a timezone token appear in the syslog header before the body/tag.
    Uses majority vote across non-empty samples.  Returns the safe default
    when no syslog headers can be parsed — this preserves the existing
    behaviour for KV/JSON formats whose conftest samples include year and IP.
    """
    year_count = ip_count = tz_count = total = 0
    for s in (samples or []):
        if not s.strip():
            continue
        hdr, _ = strip_syslog_header(s)
        if hdr is None:
            continue
        total += 1
        pri_m = _PRI_RE.match(hdr)
        clean = hdr[pri_m.end():].strip() if pri_m else hdr.strip()
        tokens = clean.split()
        # Tokens: MON=0 DAY=1 TIME=2; year, IP, and TZ appear at index 3+
        for tok in tokens[3:]:
            if _YEAR_RE.match(tok):
                year_count += 1
                break
        for tok in tokens[3:]:
            if _IP_RE.match(tok):
                ip_count += 1
                break
        for tok in tokens[3:]:
            if _TZ_TOKEN_RE.match(tok):
                tz_count += 1
                break
    if total == 0:
        return {'has_year': True, 'has_ip': True, 'has_tz': False}  # safe default
    return {
        'has_year': year_count / total >= 0.5,
        'has_ip':   ip_count  / total >= 0.5,
        'has_tz':   tz_count  / total >= 0.5,
    }


def _detect_body_timestamp(fields: dict) -> dict | None:
    """Return {field, fmt_string, description} for first recognized timestamp field, or None.

    fields: output of extract_fields() — {name: {values: [...], optional: bool}}
    fmt_string is the Java SimpleDateFormat pattern for toDateTime(), or
    'epoch_s'/'epoch_ms' for epoch timestamps.
    Returns None if no recognized timestamp field is found.
    """
    ts_lower = {n.lower() for n in _TS_FIELD_NAMES}
    for field_name, info in fields.items():
        if field_name.lower() not in ts_lower:
            continue
        for val in info.get('values', []):
            for pat, fmt_string, desc in _TS_VALUE_PATTERNS:
                if pat.match(str(val)):
                    return {'field': field_name, 'fmt_string': fmt_string, 'description': desc}
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
    """Return switch/case XML for syslog+text based on detected body structures.

    The generic catch-all case is always emitted last so specific patterns
    (access_log, error_log) are tried first.
    """
    seen = []
    for s in structures:
        if s not in seen:
            seen.append(s)
    # Generic matches anything; keep it last so specific cases run first
    ordered = [s for s in seen if s != 'generic']
    if 'generic' in seen:
        ordered.append('generic')

    lines = ['    <switch>']
    for struct in ordered:
        if struct == 'access_log':
            lines += [
                '      <case>',
                '        <!-- NCSA Combined Log Format: [code] client ident user [ts] "method path proto" status bytes -->',
                '        <!-- _req_time captures the TZ-aware timestamp for Step 3b deviceTime override -->',
                '        <collectFieldsByRegex src="$_body">',
                '          <regex><![CDATA[(?:\\d+\\s+)?<srcIpAddr:gPatIpAddr>\\s+<:gPatStr>\\s+<_user:gPatStr>\\s+\\[<_req_time:gPatMesgBodyMin>\\]\\s+"<httpMethod:gPatStr>\\s+<uriStem:gPatStr>\\s+<:gPatStr>"\\s+<httpStatusCode:gPatInt>\\s+<recvBytes64:gPatStr>]]></regex>',
                '        </collectFieldsByRegex>',
                '      </case>',
            ]
        elif struct == 'error_log':
            lines += [
                '      <case>',
                '        <!-- Error log: [timestamp] [module:level] [pid NNN] message -->',
                '        <collectFieldsByRegex src="$_body">',
                '          <regex><![CDATA[\\[<:gPatMesgBodyMin>\\]\\s+\\[<logLevel:gPatStr>\\]\\s+<msg:gPatMesgBody>]]></regex>',
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
    name   = meta.get("name") or "CustomParser"
    _fallback_anchor = name.upper().replace(" ", "_")
    anchor = meta.get("anchor") or _fallback_anchor

    # Auto-detect log-type tag from sample bodies when anchor is blank/fallback
    if fmt.startswith("syslog") and anchor == _fallback_anchor:
        detected = _detect_log_tag(samples, fmt)
        if detected is not None:
            anchor = detected

    # Detect whether year, source IP, and TZ appear in the syslog header
    hdr_struct = _detect_header_structure(samples) if fmt.startswith("syslog") else {'has_year': True, 'has_ip': True, 'has_tz': False}
    has_year = hdr_struct['has_year']
    has_ip   = hdr_struct['has_ip']
    has_tz   = hdr_struct['has_tz']

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

    # Detect body timestamp field for Step 3b (JSON/KV/text formats)
    body_ts = None
    if fmt in ('syslog+json', 'json', 'syslog+kv', 'syslog+bracket-kv', 'syslog+text') and samples:
        try:
            sampled_fields = extract_fields(samples, fmt)
            body_ts = _detect_body_timestamp(sampled_fields)
        except Exception:
            pass

    has_pri = _has_syslog_pri(samples)
    pri_prefix = "<:gPatSyslogPRI>\\s*" if has_pri else ""

    # Build optional year/IP/TZ tokens from header structure detected in samples
    year_tok     = "\\s+<:gPatYear>"        if has_year else ""
    year_capture = "\\s+<_year:gPatYear>"   if has_year else ""
    ip_tok       = "\\s+<:gPatIpAddr>"      if has_ip   else ""
    tz_tok       = "\\s+<:gPatTimeZone>"    if has_tz   else ""
    tz_capture   = "\\s+<_tz:gPatTimeZone>" if has_tz   else ""

    # eventFormatRecognizer pattern
    if fmt.startswith("syslog"):
        recognizer = (
            f"{pri_prefix}<:gPatMon>\\s+<:gPatDay>\\s+<:gPatTime>"
            f"{year_tok}{tz_tok}\\s+<:gPatStr>{ip_tok}\\s+{anchor}"
        )
    else:
        recognizer = f'"type"\\s*:\\s*"'  # generic JSON anchor stub

    # Step-1 regex to extract the body variable
    if fmt.startswith("syslog"):
        anchor_token = anchor.rstrip(":")
        header_regex = (
            f"{pri_prefix}<_mon:gPatMon>\\s+<_day:gPatDay>\\s+<_time:gPatTime>"
            f"{year_capture}{tz_capture}\\s+<_devHost:gPatStr>{ip_tok}"
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
        if has_year and has_tz:
            dt_call    = 'toDateTime($_mon, $_day, $_year, $_time, $_tz)'
            dt_comment = 'Step 2: Set deviceTime from syslog header (TZ-aware; FortiSIEM normalises to UTC)'
        elif has_year:
            dt_call    = 'toDateTime($_mon, $_day, $_year, $_time)'
            dt_comment = 'Step 2: Set deviceTime from syslog header (no TZ; assumes UTC)'
        else:
            dt_call    = 'toDateTime($_mon, $_day, $_time)'
            dt_comment = 'Step 2: Set deviceTime from syslog header (no year or TZ; assumes UTC)'
        xml_lines += [
            '',
            f'  <!-- {dt_comment} -->',
            f'  <setEventAttribute attr="deviceTime">{dt_call}</setEventAttribute>',
        ]

    step3b_lines: list[str] = []
    if body_ts:
        field_var = body_ts['field']
        fmt_str   = body_ts['fmt_string']
        desc      = body_ts['description']
        step3b_lines.append('')
        step3b_lines.append(f'  <!-- Step 3b: Override deviceTime from body timestamp ({desc}) -->')
        if fmt == 'syslog+text' and field_var == 'req_time':
            # _req_time is captured as a private var by the access_log switch/case.
            # The <when> guard ensures this only fires for access-log lines (not error-log lines).
            step3b_lines.append('  <when test="exist _req_time">')
            step3b_lines.append(
                f'    <setEventAttribute attr="deviceTime">toDateTime($_req_time, "{fmt_str}")</setEventAttribute>')
            step3b_lines.append('  </when>')
        elif fmt_str == 'epoch_ms':
            step3b_lines.append(
                f'  <setEventAttribute attr="_epochSec">divide(${field_var}, 1000)</setEventAttribute>')
            step3b_lines.append(
                '  <setEventAttribute attr="deviceTime">$_epochSec</setEventAttribute>')
        elif fmt_str == 'epoch_s':
            step3b_lines.append(
                f'  <setEventAttribute attr="deviceTime">${field_var}</setEventAttribute>')
        else:
            step3b_lines.append(
                f'  <setEventAttribute attr="deviceTime">toDateTime(${field_var}, "{fmt_str}")</setEventAttribute>')

    xml_lines += [
        '',
        f'  <!-- Step 3: Extract fields ({_safe_comment(fmt)}) -->',
        extraction,
        *step3b_lines,
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
