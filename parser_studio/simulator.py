import re
import json
import xml.etree.ElementTree as ET
from parser_studio.extractor import _flatten_json
from parser_studio.db import get_parsers

_GPATTERNS = {
    "gPatMon":         r'\w{3}|\d{1,2}',
    "gPatDay":         r'\d{1,2}',
    "gPatTime":        r'\d{1,2}:\d{1,2}:\d{1,2}',
    "gPatYear":        r'\d{2,4}',
    "gPatStr":         r'[^\s]+',
    "gPatIpAddr":      r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
    "gPatIpPort":      r'\d{1,5}',
    "gPatInt":         r'\d+',
    "gPatWord":        r'\w+',
    "gPatMesgBody":    r'.+',
    "gPatMesgBodyMin": r'.+?',
    "gPatHostName":    r'[\w.\-]+',
    "gPatFqdn":        r'\w+(?:\.\w+)+',
    "gPatStrDQ":       r'[^"]*',
    "gPatStrSQ":       r"[^']*",
    "gPatStrComma":    r'[^,]*',
}


def _fsm_regex_to_python(fsm_pattern: str) -> str:
    """Convert FSM <attr:gPat> capture syntax to Python named-group regex."""
    def replace_capture(m):
        attr     = m.group(1)
        pat_name = m.group(2)
        py_pat   = _GPATTERNS.get(pat_name, r'\S+')
        if attr:
            # Sanitise attr name: replace non-word chars with underscores
            safe = re.sub(r'\W', '_', attr)
            return f'(?P<{safe}>{py_pat})'
        return f'(?:{py_pat})'
    return re.sub(r'<([^:>]*):(\w+)>', replace_capture, fsm_pattern)


def _parse_fragment(xml_str: str) -> ET.Element | None:
    """
    Parse xml_str into an ET.Element.

    Accepts two formats:
    - Complete <eventParser>…</eventParser> document
    - <patternDefinitions>…<parsingInstructions>…  fragment (no wrapper)

    For the fragment case the content is wrapped in a temporary <eventParser>
    element so that ET can parse it and callers can use .find() uniformly.
    """
    stripped = xml_str.strip()
    # Strip leading XML comments / processing instructions to detect root tag
    candidate = re.sub(r'^(<\?[^?]*\?>|<!--.*?-->)\s*', '', stripped,
                       flags=re.DOTALL).strip()
    if candidate.startswith('<eventParser'):
        try:
            return ET.fromstring(stripped)
        except ET.ParseError:
            return None
    # Fragment: wrap so ET can parse multiple sibling elements
    try:
        return ET.fromstring(f'<eventParser>{stripped}</eventParser>')
    except ET.ParseError:
        return None


def _recognizer_matches(xml_str: str, raw: str) -> bool:
    """Return True if this parser's eventFormatRecognizer matches the raw log."""
    root = _parse_fragment(xml_str)
    if root is None:
        return False
    rec_elem = root.find("eventFormatRecognizer")
    if rec_elem is None:
        return False
    rec_text = (rec_elem.text or "").strip()
    try:
        py_pat = _fsm_regex_to_python(rec_text)
        return bool(re.search(py_pat, raw, re.DOTALL | re.IGNORECASE))
    except re.error:
        # Fall back: strip capture groups and treat as literal substring
        plain = re.sub(r'<[^>]+>', '', rec_text).strip()
        return bool(plain and plain in raw)


def _apply_function(func_str: str, attrs: dict) -> str:
    """Evaluate a setEventAttribute value expression."""
    s = func_str.strip()
    # Plain variable reference
    if s.startswith('$') and not re.match(r'\w+\(', s):
        return attrs.get(s.lstrip('$'), s)
    # Plain literal (no function call)
    if not re.search(r'\w+\(', s):
        return s

    m = re.match(r'toDateTime\((.+)\)', s)
    if m:
        args  = [a.strip().strip('"\'') for a in m.group(1).split(',')]
        parts = [attrs.get(a.lstrip('$'), a) for a in args[:4]]
        return " ".join(p for p in parts if p)

    m = re.match(r'combineMsgId\((.+)\)', s, re.DOTALL)
    if m:
        parts = []
        for tok in re.split(r',\s*', m.group(1)):
            tok = tok.strip().strip('"')
            parts.append(attrs.get(tok[1:], tok) if tok.startswith('$') else tok)
        return "".join(parts)

    # Unknown function — return as-is
    return s


def _eval_test(test: str, attrs: dict) -> bool:
    """Evaluate a when test= expression."""
    test = test.strip()
    patterns = [
        (r'^exist\s+(\S+)$',
         lambda m: m.group(1) in attrs and attrs[m.group(1)] != ""),
        (r'^not_exist\s+(\S+)$',
         lambda m: m.group(1) not in attrs or attrs[m.group(1)] == ""),
        (r'^\$(\S+)\s*=\s*[\'"](.+)[\'"]$',
         lambda m: attrs.get(m.group(1), "") == m.group(2)),
        (r'^\$(\S+)\s*!=\s*[\'"](.+)[\'"]$',
         lambda m: attrs.get(m.group(1), "") != m.group(2)),
        (r'^\$(\S+)\s+IN\s+[\'"](.+)[\'"]$',
         lambda m: attrs.get(m.group(1), "") in [v.strip() for v in m.group(2).split(',')]),
    ]
    for pat, fn in patterns:
        hit = re.match(pat, test)
        if hit:
            return fn(hit)
    return False


def _simulate_one(instructions_elem: ET.Element, raw: str) -> dict:
    """Walk parsingInstructions XML and simulate each step. Returns attrs dict."""
    attrs: dict[str, str] = {"_rawmsg": raw}

    for elem in instructions_elem:
        tag = elem.tag

        if tag == "collectFieldsByRegex":
            src_key = elem.attrib.get("src", "$_rawmsg").lstrip('$')
            src_val = attrs.get(src_key, raw)
            regex_elem = elem.find("regex")
            if regex_elem is not None and regex_elem.text:
                try:
                    m = re.search(
                        _fsm_regex_to_python(regex_elem.text.strip()),
                        src_val, re.DOTALL
                    )
                    if m:
                        attrs.update({k: v or "" for k, v in m.groupdict().items()})
                except re.error:
                    pass

        elif tag == "collectAndSetAttrByJSON":
            src_key = elem.attrib.get("src", "$_jsonBody").lstrip('$')
            src_val = attrs.get(src_key, "")
            start = src_val.find("{")
            if start != -1:
                try:
                    flat = _flatten_json(json.loads(src_val[start:]))
                    for km in elem.findall("attrKeyMap"):
                        v = flat.get(km.attrib["key"])
                        if v is not None:
                            attrs[km.attrib["attr"]] = v
                except (ValueError, KeyError):
                    pass

        elif tag == "collectAndSetAttrByKeyValuePair":
            src_key = elem.attrib.get("src", "$_body").lstrip('$')
            src_val = attrs.get(src_key, "")
            flat = {m.group(1).strip(): m.group(2)
                    for m in re.finditer(r'(\w[\w\s]{0,20}?)=([^\s,]+)', src_val)}
            for km in elem.findall("attrKeyMap"):
                if km.attrib["key"] in flat:
                    attrs[km.attrib["attr"]] = flat[km.attrib["key"]]

        elif tag == "setEventAttribute":
            attr = elem.attrib.get("attr", "")
            if attr:
                attrs[attr] = _apply_function(elem.text or "", attrs)

        elif tag == "when":
            if _eval_test(elem.attrib.get("test", ""), attrs):
                wrapper = ET.Element("p")
                wrapper.extend(list(elem))
                attrs.update(_simulate_one(wrapper, raw))

        elif tag == "choose":
            matched = False
            for child in elem:
                if child.tag == "when":
                    if not matched and _eval_test(child.attrib.get("test", ""), attrs):
                        matched = True
                        wrapper = ET.Element("p")
                        wrapper.extend(list(child))
                        attrs.update(_simulate_one(wrapper, raw))
                elif child.tag == "otherwise" and not matched:
                    wrapper = ET.Element("p")
                    wrapper.extend(list(child))
                    attrs.update(_simulate_one(wrapper, raw))

    return attrs


# ─────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────

def simulate(xml_str: str, samples: list[str]) -> list[dict]:
    """
    Single-parser mode. Returns one result dict per sample:
    {
      "fields": {eat: value, ...},   # public EATs (no _ prefix)
      "status": "pass" | "fail",     # pass = eventType present
    }
    Accepts both a complete <eventParser> document and a
    <patternDefinitions>…  fragment (see _parse_fragment).
    """
    root = _parse_fragment(xml_str)
    if root is None:
        return [{"fields": {}, "status": "fail", "error": "Invalid XML"}
                for _ in samples]

    instructions = root.find("parsingInstructions")
    if instructions is None:
        return [{"fields": {}, "status": "fail", "error": "No parsingInstructions"}
                for _ in samples]

    results = []
    for raw in samples:
        attrs  = _simulate_one(instructions, raw)
        public = {k: v for k, v in attrs.items() if not k.startswith("_")}
        status = "pass" if public.get("eventType") else "fail"
        results.append({"fields": public, "status": status})
    return results


def test_against_library(samples: list[str], db_path: str) -> dict:
    """
    Library mode — replicates FortiSIEM parser selection:
    All enabled parsers are tested in DB order (ascending id).
    The FIRST parser whose recognizer matches is the "primary" winner.

    Returns:
    {
      "total_enabled": int,
      "per_sample": [
        {
          "raw":           str,
          "matched_count": int,
          "first_match":   str | None,
          "parsers": [
            {
              "rank":           int,
              "name":           str,
              "vendor":         str,
              "model":          str,
              "matched":        bool,
              "primary":        bool,
              "status":         "pass"|"fail"|"skip",
              "fields":         dict,
              "event_type":     str,
              "event_severity": str,
            }
          ]
        }
      ]
    }
    """
    all_parsers = [p for p in get_parsers(db_path) if p["scope"] == "enabled"]
    total_enabled = len(all_parsers)

    per_sample = []
    for raw in samples:
        parser_rows = []
        matched_count = 0
        first_match   = None

        for rank, p in enumerate(all_parsers, start=1):
            xml_str = p.get("xml_content") or ""
            matched = _recognizer_matches(xml_str, raw) if xml_str else False

            if not matched:
                parser_rows.append({
                    "rank": rank, "name": p["name"],
                    "vendor": p.get("vendor", ""), "model": p.get("model", ""),
                    "matched": False, "primary": False,
                    "status": "skip", "fields": {},
                    "event_type": "", "event_severity": "",
                })
                continue

            matched_count += 1
            is_primary = first_match is None
            if is_primary:
                first_match = p["name"]

            sim = simulate(xml_str, [raw])[0]
            parser_rows.append({
                "rank":           rank,
                "name":           p["name"],
                "vendor":         p.get("vendor", ""),
                "model":          p.get("model", ""),
                "matched":        True,
                "primary":        is_primary,
                "status":         sim["status"],
                "fields":         sim["fields"],
                "event_type":     sim["fields"].get("eventType", ""),
                "event_severity": sim["fields"].get("eventSeverity", ""),
            })

        per_sample.append({
            "raw":           raw,
            "matched_count": matched_count,
            "first_match":   first_match,
            "parsers":       parser_rows,
        })

    return {"total_enabled": total_enabled, "per_sample": per_sample}


# Prevent pytest from mistaking this function for a test
test_against_library.__test__ = False
