import re
from parser_studio.eat_table import SYNONYMS, ALL_EATS

_STRIP = re.compile(r'[\s_.\-\[\](){}]')

# Regex patterns for value-type inference
_RE_IPV4 = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
_RE_HEX64 = re.compile(r'^[0-9a-fA-F]{64}$')
_RE_HEX40 = re.compile(r'^[0-9a-fA-F]{40}$')
_RE_HEX32 = re.compile(r'^[0-9a-fA-F]{32}$')
_RE_ISO_TS = re.compile(r'^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}')
_RE_EPOCH = re.compile(r'^\d{10,13}$')


def _normalise(name: str) -> str:
    """Lowercase and strip non-alphanumeric chars for fuzzy matching."""
    return _STRIP.sub("", name).lower()


def _infer_value_type(values: list[str]) -> str | None:
    """Inspect sample values and return an inferred type hint or None."""
    if not values:
        return None
    non_empty = [v for v in values if v]
    if not non_empty:
        return None

    ip_hits = sum(1 for v in non_empty if _RE_IPV4.match(v))
    if ip_hits / len(non_empty) >= 0.6:
        return "IP"

    ts_hits = sum(1 for v in non_empty if _RE_ISO_TS.match(v) or _RE_EPOCH.match(v))
    if ts_hits / len(non_empty) >= 0.6:
        return "DATE"

    hash_hits = sum(1 for v in non_empty
                    if _RE_HEX64.match(v) or _RE_HEX40.match(v) or _RE_HEX32.match(v))
    if hash_hits / len(non_empty) >= 0.6:
        return "hash"

    int_hits = sum(1 for v in non_empty if v.isdigit())
    if int_hits / len(non_empty) >= 0.8:
        try:
            nums = [int(v) for v in non_empty if v.isdigit()]
            if all(0 <= n <= 65535 for n in nums):
                return "UINT"
        except ValueError:
            pass

    return None


def _score(field_norm: str, eat: str) -> int:
    """Return a match score 0-100 for (field_norm, eat) pair against eat name only."""
    eat_norm = _normalise(eat)
    if field_norm == eat_norm:
        return 100
    if field_norm in SYNONYMS and SYNONYMS[field_norm] == eat:
        return 90
    # substring: eat keyword appears in field name
    eat_key = eat_norm.replace("ipaddr", "ip").replace("hostname", "host")
    if eat_key in field_norm or field_norm in eat_key:
        return 70
    # partial word match on camelCase segments
    for part in re.split(r'(?=[A-Z])', eat):
        p = part.lower()
        if len(p) > 3 and p in field_norm:
            return 50
    return 0


def _score_eat_row(field_norm: str, field_raw: str, eat_row: dict,
                   inferred_type: str | None) -> int:
    """Score a DB EAT row against the field using four signals."""
    eat_name = eat_row.get("name") or ""
    eat_display = eat_row.get("display_name") or ""
    eat_desc = eat_row.get("description") or ""
    eat_vtype = eat_row.get("value_type") or ""
    port_attr = bool(eat_row.get("port_attr"))

    # Signal 1: name match (existing logic)
    score = _score(field_norm, eat_name)

    # Signal 2: display name match (+20 bonus)
    if eat_display:
        disp_norm = _normalise(eat_display)
        if field_norm == disp_norm:
            score = max(score, 80)
        elif field_norm in disp_norm or disp_norm in field_norm:
            score += 20
        else:
            for part in re.split(r'(?=[A-Z]|\s)', eat_display):
                p = _normalise(part)
                if len(p) > 3 and p in field_norm:
                    score += 10
                    break

    # Signal 3: value-type inference (+25 bonus)
    if inferred_type:
        if inferred_type == "IP" and eat_vtype in ("IP", "IPADDRESS"):
            score += 25
        elif inferred_type == "DATE" and eat_vtype in ("DATE", "TIMESTAMP"):
            score += 25
        elif inferred_type == "hash" and "hash" in _normalise(eat_name):
            score += 25
        elif inferred_type == "UINT" and port_attr and "port" in field_norm:
            score += 25
        elif inferred_type == "UINT" and eat_vtype in ("UINT", "INT", "INTEGER"):
            score += 10

    # Signal 4: description keyword match (+10 bonus)
    if eat_desc and field_norm and field_norm in _normalise(eat_desc):
        score += 10

    return min(score, 100)


def _confidence(score: int) -> str:
    if score >= 70:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def suggest_mappings(
    field_names: list[str],
    eat_rows: list[dict] | None = None,
    field_values: dict | None = None,
) -> dict[str, list[dict]]:
    """
    Returns {field_name: [{"eat": str, "score": int, "confidence": str}, ...]}
    sorted by score desc. Top 5 suggestions per field.

    When eat_rows is provided (full DB rows), scores all non-deprecated EATs
    using four signals. Otherwise falls back to ALL_EATS (backwards-compatible).
    """
    # Build the EAT universe to score against
    if eat_rows:
        active_rows = [r for r in eat_rows if not r.get("deprecated")]
    else:
        active_rows = None

    result = {}
    for field in field_names:
        norm = _normalise(field)
        values = (field_values or {}).get(field, [])
        inferred_type = _infer_value_type(values)

        if active_rows is not None:
            # DB-backed multi-signal scoring
            scored = []
            for row in active_rows:
                s = _score_eat_row(norm, field, row, inferred_type)
                scored.append({"eat": row["name"], "score": s,
                               "confidence": _confidence(s)})
            scored.sort(key=lambda x: -x["score"])
            suggestions = scored[:5]
        else:
            # Legacy path: synonym lookup + ALL_EATS
            if norm in SYNONYMS:
                best_eat = SYNONYMS[norm]
                s = 100
                suggestions = [{"eat": best_eat, "score": s,
                                 "confidence": _confidence(s)}]
                for eat in ALL_EATS:
                    if eat != best_eat:
                        sc = _score(norm, eat)
                        if sc >= 50:
                            suggestions.append({"eat": eat, "score": sc,
                                                "confidence": _confidence(sc)})
                suggestions = sorted(suggestions, key=lambda x: -x["score"])[:5]
            else:
                scored = [{"eat": eat, "score": _score(norm, eat),
                           "confidence": _confidence(_score(norm, eat))}
                          for eat in ALL_EATS]
                scored.sort(key=lambda x: -x["score"])
                suggestions = scored[:5]

        result[field] = suggestions
    return result
