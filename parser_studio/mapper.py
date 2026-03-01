import re
from parser_studio.eat_table import SYNONYMS, ALL_EATS

_STRIP = re.compile(r'[\s_.\-\[\](){}]')


def _normalise(name: str) -> str:
    """Lowercase and strip non-alphanumeric chars for fuzzy matching."""
    return _STRIP.sub("", name).lower()


def _score(field_norm: str, eat: str) -> int:
    """Return a match score 0-100 for (field_norm, eat) pair."""
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


def suggest_mappings(field_names: list[str]) -> dict[str, list[dict]]:
    """
    Returns {field_name: [{"eat": str, "score": int}, ...]} sorted by score desc.
    Top 3 suggestions per field. Fields with max score < 30 still return a
    suggestion but marked with score < 30.
    """
    result = {}
    for field in field_names:
        norm = _normalise(field)
        # Direct synonym lookup first
        if norm in SYNONYMS:
            best_eat = SYNONYMS[norm]
            suggestions = [{"eat": best_eat, "score": 100}]
            for eat in ALL_EATS:
                if eat != best_eat:
                    s = _score(norm, eat)
                    if s >= 50:
                        suggestions.append({"eat": eat, "score": s})
            suggestions = sorted(suggestions, key=lambda x: -x["score"])[:3]
        else:
            scores = [{"eat": eat, "score": _score(norm, eat)} for eat in ALL_EATS]
            scores.sort(key=lambda x: -x["score"])
            suggestions = scores[:3]
        result[field] = suggestions
    return result
