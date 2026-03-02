from parser_studio.mapper import suggest_mappings, ALL_EATS

def test_exact_match():
    result = suggest_mappings(["srcip"])
    assert result["srcip"][0]["eat"] == "srcIpAddr"
    assert result["srcip"][0]["score"] == 100

def test_alias_match():
    result = suggest_mappings(["sourceip"])
    assert result["sourceip"][0]["eat"] == "srcIpAddr"

def test_dot_notation_match():
    # "agentDetectionInfo.agentIp" -> srcIpAddr
    result = suggest_mappings(["agentDetectionInfo.agentIp"])
    assert result["agentDetectionInfo.agentIp"][0]["eat"] == "srcIpAddr"

def test_unknown_field():
    result = suggest_mappings(["xyzCustomField999"])
    assert result["xyzCustomField999"][0]["score"] < 30

def test_returns_top5():
    result = suggest_mappings(["user"])
    assert len(result["user"]) <= 5

def test_all_eats_populated():
    assert "srcIpAddr" in ALL_EATS
    assert "destIpAddr" in ALL_EATS
    assert "eventType" in ALL_EATS
    assert "eventSeverity" in ALL_EATS
    assert len(ALL_EATS) > 20

def test_message_field():
    # threatName is a real EAT in the DB — it should map directly to itself
    result = suggest_mappings(["threatName"])
    assert result["threatName"][0]["eat"] == "threatName"

def test_hash_field():
    result = suggest_mappings(["md5"])
    assert result["md5"][0]["eat"] == "hashMD5"

# === New tests for DB-backed multi-signal scoring ===

def test_db_eat_rows_expands_suggestions():
    """Custom EAT row from DB should appear in suggestions."""
    custom_rows = [
        {"name": "customSrcRegion", "display_name": "Source Region",
         "value_type": "STRING", "description": "source region for the event",
         "deprecated": False, "port_attr": False},
        {"name": "srcIpAddr", "display_name": "Source IP Address",
         "value_type": "IP", "description": "source IP address",
         "deprecated": False, "port_attr": False},
    ]
    result = suggest_mappings(["srcregion"], eat_rows=custom_rows)
    eat_names = [s["eat"] for s in result["srcregion"]]
    assert "customSrcRegion" in eat_names

def test_value_type_inference_ip():
    """Fields with IP sample values should boost IP-type EATs."""
    eat_rows = [
        {"name": "srcIpAddr", "display_name": "Source IP",
         "value_type": "IP", "description": "",
         "deprecated": False, "port_attr": False},
        {"name": "eventSeverity", "display_name": "Severity",
         "value_type": "UINT", "description": "",
         "deprecated": False, "port_attr": False},
    ]
    field_values = {"clientaddr": ["10.0.0.1", "192.168.1.1", "172.16.0.5"]}
    result = suggest_mappings(["clientaddr"], eat_rows=eat_rows, field_values=field_values)
    # srcIpAddr should score higher than eventSeverity because values are IPs
    suggestions = result["clientaddr"]
    names = [s["eat"] for s in suggestions]
    assert names.index("srcIpAddr") < names.index("eventSeverity")

def test_deprecated_eat_excluded():
    """Deprecated EAT rows must never appear in suggestions."""
    eat_rows = [
        {"name": "oldDeprecatedAttr", "display_name": "Old Field",
         "value_type": "STRING", "description": "oldfield description",
         "deprecated": True, "port_attr": False},
        {"name": "srcIpAddr", "display_name": "Source IP",
         "value_type": "IP", "description": "",
         "deprecated": False, "port_attr": False},
    ]
    result = suggest_mappings(["oldfield"], eat_rows=eat_rows)
    eat_names = [s["eat"] for s in result["oldfield"]]
    assert "oldDeprecatedAttr" not in eat_names

def test_confidence_label_high_medium_low():
    """Score thresholds should produce correct confidence labels."""
    eat_rows = [
        {"name": "srcIpAddr", "display_name": "Source IP",
         "value_type": "IP", "description": "",
         "deprecated": False, "port_attr": False},
        {"name": "xyzObscureAttr", "display_name": "Xyz Obscure",
         "value_type": "STRING", "description": "",
         "deprecated": False, "port_attr": False},
    ]
    # srcip exact synonym -> score 100 -> high confidence
    result = suggest_mappings(["srcip"], eat_rows=eat_rows)
    top = result["srcip"][0]
    assert top["eat"] == "srcIpAddr"
    assert top["confidence"] == "high"

    # Completely unknown field -> low confidence
    result2 = suggest_mappings(["zzz999unknown"], eat_rows=eat_rows)
    for s in result2["zzz999unknown"]:
        assert s["confidence"] in ("low", "medium", "high")
    if result2["zzz999unknown"]:
        assert result2["zzz999unknown"][0]["confidence"] in ("low", "medium")
