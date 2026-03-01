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

def test_returns_top3():
    result = suggest_mappings(["user"])
    assert len(result["user"]) <= 3

def test_all_eats_populated():
    assert "srcIpAddr" in ALL_EATS
    assert "destIpAddr" in ALL_EATS
    assert "eventType" in ALL_EATS
    assert "eventSeverity" in ALL_EATS
    assert len(ALL_EATS) > 20

def test_message_field():
    result = suggest_mappings(["threatName"])
    assert result["threatName"][0]["eat"] == "msg"

def test_hash_field():
    result = suggest_mappings(["md5"])
    assert result["md5"][0]["eat"] == "hashMD5"
