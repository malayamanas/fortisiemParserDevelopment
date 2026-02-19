#!/usr/bin/env python3
"""
FortiSIEM Parser Simulator: SentinelOneSingularityThreat.xml
=============================================================
Simulates each step of the threat parser against sample log events.
"""

import re
import json
from datetime import datetime, timezone

# ──────────────────────────────────────────────────────────────────────────────
# FortiSIEM global pattern equivalents
# ──────────────────────────────────────────────────────────────────────────────
G = {
    "gPatMon":      r"\w{3}",
    "gPatDay":      r"\d{1,2}",
    "gPatTime":     r"\d{2}:\d{2}:\d{2}",
    "gPatYear":     r"\d{4}",
    "gPatStr":      r"\S+",
    "gPatIpAddr":   r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    "gPatMesgBody": r".+",
}

# ──────────────────────────────────────────────────────────────────────────────
# Base sample JSON payload (realistic SentinelOne threat event)
# ──────────────────────────────────────────────────────────────────────────────
BASE_JSON = {
    "accountId": "225494730938493804",
    "accountName": "LabAccount",
    "agentId": "1245680559492378683",
    "agentIp": "10.0.1.50",
    "agentOsType": "windows",
    "agentVersion": "21.6.2.272",
    "createdAt": "2025-07-23T00:27:27.233611Z",
    "updatedAt": "2025-07-23T00:28:10.000000Z",
    "fileDisplayName": "AutoKMS.exe",
    "filePath": "\\Device\\HarddiskVolume2\\Windows\\AutoKMS\\AutoKMS.exe",
    "fileContentHash": "c3d10d8d9fce936e5ca32f930f20c8e703619f71",
    "groupId": "2082727358893743954",
    "groupName": "Default Group",
    "siteId": "208272323736",
    "siteName": "Default site",
    "id": "1251555311751427932",
    "threatId": "225494730938493804",
    "threatInfo": {
        "classification": "Malware",
        "classificationSource": "Static",
        "confidenceLevel": "malicious",
        "incidentStatus": "unresolved",
        "mitigationStatus": "not_mitigated",
        "threatName": "Trojan.Win32.AutoKMS",
        "md5": "5d41402abc4b2a76b9719d911017c592",
        "detectionType": "static",
        "analystVerdict": "undefined",
        "processUser": "SYSTEM",
        "initiatedBy": "agent_policy",
        "automaticallyResolved": False,
        "rebootRequired": False,
        "cloudVerdict": "malicious",
        "mitigatedPreemptively": False,
        "createdAt": "2025-07-23T00:27:27.233611Z",
    },
    "agentDetectionInfo": {
        "agentComputerName": "LAB01",
        "agentId": "1245680559492378683",
        "agentIp": "10.0.1.50",
        "agentIpV4": "10.0.1.50",
        "agentLastLoggedInUserName": "jsmith",
        "agentMitigationMode": "protect",
        "agentOsName": "Windows 10 Home",
        "agentOsRevision": "19041",
        "agentVersion": "21.6.2.272",
        "externalIp": "203.0.113.50",
        "groupId": "2082727358893743954",
        "groupName": "Default Group",
        "siteId": "208272323736",
        "siteName": "Default site",
        "agentDomain": "WORKGROUP",
        "agentUuid": "c29ca0cee8a0a989321495b78b1d256ab7189144",
    },
    "agentRealtimeInfo": {
        "agentComputerName": "LAB01",
        "agentId": "1245680559492378683",
        "agentIsActive": True,
        "agentMachineType": "laptop",
        "agentOsName": "Windows 10 Home",
        "agentOsType": "windows",
        "agentVersion": "21.6.2.272",
        "externalIp": "203.0.113.50",
    },
}

def make_log(override_threat_info=None, override_top=None, tag="SENTINELONE_THREATS"):
    """Build a syslog line from BASE_JSON with optional overrides."""
    payload = json.loads(json.dumps(BASE_JSON))  # deep copy
    if override_threat_info:
        payload["threatInfo"].update(override_threat_info)
    if override_top:
        payload.update(override_top)
    json_str = json.dumps(payload)
    return f"Jul 23 00:33:28 2025 yoursubdomain.sentinelone.net 1.1.1.1 {tag}: {json_str}"

# ──────────────────────────────────────────────────────────────────────────────
# Test cases
# ──────────────────────────────────────────────────────────────────────────────
TEST_CASES = [
    # label, log, expected_event_type, expected_severity
    (
        "Malware + not_mitigated (malicious)",
        make_log(),
        "SentinelOne-Singularity-Threat-Malware-not_mitigated",
        9,
    ),
    (
        "Malware + mitigated (malicious)",
        make_log({"mitigationStatus": "mitigated", "incidentStatus": "resolved",
                  "automaticallyResolved": True}),
        "SentinelOne-Singularity-Threat-Malware-mitigated",
        4,
    ),
    (
        "Ransomware + not_mitigated -> severity 10 override",
        make_log({"classification": "Ransomware", "confidenceLevel": "malicious",
                  "mitigationStatus": "not_mitigated", "threatName": "Ransom.Win32.WannaCry"}),
        "SentinelOne-Singularity-Threat-Ransomware-not_mitigated",
        10,
    ),
    (
        "PUA + suspicious + not_mitigated",
        make_log({"classification": "PUA", "confidenceLevel": "suspicious",
                  "mitigationStatus": "not_mitigated", "threatName": "PUA.Win32.Adware"}),
        "SentinelOne-Singularity-Threat-PUA-not_mitigated",
        7,
    ),
    (
        "Benign classification -> severity 2",
        make_log({"classification": "Benign", "confidenceLevel": "benign",
                  "mitigationStatus": "mitigated", "threatName": "Safe.Win32.Tool"}),
        "SentinelOne-Singularity-Threat-Benign-mitigated",
        2,
    ),
    (
        "No classification -> Generic fallback (malicious+not_mitigated -> sev 9)",
        make_log(override_threat_info={"classification": None, "threatName": "Unknown"}),
        "SentinelOne-Singularity-Threat-Generic",
        9,
    ),
    (
        "SKIP: Missing threatInfo -> recognizer fails",
        "Jul 23 00:33:28 2025 s1.example.com 1.1.1.1 SENTINELONE_THREATS: "
        '{"accountId":"123","accountName":"Lab","createdAt":"2025-07-23T00:27:27.233611Z"}',
        None,
        None,
    ),
    (
        "SKIP: Wrong tag (SENTINELONE_ACTIVITIES) -> recognizer fails",
        make_log(tag="SENTINELONE_ACTIVITIES"),
        None,
        None,
    ),
]

# ──────────────────────────────────────────────────────────────────────────────
# Recognizer
# ──────────────────────────────────────────────────────────────────────────────
RECOGNIZER_RE = re.compile(
    r"(?P<mon>{gPatMon})\s+(?P<day>{gPatDay})\s+(?P<time>{gPatTime})\s+"
    r"(?P<year>{gPatYear})\s+(?P<hostname>{gPatStr})\s+(?P<ip>{gPatIpAddr})\s+"
    r"SENTINELONE_THREATS:.*\"threatInfo\"".format(**G),
    re.DOTALL,
)

SYSLOG_RE = re.compile(
    r"(?P<_mon>{gPatMon})\s+(?P<_day>{gPatDay})\s+(?P<_time>{gPatTime})\s+"
    r"(?P<_year>{gPatYear})\s+(?P<_devHostname>{gPatStr})\s+{gPatIpAddr}\s+"
    r"SENTINELONE_THREATS:\s+(?P<_jsonBody>.+)".format(**G),
    re.DOTALL,
)

IP_RE = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")

def extract_ip(val):
    m = IP_RE.search(str(val)) if val else None
    return m.group(0) if m else None

JSON_MAPPINGS = [
    # (json_dotpath, fsm_attr)
    ("accountId",                                      "_s1AccountId"),
    ("accountName",                                    "customer"),
    ("agentId",                                        "_s1AgentId"),
    ("agentIp",                                        "_s1AgentIp"),
    ("agentOsType",                                    "_s1OsType"),
    ("agentVersion",                                   "_s1AgentVersion"),
    ("createdAt",                                      "_createdAt"),
    ("updatedAt",                                      "_updatedAt"),
    ("fileDisplayName",                                "fileName"),
    ("filePath",                                       "_filePath"),
    ("fileContentHash",                                "hashSHA1"),
    ("groupId",                                        "_s1GroupId"),
    ("groupName",                                      "_s1GroupName"),
    ("siteId",                                         "_s1SiteId"),
    ("siteName",                                       "_s1SiteName"),
    ("id",                                             "_s1EventId"),
    ("threatId",                                       "_s1ThreatId"),
    # threatInfo.*
    ("threatInfo.classification",                      "_classification"),
    ("threatInfo.classificationSource",                "_classificationSrc"),
    ("threatInfo.confidenceLevel",                     "_confidenceLevel"),
    ("threatInfo.incidentStatus",                      "_incidentStatus"),
    ("threatInfo.mitigationStatus",                    "_mitigationStatus"),
    ("threatInfo.threatName",                          "_threatName"),
    ("threatInfo.md5",                                 "hashMD5"),
    ("threatInfo.detectionType",                       "_detectionType"),
    ("threatInfo.analystVerdict",                      "_analystVerdict"),
    ("threatInfo.processUser",                         "_processUser"),
    ("threatInfo.initiatedBy",                         "_initiatedBy"),
    ("threatInfo.automaticallyResolved",               "_autoResolved"),
    ("threatInfo.rebootRequired",                      "_rebootRequired"),
    ("threatInfo.cloudVerdict",                        "_cloudVerdict"),
    ("threatInfo.mitigatedPreemptively",               "_mitigatedPreempt"),
    ("threatInfo.createdAt",                           "_threatCreatedAt"),
    # agentDetectionInfo.*
    ("agentDetectionInfo.agentComputerName",           "srcHostName"),
    ("agentDetectionInfo.agentIp",                     "_detectAgentIp"),
    ("agentDetectionInfo.externalIp",                  "_detectExternalIp"),
    ("agentDetectionInfo.agentLastLoggedInUserName",   "user"),
    ("agentDetectionInfo.agentMitigationMode",         "_agentMitigMode"),
    ("agentDetectionInfo.agentOsName",                 "_agentOsName"),
    ("agentDetectionInfo.agentUuid",                   "_agentUuid"),
    ("agentDetectionInfo.agentDomain",                 "_agentDomain"),
    # agentRealtimeInfo.*
    ("agentRealtimeInfo.agentIsActive",                "_rtIsActive"),
    ("agentRealtimeInfo.agentMachineType",             "_rtMachineType"),
    ("agentRealtimeInfo.agentOsType",                  "_rtOsType"),
    ("agentRealtimeInfo.externalIp",                   "_rtExternalIp"),
]

def json_get(obj, dotpath):
    cur = obj
    for k in dotpath.split("."):
        if isinstance(cur, dict):
            cur = cur.get(k)
        else:
            return None
    return cur

# ──────────────────────────────────────────────────────────────────────────────
# Severity logic (mirrors parser XML Step 11)
# ──────────────────────────────────────────────────────────────────────────────
def compute_severity(attrs):
    sev = 5
    cl = attrs.get("_confidenceLevel")
    ms = attrs.get("_mitigationStatus")
    cls = attrs.get("_classification")

    if cl == "malicious":
        sev = 8
        if ms == "not_mitigated":
            sev = 9
        elif ms == "mitigated":
            sev = 4
    elif cl == "suspicious":
        sev = 5
        if ms == "not_mitigated":
            sev = 7
    elif cl == "benign":
        sev = 2

    # Ransomware override
    if cls == "Ransomware" and ms == "not_mitigated":
        sev = 10
    return sev

# ──────────────────────────────────────────────────────────────────────────────
# Event type logic (mirrors parser XML Step 10)
# ──────────────────────────────────────────────────────────────────────────────
def compute_event_type(attrs):
    cls = attrs.get("_classification")
    ms  = attrs.get("_mitigationStatus")
    if cls:
        if ms:
            return f"SentinelOne-Singularity-Threat-{cls}-{ms}"
        return f"SentinelOne-Singularity-Threat-{cls}"
    return "SentinelOne-Singularity-Threat-Generic"

# ──────────────────────────────────────────────────────────────────────────────
# Simulation engine
# ──────────────────────────────────────────────────────────────────────────────
def simulate(label, raw_log, expected_type, expected_sev):
    sep = "=" * 72
    print(f"\n{sep}")
    print(f"  TEST      : {label}")
    print(f"  EXPECTED  : type={expected_type}  sev={expected_sev}")
    print(sep)

    print("\n[eventFormatRecognizer]")
    if not RECOGNIZER_RE.search(raw_log):
        print("  RESULT : NO MATCH -> Parser not invoked.")
        outcome = "SKIP"
        passed = expected_type is None
        print(f"  {'PASS' if passed else 'FAIL'}")
        return passed

    print("  RESULT : MATCH -> Parser invoked.")
    attrs = {}

    # Step 1
    m = SYSLOG_RE.match(raw_log)
    if not m:
        print("  ERROR: syslog header regex failed.")
        return False
    for k in ("_mon", "_day", "_time", "_year", "_devHostname"):
        attrs[k] = m.group(k)
    attrs["_jsonBody"] = m.group("_jsonBody").strip()
    print(f"\n[Step 1] Syslog header: {attrs['_mon']} {attrs['_day']} {attrs['_year']} "
          f"{attrs['_time']}  host={attrs['_devHostname']}")

    # Step 2
    try:
        dt_str = f"{attrs['_mon']} {attrs['_day']} {attrs['_year']} {attrs['_time']}"
        attrs["deviceTime"] = datetime.strptime(dt_str, "%b %d %Y %H:%M:%S")
        print(f"[Step 2] deviceTime = {attrs['deviceTime'].isoformat()}")
    except ValueError as e:
        print(f"[Step 2] WARNING: {e}")

    # Step 3: JSON
    print("\n[Step 3] JSON field extraction")
    try:
        obj = json.loads(attrs["_jsonBody"])
    except json.JSONDecodeError as e:
        print(f"  ERROR: JSON parse failed: {e}")
        return False

    for dotpath, fsm_attr in JSON_MAPPINGS:
        val = json_get(obj, dotpath)
        if val is not None:
            attrs[fsm_attr] = val
            dv = str(val)
            if len(dv) > 60:
                dv = dv[:60] + "..."
            print(f"  {fsm_attr:<30} = {dv}")

    # Step 4: eventTime
    ts = attrs.get("_threatCreatedAt") or attrs.get("_createdAt")
    if ts:
        try:
            attrs["eventTime"] = datetime.fromisoformat(
                ts.rstrip("Z")
            ).replace(tzinfo=timezone.utc)
            print(f"\n[Step 4] eventTime = {attrs['eventTime'].isoformat()}")
        except ValueError:
            print(f"\n[Step 4] WARNING: could not parse timestamp '{ts}'")

    # Step 5: msg
    if attrs.get("_threatName"):
        attrs["msg"] = attrs["_threatName"]
        print(f"[Step 5] msg = {attrs['msg']}")

    # Step 6: srcIpAddr
    ip = extract_ip(attrs.get("_detectAgentIp")) or extract_ip(attrs.get("_s1AgentIp"))
    if ip:
        attrs["srcIpAddr"] = ip
        print(f"[Step 6] srcIpAddr = {ip}")

    # Step 7: destIpAddr
    ip = extract_ip(attrs.get("_detectExternalIp")) or extract_ip(attrs.get("_rtExternalIp"))
    if ip:
        attrs["destIpAddr"] = ip
        print(f"[Step 7] destIpAddr = {ip}")

    # Step 8: procName
    if attrs.get("_processUser"):
        attrs["procName"] = attrs["_processUser"]
        print(f"[Step 8] procName = {attrs['procName']}")

    # Step 9: eventAction
    ms = attrs.get("_mitigationStatus")
    action_map = {"mitigated": 1, "not_mitigated": 2}
    attrs["eventAction"] = action_map.get(ms, 0)
    print(f"[Step 9] eventAction = {attrs['eventAction']} (mitigationStatus='{ms}')")

    # Step 10: eventType
    attrs["eventType"] = compute_event_type(attrs)
    print(f"\n[Step 10] eventType = {attrs['eventType']}")

    # Step 11: eventSeverity
    attrs["eventSeverity"] = compute_severity(attrs)
    print(f"[Step 11] eventSeverity = {attrs['eventSeverity']}")

    # Final summary
    print("\n[Final Event Attributes]")
    for attr in ["eventType", "eventSeverity", "deviceTime", "eventTime", "customer",
                 "srcHostName", "srcIpAddr", "destIpAddr", "user", "procName",
                 "msg", "fileName", "hashSHA1", "hashMD5", "eventAction"]:
        val = attrs.get(attr)
        if val is not None:
            dv = str(val)
            if len(dv) > 70:
                dv = dv[:70] + "..."
            print(f"  {attr:<20} = {dv}")

    # Verdict
    type_ok = attrs.get("eventType") == expected_type
    sev_ok  = attrs.get("eventSeverity") == expected_sev
    passed  = type_ok and sev_ok
    print(f"\n  eventType  : {'PASS' if type_ok else 'FAIL'}  got={attrs.get('eventType')}  want={expected_type}")
    print(f"  severity   : {'PASS' if sev_ok  else 'FAIL'}  got={attrs.get('eventSeverity')}  want={expected_sev}")
    print(f"  OVERALL    : {'PASS' if passed else 'FAIL'}")
    return passed


# ──────────────────────────────────────────────────────────────────────────────
# Run
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("FortiSIEM Parser Simulator: SentinelOneSingularityThreat.xml")
    print("=" * 72)

    results = []
    for label, log, exp_type, exp_sev in TEST_CASES:
        ok = simulate(label, log, exp_type, exp_sev)
        results.append((label, ok))

    print("\n" + "=" * 72)
    print("SUMMARY")
    print("=" * 72)
    passed = sum(1 for _, ok in results if ok)
    for label, ok in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    print(f"\n{passed}/{len(results)} tests passed.")
