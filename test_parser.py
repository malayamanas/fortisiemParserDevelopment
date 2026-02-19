#!/usr/bin/env python3
"""
FortiSIEM Parser Simulator: SentinelOneSingularity
====================================================
Simulates each step of SentinelOneSingularity.xml against test log events.

FortiSIEM global pattern equivalents used:
  gPatMon       -> \\w{3}
  gPatDay       -> \\d{1,2}
  gPatTime      -> \\d{2}:\\d{2}:\\d{2}
  gPatYear      -> \\d{4}
  gPatStr       -> \\S+
  gPatIpAddr    -> \\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}
  gPatMesgBody  -> .+
"""

import re
import json
from datetime import datetime, timezone
from textwrap import dedent

# ──────────────────────────────────────────────────────────────────────────────
# Test log definitions
# ──────────────────────────────────────────────────────────────────────────────

# Original sample log from the user (no incidentStatus key → should NOT match)
LOG_NO_INCIDENT_STATUS = (
    'Jul 23 00:33:28 2025 yoursubdomain.sentinelone.net 1.1.1.1 '
    'SENTINELONE_ACTIVITIES: {"accountId": "2082727357056638789", "accountName": "LabAccount", '
    '"activityType": 5232, "activityUuid": "2f9843ee-69c5-4fcb-b00e-257d8d0a44f6", '
    '"agentId": "242311111107991", "agentUpdatedVersion": null, "comments": null, '
    '"createdAt": "2025-07-23T00:27:27.233611Z", '
    '"data": {"accountName": "LabAccount", "action": "Block", "application": null, '
    '"applicationType": "any", "computerName": "LAB01", '
    '"createdByUsername": "test.user@example.com", "direction": "any", '
    '"durationOfMeasurement": 60, '
    '"fullScopeDetails": "Group Default Group in Site Default site of Account LabAccount", '
    '"fullScopeDetailsPath": "Global / LabAccount / Default site / Default Group", '
    '"groupName": "Default Group", "ipAddress": "2.2.2.2", "localHost": null, '
    '"localHostType": "any", "localPortType": "any", "localPorts": null, '
    '"locationNames": ["Fallback", "Prod2 Ext"], "numberOfEvents": 8, "order": 48, '
    '"osTypes": ["windows"], "processId": 1820, '
    '"processName": "\\\\device\\\\harddiskvolume2\\\\windows\\\\system32\\\\svchost.exe", '
    '"protocol": null, "remoteHostTypes": ["range"], '
    '"remoteHosts": ["224.0.0.0", "239.255.255.255"], "remotePortType": "any", '
    '"remotePorts": null, "reportedDirection": "outbound", "reportedLocalHost": null, '
    '"reportedLocalPort": "", "reportedProtocol": "", "reportedRemoteHost": "224.0.0.252", '
    '"reportedRemotePort": "", "ruleDescription": null, '
    '"ruleId": 2255188848135565064, '
    '"ruleName": "Block broadcast and multicast traffic-external", '
    '"ruleScopeLevel": "account", "ruleScopeName": "LabAccount", '
    '"siteName": "Default site", "status": "Enabled", "tagNames": []}, '
    '"description": null, "groupId": "2082727358893743954", "groupName": "Default Group", '
    '"hash": null, "id": "2264937978012492262", "osFamily": null, '
    '"primaryDescription": "Firewall Control blocked traffic on the Endpoint LAB01 because of '
    'rule Block broadcast and multicast traffic-external in account LabAccount.", '
    '"secondaryDescription": "IP address: 1.1.1.1", "siteId": "208272323736", '
    '"siteName": "Default site", "threatId": null, '
    '"updatedAt": "2025-07-23T00:27:27.233612Z", "userId": null}'
)

# Test log 1: incidentStatus=not_mitigated + recent createdAt (today) → ACTIVE event
_today = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000000Z")
LOG_ACTIVE = LOG_NO_INCIDENT_STATUS.replace(
    '"activityType": 5232',
    '"activityType": 5232, "incidentStatus": "not_mitigated"'
).replace(
    '"createdAt": "2025-07-23T00:27:27.233611Z"',
    f'"createdAt": "{_today}"'
)

# Test log 2: incidentStatus=not_mitigated + old createdAt (6 days ago) → STALE event
LOG_STALE = LOG_NO_INCIDENT_STATUS.replace(
    '"activityType": 5232',
    '"activityType": 5232, "incidentStatus": "not_mitigated"'
)  # keeps original 2025-07-23 date → will be > 5 days old in 2026

# Test log 3: incidentStatus=mitigated → should NOT match recognizer
LOG_MITIGATED = LOG_NO_INCIDENT_STATUS.replace(
    '"activityType": 5232',
    '"activityType": 5232, "incidentStatus": "mitigated"'
).replace(
    '"createdAt": "2025-07-23T00:27:27.233611Z"',
    f'"createdAt": "{_today}"'
)

TEST_CASES = [
    ("ORIGINAL (no incidentStatus key)",   LOG_NO_INCIDENT_STATUS, "SKIP"),
    ("ACTIVE   (not_mitigated + recent)",  LOG_ACTIVE,             "ACTIVE"),
    ("STALE    (not_mitigated + 6d old)",  LOG_STALE,              "STALE"),
    ("FILTERED (mitigated + recent)",      LOG_MITIGATED,          "SKIP"),
]

# ──────────────────────────────────────────────────────────────────────────────
# FortiSIEM global pattern equivalents (Python regex)
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
# Helper: simulate eventFormatRecognizer
# ──────────────────────────────────────────────────────────────────────────────
RECOGNIZER_RE = re.compile(
    r"(?P<mon>{gPatMon})\s+(?P<day>{gPatDay})\s+(?P<time>{gPatTime})\s+"
    r"(?P<year>{gPatYear})\s+(?P<hostname>{gPatStr})\s+(?P<ip>{gPatIpAddr})\s+"
    r"SENTINELONE_ACTIVITIES:.*\"incidentStatus\"\s*:\s*\"not_mitigated\"".format(**G),
    re.DOTALL
)

# ──────────────────────────────────────────────────────────────────────────────
# Helper: simulate syslog header collectFieldsByRegex (Step 1)
# ──────────────────────────────────────────────────────────────────────────────
SYSLOG_HEADER_RE = re.compile(
    r"(?P<_mon>{gPatMon})\s+(?P<_day>{gPatDay})\s+(?P<_time>{gPatTime})\s+"
    r"(?P<_year>{gPatYear})\s+(?P<_devHostname>{gPatStr})\s+{gPatIpAddr}\s+"
    r"SENTINELONE_ACTIVITIES:\s+(?P<_jsonBody>.+)".format(**G),
    re.DOTALL
)

# ──────────────────────────────────────────────────────────────────────────────
# Helper: resolve first IPv4 from a string value
# ──────────────────────────────────────────────────────────────────────────────
IP_RE = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")

def extract_ip(val):
    m = IP_RE.search(str(val)) if val else None
    return m.group(0) if m else None

# ──────────────────────────────────────────────────────────────────────────────
# JSON key mappings: (json_key, fsm_attr)
# Top-level keys and nested data.* keys (dot notation)
# ──────────────────────────────────────────────────────────────────────────────
JSON_MAPPINGS = [
    # Top-level
    ("accountId",            "_s1AccountId"),
    ("accountName",          "customer"),
    ("activityType",         "_activityType"),
    ("activityUuid",         "_activityUuid"),
    ("agentId",              "_agentId"),
    ("incidentStatus",       "_incidentStatus"),
    ("createdAt",            "_createdAt"),
    ("updatedAt",            "_updatedAt"),
    ("groupId",              "_s1GroupId"),
    ("groupName",            "_s1GroupName"),
    ("siteId",               "_s1SiteId"),
    ("siteName",             "_s1SiteName"),
    ("id",                   "_s1EventId"),
    ("threatId",             "_s1ThreatId"),
    ("userId",               "_s1UserId"),
    ("osFamily",             "_s1OsFamily"),
    ("primaryDescription",   "msg"),
    ("secondaryDescription", "_secondaryDesc"),
    # Nested data.*
    ("data.computerName",        "srcHostName"),
    ("data.ipAddress",           "_dataIpAddr"),
    ("data.processName",         "procName"),
    ("data.processId",           "_dataProcId"),
    ("data.ruleName",            "policyName"),
    ("data.ruleId",              "_dataRuleId"),
    ("data.ruleScopeLevel",      "_dataRuleScopeLevel"),
    ("data.ruleScopeName",       "_dataRuleScopeName"),
    ("data.action",              "_dataAction"),
    ("data.direction",           "_dataDirection"),
    ("data.reportedDirection",   "_dataReportedDir"),
    ("data.protocol",            "_dataProtocol"),
    ("data.reportedRemoteHost",  "_dataRemoteHost"),
    ("data.reportedRemotePort",  "_dataRemotePort"),
    ("data.reportedLocalHost",   "_dataLocalHost"),
    ("data.reportedLocalPort",   "_dataLocalPort"),
    ("data.status",              "_dataStatus"),
    ("data.fullScopeDetails",    "_dataFullScope"),
    ("data.numberOfEvents",      "_dataNumEvents"),
    ("data.createdByUsername",   "_dataCreatedBy"),
]

def json_get(obj, dotpath):
    """Traverse a JSON object using dot-notation path."""
    keys = dotpath.split(".")
    cur = obj
    for k in keys:
        if isinstance(cur, dict):
            cur = cur.get(k)
        else:
            return None
    return cur

# ──────────────────────────────────────────────────────────────────────────────
# Main parser simulation
# ──────────────────────────────────────────────────────────────────────────────
def simulate_parser(label, raw_log, expected):
    sep = "=" * 72
    print(f"\n{sep}")
    print(f"  TEST CASE : {label}")
    print(f"  EXPECTED  : {expected}")
    print(sep)

    # ── eventFormatRecognizer ─────────────────────────────────────────────────
    print("\n[eventFormatRecognizer]")
    if not RECOGNIZER_RE.search(raw_log):
        print("  RESULT : NO MATCH  -> Parser not invoked for this log.")
        print(f"  {'PASS' if expected == 'SKIP' else 'FAIL'} (expected: {expected})")
        return
    print("  RESULT : MATCH     -> Parser invoked.")

    attrs = {}   # simulated FortiSIEM event attribute store

    # ── Step 1: syslog header + JSON body ────────────────────────────────────
    print("\n[Step 1] Syslog header parse")
    m = SYSLOG_HEADER_RE.match(raw_log)
    if not m:
        print("  ERROR: syslog header regex did not match.")
        return
    attrs["_mon"]         = m.group("_mon")
    attrs["_day"]         = m.group("_day")
    attrs["_time"]        = m.group("_time")
    attrs["_year"]        = m.group("_year")
    attrs["_devHostname"] = m.group("_devHostname")
    attrs["_jsonBody"]    = m.group("_jsonBody").strip()
    print(f"  _mon          = {attrs['_mon']}")
    print(f"  _day          = {attrs['_day']}")
    print(f"  _time         = {attrs['_time']}")
    print(f"  _year         = {attrs['_year']}")
    print(f"  _devHostname  = {attrs['_devHostname']}")
    print(f"  _jsonBody     = {attrs['_jsonBody'][:80]}...")

    # ── Step 2: deviceTime ───────────────────────────────────────────────────
    print("\n[Step 2] deviceTime")
    try:
        device_time_str = (
            f"{attrs['_mon']} {attrs['_day']} {attrs['_year']} {attrs['_time']}"
        )
        attrs["deviceTime"] = datetime.strptime(device_time_str, "%b %d %Y %H:%M:%S")
        print(f"  deviceTime    = {attrs['deviceTime'].isoformat()}")
    except ValueError as e:
        print(f"  WARNING: could not parse deviceTime: {e}")

    # ── Step 3: JSON field extraction ────────────────────────────────────────
    print("\n[Step 3] JSON field extraction (collectAndSetAttrByJSON)")
    try:
        json_obj = json.loads(attrs["_jsonBody"])
    except json.JSONDecodeError as e:
        print(f"  ERROR: JSON parse failed: {e}")
        return

    for json_key, fsm_attr in JSON_MAPPINGS:
        val = json_get(json_obj, json_key)
        if val is not None:
            attrs[fsm_attr] = val
            display_val = str(val)
            if len(display_val) > 60:
                display_val = display_val[:60] + "..."
            print(f"  {fsm_attr:<28} = {display_val}")

    # ── Step 4: eventTime + age ──────────────────────────────────────────────
    print("\n[Step 4] eventTime + _ageMs (5-day gate)")
    created_at_str = attrs.get("_createdAt")
    if created_at_str:
        # Strip trailing Z and parse (handle microseconds)
        ts_str = created_at_str.rstrip("Z")
        try:
            event_time = datetime.fromisoformat(ts_str).replace(tzinfo=timezone.utc)
            attrs["eventTime"] = event_time
            now = datetime.now(timezone.utc)
            age_ms = int((now - event_time).total_seconds() * 1000)
            attrs["_ageMs"] = age_ms
            age_days = age_ms / 86400000
            print(f"  eventTime     = {event_time.isoformat()}")
            print(f"  now()         = {now.isoformat()}")
            print(f"  _ageMs        = {age_ms:,} ms  ({age_days:.2f} days)")
            print(f"  Threshold     = 432,000,000 ms (5 days)")
            print(f"  Within 5 days = {'YES' if age_ms <= 432000000 else 'NO'}")
        except ValueError as e:
            print(f"  WARNING: could not parse createdAt '{created_at_str}': {e}")
    else:
        print("  WARNING: _createdAt not found in JSON payload.")

    # ── Steps 5-10: field resolution ─────────────────────────────────────────
    print("\n[Steps 5-10] Field resolution")

    # Step 5: srcIpAddr
    ip = extract_ip(attrs.get("_dataIpAddr"))
    if ip:
        attrs["srcIpAddr"] = ip
        print(f"  srcIpAddr     = {ip}  (from data.ipAddress)")

    # Step 6: destIpAddr
    ip = extract_ip(attrs.get("_dataRemoteHost"))
    if ip:
        attrs["destIpAddr"] = ip
        print(f"  destIpAddr    = {ip}  (from data.reportedRemoteHost)")

    # Step 7: procId
    pid = attrs.get("_dataProcId")
    if pid is not None:
        try:
            attrs["procId"] = int(pid)
            print(f"  procId        = {attrs['procId']}  (from data.processId)")
        except (ValueError, TypeError):
            pass

    # Step 8: connMode
    rdir = attrs.get("_dataReportedDir")
    if rdir:
        attrs["connMode"] = rdir
        print(f"  connMode      = {rdir}  (from data.reportedDirection)")

    # Step 9: eventAction
    action = attrs.get("_dataAction")
    if action:
        mapping = {"Block": 1, "Allow": 2}
        attrs["eventAction"] = mapping.get(action, 0)
        print(f"  eventAction   = {attrs['eventAction']}  (from data.action='{action}')")

    # Step 10: user
    creator = attrs.get("_dataCreatedBy")
    if creator:
        attrs["user"] = creator
        print(f"  user          = {creator}  (from data.createdByUsername)")

    # ── Step 11: CORE FILTER (incidentStatus + 5-day gate) ───────────────────
    print("\n[Step 11] CORE FILTER: 5-day age gate")
    age_ms = attrs.get("_ageMs")
    if age_ms is not None:
        if age_ms <= 432000000:
            attrs["eventType"]     = "SentinelOne-Singularity-Incident-Not-Mitigated"
            attrs["eventSeverity"] = 8
            result = "ACTIVE"
        else:
            attrs["eventType"]     = "SentinelOne-Singularity-Incident-Stale"
            attrs["eventSeverity"] = 1
            result = "STALE"
    else:
        # Fallback: age unknown
        attrs["eventType"]     = "SentinelOne-Singularity-Incident-Not-Mitigated"
        attrs["eventSeverity"] = 8
        result = "ACTIVE (fallback - no age)"

    print(f"  eventType     = {attrs['eventType']}")
    print(f"  eventSeverity = {attrs['eventSeverity']}")

    # ── Final event summary ──────────────────────────────────────────────────
    print("\n[Final Event Attributes]")
    STORED_ATTRS = [
        "eventType", "eventSeverity", "deviceTime", "eventTime",
        "customer", "srcHostName", "srcIpAddr", "destIpAddr",
        "procName", "procId", "policyName", "connMode",
        "eventAction", "user", "msg",
    ]
    for attr in STORED_ATTRS:
        val = attrs.get(attr)
        if val is not None:
            display = str(val)
            if len(display) > 70:
                display = display[:70] + "..."
            print(f"  {attr:<20} = {display}")

    # ── Pass/Fail ────────────────────────────────────────────────────────────
    print(f"\n  RESULT   : {result}")
    passed = result.startswith(expected)
    print(f"  {'PASS' if passed else 'FAIL'}  (expected: {expected})")


# ──────────────────────────────────────────────────────────────────────────────
# Run all test cases
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("FortiSIEM Parser Simulator: SentinelOneSingularity.xml")
    print("=" * 72)

    results = []
    for label, log, expected in TEST_CASES:
        simulate_parser(label, log, expected)

    print("\n" + "=" * 72)
    print("All test cases complete.")
