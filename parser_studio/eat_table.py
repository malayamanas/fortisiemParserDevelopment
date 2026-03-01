# eat_table.py — keyword synonym table for EAT mapping
# Format: "normalised_field_keyword": "FortiSIEM_EAT"
# Normalisation: lowercase, remove spaces/underscores/dots/brackets

SYNONYMS: dict[str, str] = {
    # === Source IP ===
    "srcipaddr": "srcIpAddr", "srcip": "srcIpAddr", "sourceip": "srcIpAddr",
    "sourceipaddr": "srcIpAddr", "clientip": "srcIpAddr", "remoteip": "srcIpAddr",
    "agentip": "srcIpAddr", "protectorip": "srcIpAddr", "saddr": "srcIpAddr",
    "fromip": "srcIpAddr", "localip": "srcIpAddr", "reportedlocalhost": "srcIpAddr",
    "agentdetectioninfoagentip": "srcIpAddr", "detectagentip": "srcIpAddr",

    # === Destination IP ===
    "destipaddr": "destIpAddr", "destip": "destIpAddr", "dstip": "destIpAddr",
    "dst": "destIpAddr", "destinationip": "destIpAddr", "serverip": "destIpAddr",
    "externalip": "destIpAddr", "remotehost": "destIpAddr", "toip": "destIpAddr",
    "reportedremotehost": "destIpAddr", "agentdetectioninfoexternalip": "destIpAddr",

    # === Source Hostname ===
    "srchostname": "srcHostName", "hostname": "srcHostName",
    "agentcomputername": "srcHostName",
    "machinename": "srcHostName", "host": "srcHostName", "srchost": "srcHostName",
    "agentdetectioninfoagentcomputername": "srcHostName",
    "computername": "srcHostName",

    # === Destination Hostname ===
    "destname": "destName", "desthostname": "destName", "servername": "destName",
    "dsthost": "destName",

    # === User ===
    "user": "user", "username": "user", "loginuser": "user",
    "loggedinusername": "user", "logonuser": "user", "loginname": "user",
    "agentlastloggedinusername": "user",
    "agentdetectioninfoagentlastloggedinusername": "user",
    "processuser": "user", "subject": "user",

    # === Target User ===
    "targetuser": "targetUser", "targetusername": "targetUser",
    "destuser": "targetUser", "targetaccount": "targetUser",

    # === Message ===
    "msg": "msg", "message": "msg", "threatname": "msg", "description": "msg",
    "reason": "msg", "detail": "msg", "info": "msg", "summary": "msg",
    "threatinfothreatname": "msg",

    # === Event Severity ===
    "eventseverity": "eventSeverity", "severity": "eventSeverity",
    "threatseverity": "eventSeverity", "level": "eventSeverity",
    "priority": "eventSeverity", "urgency": "eventSeverity",

    # === Hashes ===
    "sha1": "hashSHA1", "filecontenthash": "hashSHA1", "sha256": "hashSHA256",
    "md5": "hashMD5", "threatinfomd5": "hashMD5", "filehash": "hashSHA1",

    # === Process ===
    "procname": "procName", "processname": "procName", "process": "procName",
    "application": "procName", "app": "procName", "executable": "procName",
    "procid": "procId", "processid": "procId", "pid": "procId",
    "parentprocname": "parentProcName", "parentprocess": "parentProcName",
    "parentprocid": "parentProcId", "parentpid": "parentProcId",

    # === File ===
    "filename": "fileName", "filedisplayname": "fileName", "file": "fileName",
    "filepath": "filePath", "fullpath": "filePath", "path": "filePath",

    # === Network ===
    "ipproto": "ipProto", "proto": "ipProto", "protocol": "ipProto",
    "srcport": "srcIpPort", "sourceport": "srcIpPort", "sport": "srcIpPort",
    "destport": "destIpPort", "dstport": "destIpPort", "dport": "destIpPort",
    "destinationport": "destIpPort",

    # === Action ===
    "eventaction": "eventAction", "action": "eventAction",
    "mitigationstatus": "eventAction", "disposition": "eventAction",
    "verdict": "eventAction", "result": "eventAction",

    # === Customer / Account ===
    "customer": "customer", "accountname": "customer", "tenant": "customer",
    "tenantid": "customer", "org": "customer", "organization": "customer",

    # === Command ===
    "command": "command", "commandline": "command", "cmdline": "command",
    "cmd": "command", "execcommand": "command",

    # === Policy / Rule ===
    "policyname": "policyName", "policy": "policyName",
    "rulename": "ruleName", "rule": "ruleName", "signature": "ruleName",

    # === Virus / Threat ===
    "virusname": "virusName", "malwarename": "virusName",
    "threatlevel": "threatLevel", "risklevel": "threatLevel",

    # === Session ===
    "sessionid": "sessionId", "connid": "sessionId", "flowid": "sessionId",

    # === Domain ===
    "domain": "domain", "workgroup": "domain", "realm": "domain",

    # === Classification ===
    "classification": "_classification", "category": "_classification",
    "threatcategory": "_classification",

    # === Confidence ===
    "confidencelevel": "_confidenceLevel", "confidence": "_confidenceLevel",

    # === Time ===
    "createdat": "eventTime", "timestamp": "eventTime", "eventtime": "eventTime",
    "attacktime": "eventTime",
}

ALL_EATS: list[str] = sorted({
    "srcIpAddr", "destIpAddr", "srcHostName", "destName", "srcName",
    "user", "targetUser", "domain", "customer",
    "msg", "command", "policyName", "ruleName", "connMode",
    "eventType", "eventSeverity", "eventTime", "deviceTime", "eventAction",
    "procName", "procId", "parentProcName", "parentProcId",
    "fileName", "filePath", "hashMD5", "hashSHA1", "hashSHA256",
    "ipProto", "srcIpPort", "destIpPort", "sessionId", "serviceName",
    "virusName", "threatLevel", "authenMethod",
    "winEventId", "winLogonType", "winLogonId",
    "_classification", "_confidenceLevel",
})
