# eat_table.py — keyword synonym table for EAT mapping
# Format: "normalised_field_keyword": "FortiSIEM_EAT"
# Normalisation: lowercase, remove spaces/underscores/dots/brackets

SYNONYMS: dict[str, str] = {

    # =========================================================================
    # === Source IP ===
    # =========================================================================
    "srcipaddr": "srcIpAddr", "srcip": "srcIpAddr", "sourceip": "srcIpAddr",
    "sourceipaddr": "srcIpAddr", "clientip": "srcIpAddr", "remoteip": "srcIpAddr",
    "agentip": "srcIpAddr", "protectorip": "srcIpAddr", "saddr": "srcIpAddr",
    "fromip": "srcIpAddr", "localip": "srcIpAddr", "reportedlocalhost": "srcIpAddr",
    "agentdetectioninfoagentip": "srcIpAddr", "detectagentip": "srcIpAddr",
    # CEF / LEEF
    "src": "srcIpAddr",
    # NetFlow / IPFIX
    "sourceipv4address": "srcIpAddr", "sourceipv6address": "srcIpAddr",
    # Zeek
    "idorigh": "srcIpAddr",
    # PAN / FortiGate
    "natsrcip": "srcIpAddr",                                                  # mapped to pre-NAT; see postNAT section
    # Windows / CEF additional
    "ipaddress": "srcIpAddr", "ipaddr": "srcIpAddr",
    # Check Point
    "xlatesrc": "srcIpAddr",
    # LEEF
    "identsrc": "srcIpAddr",
    # syslog-KV generic
    "srcaddr": "srcIpAddr", "sip": "srcIpAddr",

    # =========================================================================
    # === Destination IP ===
    # =========================================================================
    "destipaddr": "destIpAddr", "destip": "destIpAddr", "dstip": "destIpAddr",
    "dst": "destIpAddr", "destinationip": "destIpAddr", "serverip": "destIpAddr",
    "externalip": "destIpAddr", "remotehost": "destIpAddr", "toip": "destIpAddr",
    "reportedremotehost": "destIpAddr", "agentdetectioninfoexternalip": "destIpAddr",
    # CEF
    "destinationaddress": "destIpAddr",
    # NetFlow / IPFIX
    "destinationipv4address": "destIpAddr", "destinationipv6address": "destIpAddr",
    # Zeek
    "idresph": "destIpAddr",
    # PAN / FortiGate
    "natdstip": "destIpAddr",
    # Check Point
    "xlatedst": "destIpAddr",
    # LEEF
    "identdst": "destIpAddr",
    # syslog-KV generic
    "dstaddr": "destIpAddr", "dip": "destIpAddr",

    # =========================================================================
    # === Source Hostname ===
    # =========================================================================
    "srchostname": "srcHostName", "hostname": "srcHostName",
    "agentcomputername": "srcHostName",
    "machinename": "srcHostName", "host": "srcHostName", "srchost": "srcHostName",
    "agentdetectioninfoagentcomputername": "srcHostName",
    "computername": "srcHostName",
    # CEF
    "shost": "srcHostName",
    # LEEF
    "identhostname": "srcHostName",
    # Windows
    "workstationname": "srcHostName",

    # =========================================================================
    # === Destination Hostname ===
    # =========================================================================
    "destname": "destName", "desthostname": "destName", "servername": "destName",
    "dsthost": "destName",
    # CEF
    "dhost": "destName",
    # syslog-KV
    "targetmachinename": "destName", "targetcomputer": "destName",
    "dstname": "destName",

    # =========================================================================
    # === Source Name (FQDN / DNS-resolved) ===
    # =========================================================================
    "srcname": "srcName", "sourcename": "srcName",

    # =========================================================================
    # === Host (generic, device-centric) ===
    # =========================================================================
    "hostip": "hostIpAddr", "hostipaddr": "hostIpAddr",
    "devhostname": "hostName", "devicehostname": "hostName",

    # =========================================================================
    # === User ===
    # =========================================================================
    "user": "user", "username": "user", "loginuser": "user",
    "loggedinusername": "user", "logonuser": "user", "loginname": "user",
    "agentlastloggedinusername": "user",
    "agentdetectioninfoagentlastloggedinusername": "user",
    "processuser": "user",
    # CEF
    "suser": "user",
    # LEEF
    "usrname": "user",
    # Windows Security Event Log
    "subjectusername": "user", "subjectaccountname": "user",
    # JSON / API
    "accountlogin": "user", "loginid": "user", "userid": "user",
    "actorname": "user", "actor": "user",
    # RADIUS / VPN
    "callingpartyloginuserid": "user",

    # =========================================================================
    # === Target User ===
    # =========================================================================
    "targetuser": "targetUser", "targetusername": "targetUser",
    "destuser": "targetUser", "targetaccount": "targetUser",
    # CEF
    "duser": "targetUser",
    # Windows Security Event Log
    "targetaccountname": "targetUser",
    "oldtargetusername": "targetUser",
    # Kerberos
    "samaccountname": "targetUser",

    # =========================================================================
    # === Message ===
    # =========================================================================
    "msg": "msg", "message": "msg", "description": "msg",
    "reason": "msg", "detail": "msg", "info": "msg", "summary": "msg",
    "threatinfothreatname": "msg",
    # CEF
    "devicecustomstring1": "msg", "cs1": "msg",
    # syslog-KV
    "logmessage": "msg", "eventdescription": "msg", "remarks": "msg",
    "additionalinfo": "msg", "details": "msg",
    # FortiGate
    "logdesc": "msg",

    # =========================================================================
    # === Event Severity ===
    # =========================================================================
    "eventseverity": "eventSeverity", "severity": "eventSeverity",
    "threatseverity": "eventSeverity", "level": "eventSeverity",
    "priority": "eventSeverity", "urgency": "eventSeverity",
    # Syslog / CEF
    "syslogpriority": "eventSeverity", "syslogpri": "eventSeverity",
    # FortiGate
    "risk": "eventSeverity",

    # =========================================================================
    # === Event Type ===
    # =========================================================================
    "eventtype": "eventType", "event": "eventType",
    "logtype": "eventType", "eventname": "eventType",
    # CEF / LEEF
    "deviceeventclassid": "eventType", "categorydevicetype": "eventType",
    "activitytype": "activityType",

    # =========================================================================
    # === Event ID ===
    # =========================================================================
    "eventid": "eventId", "evtid": "eventId",
    "wineventid": "winEventId", "winevtid": "winEventId",
    # Windows Security Event Log
    "systemprovidereventid": "winEventId",

    # =========================================================================
    # === Hashes ===
    # =========================================================================
    "sha1": "hashSHA1", "filecontenthash": "hashSHA1", "sha256": "hashSHA256",
    "md5": "hashMD5", "threatinfomd5": "hashMD5", "filehash": "hashSHA256",
    "sha512": "hashSHA512", "filesha256": "hashSHA256", "filemd5": "hashMD5",
    "filesha1": "hashSHA1",
    # CrowdStrike / EDR
    "sha256hashdata": "hashSHA256", "md5hashdata": "hashMD5",
    "targetsha256": "hashSHA256", "parenthashcode": "parentFileHashCode",
    # Zeek
    "md5hash": "hashMD5", "sha1hash": "hashSHA1",
    # FortiGate
    "checksum": "hashMD5",
    # generic
    "hashalgo": "hashAlgo", "hashtarget": "targetHashCode",

    # =========================================================================
    # === Process ===
    # =========================================================================
    "procname": "procName", "processname": "procName", "process": "procName",
    "executable": "procName",
    "procid": "procId", "processid": "procId", "pid": "procId",
    "parentprocname": "parentProcName", "parentprocess": "parentProcName",
    "parentprocid": "parentProcId", "parentpid": "parentProcId",
    # CrowdStrike / EDR
    "processimagefilename": "procName", "imagepath": "procName",
    "parentprocessimagefilename": "parentProcName",
    "processimagefilepath": "filePath",
    # Windows Security Event Log
    "processnewname": "procName", "newprocessname": "procName",
    "parentprocessname": "parentProcName",

    # =========================================================================
    # === File ===
    # =========================================================================
    "filename": "fileName", "filedisplayname": "fileName", "file": "fileName",
    "filepath": "filePath", "fullpath": "filePath", "path": "filePath",
    # CEF
    "fname": "fileName", "fsize": "fileSize",
    # additional
    "fileext": "fileExt", "fileextension": "fileExt",
    "filesize": "fileSize", "fileowner": "fileOwner",
    "filecreationtime": "fileCreateTime", "filecreated": "fileCreateTime",
    "filemodificationtime": "fileModificationTime", "filemodified": "fileModificationTime",
    "fileid": "fileId", "filecount": "fileCount",
    "filedisposition": "fileDisposition", "filedirection": "fileDirection",
    "commandpath": "commandPath",

    # =========================================================================
    # === Command ===
    # =========================================================================
    "command": "command", "commandline": "commandLine", "cmdline": "commandLine",
    "cmd": "command", "execcommand": "command",
    "commandname": "commandName", "commandtype": "commandType",
    # CrowdStrike / EDR
    "cmdlncmpl": "commandLine",

    # =========================================================================
    # === Network Ports ===
    # =========================================================================
    "srcport": "srcIpPort", "sourceport": "srcIpPort", "sport": "srcIpPort",
    "spt": "srcIpPort",                                                       # CEF
    # NetFlow / IPFIX
    "sourcetransportport": "srcIpPort",
    # Zeek
    "idorigp": "srcIpPort",

    "destport": "destIpPort", "dstport": "destIpPort", "dport": "destIpPort",
    "destinationport": "destIpPort", "dpt": "destIpPort",                    # CEF
    # NetFlow / IPFIX
    "destinationtransportport": "destIpPort",
    # Zeek
    "idrespp": "destIpPort",

    # =========================================================================
    # === IP Protocol ===
    # =========================================================================
    "ipproto": "ipProto", "proto": "ipProto", "protocol": "ipProto",
    # NetFlow / IPFIX
    "protocolidentifier": "ipProto",
    # Zeek
    "transport": "ipProto",
    # syslog-KV
    "l4proto": "ipProto", "protonum": "ipProto",

    # =========================================================================
    # === Action ===
    # =========================================================================
    "eventaction": "eventAction", "action": "eventAction",
    "mitigationstatus": "eventAction", "disposition": "eventAction",
    "verdict": "eventAction", "result": "eventAction",
    # CEF
    "act": "eventAction",
    # LEEF
    "identaction": "eventAction",
    # FortiGate
    "fcgaction": "eventAction",
    # generic
    "actionresult": "actionResult", "actionname": "actionName",
    "actionid": "actionId", "actionerror": "actionError",

    # =========================================================================
    # === Policy / Rule ===
    # =========================================================================
    "policyname": "policyName", "policy": "policyName",
    "rulename": "ruleName", "rule": "ruleName", "signature": "ruleName",
    "ruleid": "ruleId", "policyid": "policyId",
    # FortiGate
    "policytype": "policyName",
    # PAN
    "ruleuuid": "ruleId",
    # generic
    "filtername": "policyName", "accesspolicyid": "accessCtlPolicyId",

    # =========================================================================
    # === Virus / Threat ===
    # =========================================================================
    "virusname": "virusName", "malwarename": "virusName",
    "threatlevel": "threatLevel", "risklevel": "threatLevel",
    "threatfamily": "virusName",
    "threattype": "threatType", "threatid": "threatId",
    "threatname": "threatName",
    # Analyst / detection
    "analystverd": "analystVerdict",
    "detectiontype": "detectionType",
    "confidence": "confidenceLevel",

    # =========================================================================
    # === Session ===
    # =========================================================================
    "sessionid": "sessionId", "connid": "sessionId", "flowid": "sessionId",
    # Zeek
    "uid": "sessionId",
    # FortiGate / PAN
    "sessid": "sessionId",

    # =========================================================================
    # === Domain ===
    # =========================================================================
    "domain": "domain", "workgroup": "domain", "realm": "domain",
    # syslog-KV
    "srcdomain": "srcDomain", "sourcedomain": "srcDomain",
    "dstdomain": "destDomain", "destdomain": "destDomain", "destinationdomain": "destDomain",

    # =========================================================================
    # === Customer / Tenant ===
    # =========================================================================
    "customer": "customer", "accountname": "customer", "tenant": "customer",
    "tenantid": "customer", "org": "customer", "organization": "customer",

    # =========================================================================
    # === Account / Group ===
    # =========================================================================
    "accountid": "accountId",
    "groupid": "groupName", "groupname": "groupName",
    "siteid": "siteId", "sitename": "siteName",

    # =========================================================================
    # === Classification ===
    # =========================================================================
    "classification": "_classification", "category": "_classification",
    "threatcategory": "threatCategory",

    # =========================================================================
    # === Confidence ===
    # =========================================================================
    "confidencelevel": "_confidenceLevel", "confidencevalue": "_confidenceLevel",

    # =========================================================================
    # === Time ===
    # =========================================================================
    "createdat": "eventTime", "timestamp": "eventTime", "eventtime": "eventTime",
    "attacktime": "eventTime",
    "devicetime": "deviceTime", "logtime": "deviceTime", "localtime": "deviceTime",
    "eventtimestamp": "eventTime",
    # ISO 8601 variants (normalised the same)
    "timeutc": "eventTime", "timestamputc": "eventTime",
    "receivedtime": "deviceTime", "reportedtime": "deviceTime",

    # =========================================================================
    # === Duration ===
    # =========================================================================
    "durationmsec": "durationMSec", "duration": "durationMSec",
    "sessionduration": "durationMSec", "flowduration": "durationMSec",
    "elapsed": "durationMSec", "conntime": "durationMSec",
    # CEF
    "devicecustomnumber1": "durationMSec",
    # FortiGate
    "dur": "durationMSec",

    # =========================================================================
    # === HTTP / Web ===
    # =========================================================================
    "httpmethod": "httpMethod", "method": "httpMethod", "requestmethod": "httpMethod",
    "httpstatuscode": "httpStatusCode", "statuscode": "httpStatusCode",
    "httpstatus": "httpStatusCode", "responsecode": "httpStatusCode",
    "httpreferrer": "httpReferrer", "referer": "httpReferrer", "referrer": "httpReferrer",
    # CEF
    "request": "httpFullRequest", "requesturl": "httpFullRequest",
    "httpurl": "httpFullRequest", "httpuri": "httpEndUri",
    "url": "httpFullRequest", "uri": "httpEndUri",
    # User-Agent
    "httpuseragent": "httpUserAgent", "useragent": "httpUserAgent",
    "ua": "httpUserAgent", "browsername": "browserName",
    "callersupplieduseragent": "httpUserAgent",
    # Content
    "httpcontenttype": "httpContentType", "contenttype": "httpContentType",
    "httpcontentlen": "httpContentLen", "contentlength": "httpContentLen",
    # Cookie
    "httpcookie": "httpCookie", "cookie": "httpCookie",
    # Host
    "httphost": "httpHost", "vhost": "httpHost",
    # File extension
    "httpfileext": "httpFileExt",
    # Response time
    "httpresponsetime": "httpResponseTimeMs", "serverresponsetime": "httpResponseTimeMs",
    # Forward / proxy
    "httpforwardaddr": "httpForwardAddr", "xforwardedfor": "httpForwardAddr",
    "xrealip": "httpForwardAddr",
    "httpproxyaction": "httpProxyAction", "proxyaction": "httpProxyAction",
    # Full request
    "httprequest": "httpFullRequest", "fullrequest": "httpFullRequest",
    # Accept-Language
    "httpacceptlang": "httpAcceptLang", "acceptlanguage": "httpAcceptLang",
    # End URI
    "httpenduri": "httpEndUri", "enduri": "httpEndUri",
    # Request headers
    "httprequestheaders": "httpRequestHeaders", "requestheaders": "httpRequestHeaders",

    # =========================================================================
    # === DNS ===
    # =========================================================================
    "dnsquery": "DNSQuery", "query": "DNSQuery",
    "dnsqueryname": "dnsQueryName", "queryname": "dnsQueryName",
    "dnsquerytype": "dnsQueryType", "querytype": "dnsQueryType",
    "dnsqueryclass": "dnsQueryClass", "queryclass": "dnsQueryClass",
    "dnsresponsecode": "dnsResponseCode", "rcode": "dnsResponseCode",
    "dnsrecordtype": "DNSRecordType", "recordtype": "DNSRecordType",
    "dnsresponsetype": "DNSResponseType",
    "dnstransactionid": "dnsTransactionId", "txid": "dnsTransactionId",
    "dnsqueryipaddr": "dnsQueryIpAddr", "resolver": "dnsQueryIpAddr",
    "dnsreferral": "dnsReferral",
    "dnsresponsetime": "dnsResponseTimeMs",
    "dnsserver": "dnsServer", "dnsservername": "dnsServerName",
    "dnszone": "dnsZone", "zone": "dnsZone",
    "dnssec": "dnsSec",
    "dnsnxdomain": "dnsQueryNxDomain",

    # =========================================================================
    # === Email / SMTP ===
    # =========================================================================
    "mailsubject": "mailSubject", "subject": "mailSubject",                  # NOTE: duplicate with user section — mailSubject wins here
    "mailsender": "senderMailAddr", "mailfrom": "senderMailAddr",
    "from": "senderMailAddr", "sender": "senderMailAddr",
    "sendermail": "senderMailAddr", "sendermailaddr": "senderMailAddr",
    "maildomain": "mailDomain", "emaildomain": "mailDomain",
    "mailaction": "mailAction",
    "emailid": "emailId", "messageid": "smtpMsgId", "msgid": "smtpMsgId",
    "smtpmsgid": "smtpMsgId",
    "smtpfailcode": "smtpFailCode",
    "mailorigclientip": "mailOrigClientIp",
    "mailorigserverip": "mailOrigServerIp",
    "mailreturnpath": "mailReturnPath",
    "mailgatewayname": "mailGatewayName",
    "ccmailaddr": "ccMailAddr", "ccmail": "ccMailAddr",
    "mailboxguid": "mailboxGUID", "mailboxupn": "mailboxUPN",

    # =========================================================================
    # === Bytes / Packets / Bandwidth ===
    # =========================================================================
    # Inbound / received
    "recvbytes": "recvBytes", "receivedbytes": "recvBytes", "bytesreceived": "recvBytes",
    "bytesrecv": "recvBytes", "inbytes": "recvBytes", "rcvdbyte": "recvBytes",
    # CEF
    "in": "recvBytes",
    # outbound / sent
    "sentbytes": "sentBytes", "bytessent": "sentBytes", "outbytes": "sentBytes",
    "sentbyte": "sentBytes",
    # CEF
    "out": "sentBytes",
    # total
    "totbytes": "totBytes", "totalbytes": "totBytes", "bytes": "totBytes",
    # packets
    "recvpkts": "recvPkts", "receivedpkts": "recvPkts", "pktsrecv": "recvPkts",
    "sentpkts": "sentPkts", "sentpackets": "sentPkts",
    "totpkts": "totPkts", "totalpackets": "totPkts", "packets": "totPkts",
    # PAN-OS traffic log packet fields (bytessent/bytesreceived already mapped above)
    "pktssent": "sentPkts", "pktsreceived": "recvPkts",
    # NetFlow (octet = bytes in IPFIX; delta counts are direction-agnostic totals)
    "octetdeltacount": "totBytes", "packetdeltacount": "totPkts",
    # 64-bit variants
    "recvbytes64": "recvBytes64", "sentbytes64": "sentBytes64",
    "totbytes64": "totBytes64",
    # flows
    "totflows": "totFlows", "flowcount": "totFlows",
    # bits-per-second
    "recvbitspersec": "recvBitsPerSec", "sentbitspersec": "sentBitsPerSec",

    # =========================================================================
    # === NAT / Translation ===
    # =========================================================================
    # Post-NAT source (what the firewall translates FROM on the outside)
    "postnatsrcip": "postNATSrcIpAddr", "postnatsrcipaddr": "postNATSrcIpAddr",
    "translatesrc": "postNATSrcIpAddr", "translatedsrcip": "postNATSrcIpAddr",
    "postnatsrcport": "postNATSrcIpPort", "postnatsrcipport": "postNATSrcIpPort",
    "translatesrcport": "postNATSrcIpPort",
    # Post-NAT destination
    "postnatdstip": "postNATDestIpAddr", "postnatdestip": "postNATDestIpAddr",
    "postnatdstipaddr": "postNATDestIpAddr",
    "translatedst": "postNATDestIpAddr", "translateddstip": "postNATDestIpAddr",
    "postnatdstport": "postNATDestIpPort", "postnatdestport": "postNATDestIpPort",
    "postnatdstipport": "postNATDestIpPort",
    "translatedstport": "postNATDestIpPort",
    # Pre-NAT destination (original destination before DNAT)
    "prenatdstip": "preNATDestIpAddr", "prenatdestip": "preNATDestIpAddr",
    "prenatdstport": "preNATDestIpPort", "prenatdestport": "preNATDestIpPort",
    # Check Point XLate fields
    "xlatedstip": "postNATDestIpAddr", "xlatesrcip": "postNATSrcIpAddr",

    # =========================================================================
    # === Interface / VLAN / Zone ===
    # =========================================================================
    "srcintfname": "srcIntfName", "srcintf": "srcIntfName", "ininterface": "srcIntfName",
    "srcintfalias": "srcIntfAlias",
    "destintfname": "destIntfName", "dstintf": "destIntfName", "outinterface": "destIntfName",
    "destintfalias": "destIntfAlias",
    "intfname": "intfName", "interface": "intfName",
    "intfalias": "intfAlias",
    # Zone
    "srcfwzone": "srcFwZone", "srczone": "srcFwZone",
    "destfwzone": "destFwZone", "dstzone": "destFwZone", "destzone": "destFwZone",
    # VLAN
    "srcvlan": "srcVLAN", "svlan": "srcVLAN",
    "destvlan": "destVLAN", "dvlan": "destVLAN",
    "hostvlan": "hostVLAN", "vlanid": "vlanId", "vlan": "vlanId",
    # VDOM (FortiGate)
    "vdom": "vdom", "virtualdom": "vdom",

    # =========================================================================
    # === MAC Address ===
    # =========================================================================
    "srcmacaddr": "srcMACAddr", "srcmac": "srcMACAddr", "smac": "srcMACAddr",
    "sourcemac": "srcMACAddr", "sourcemacaddress": "srcMACAddr",
    "destmacaddr": "destMACAddr", "dstmac": "destMACAddr", "dmac": "destMACAddr",
    "destinationmac": "destMACAddr",
    "clientmacaddress": "clientMACaddress", "clientmac": "clientMACaddress",
    "hostmacaddr": "hostMACAddr", "hostmac": "hostMACAddr",
    "dhcpservermac": "dhcpServerMacAddr",

    # =========================================================================
    # === IP TTL / ToS / DSCP ===
    # =========================================================================
    "ipttl": "ipTtl", "ttl": "ipTtl",
    "tos": "tos", "typeofservice": "tos",
    "dscp": "dscp", "dscpvalue": "dscp",
    "srcdscp": "srcDscp", "destdscp": "destDscp",

    # =========================================================================
    # === TCP Flags ===
    # =========================================================================
    "tcpflags": "tcpFlags", "tcpflag": "tcpFlags", "flags": "tcpFlags",

    # =========================================================================
    # === ICMP ===
    # =========================================================================
    "icmptype": "icmpType", "icmpcode": "icmpCode",

    # =========================================================================
    # === VPN / Tunnel / IPSec ===
    # =========================================================================
    "vpnname": "vpnTunnelName", "vpntunnelname": "vpnTunnelName",
    "tunnelname": "vpnTunnelName", "vpnstatus": "vpnStatus",
    "vpnconntype": "vpnConnType", "vpnconncount": "vpnConnCount",
    "sslvpnstatus": "sslVpnStatus", "sslvpnconncount": "sslVpnConnCount",
    "remotevpnip": "remoteVpnIpAddr", "remotevpnipaddr": "remoteVpnIpAddr",
    "localvpnip": "localVpnIpAddr", "localvpnipaddr": "localVpnIpAddr",
    "tunnelprotocol": "tunnelProtocol",
    # IKE / IPsec
    "ikesaid": "ikeSAID", "said": "SAID", "satype": "SAType",
    "spiin": "SPIInbound", "spinbound": "SPIInbound",
    "spiout": "SPIOutbound", "spoutbound": "SPIOutbound",
    "childsaid": "childSAID",
    "ikesalifetime": "IKE_SAlifetime",

    # =========================================================================
    # === Authentication / Logon ===
    # =========================================================================
    "authenmethod": "authenMethod", "authmethod": "authenMethod",
    "authenticationmethod": "authenMethod",
    "authenalgo": "authenAlgo", "authalgo": "authenAlgo",
    "authresult": "authResult", "authsuccess": "authResult",
    "authfailure": "authResult",
    "authdetails": "authDetails", "authrequirement": "authRequirement",
    "authstrength": "authStrength", "authaction": "authAction",
    "authserverip": "authServerIpAddr", "authservername": "authServerName",
    # Logon
    "logontype": "logonType", "logintype": "logonType",
    "logontime": "logonTime", "logintime": "logonTime",
    # Windows
    "winlogontype": "winLogonType", "winlogonid": "winLogonId",
    "winlogonfailcode": "winLogonFailCode", "winlogonfailcode2": "winLogonFailCode2",
    "winkerbfailcode": "winKerbFailCode", "winiassfailcode": "winIASFailCode",
    "winlogoncalleruser": "winLogonCallerUser",
    # RADIUS
    "calledstationid": "calledStationId", "callingstationid": "callingStationId",
    # Kerberos
    "preauthtype": "PreAuthType", "preauthenctype": "PreAuthEncryptionType",
    "sessionkeyenctype": "SessionKeyEncryptionType",
    "accountsupportenctypes": "AccountSupportEncryptionTypes",

    # =========================================================================
    # === Windows-Specific ===
    # =========================================================================
    # Windows Event Log
    "winevtcategory": "winEvtCategory", "winsubcategory": "winEvtSubCategory",
    "winevtsubcategory": "winEvtSubCategory",
    # Windows Security Event Log field names (raw)
    "subjectlogonid": "winLogonId",
    "targetlogonid": "winLogonId",
    "accessmask": "accessMask",
    "privilegelist": "privName",
    "creatorprocessname": "parentProcName",
    "objecttype": "osObjType",
    "objectname": "fileName",
    "shareinfo": "filePath",
    # SAM Account
    "samaccname": "SamAccountName",

    # =========================================================================
    # === Certificate / TLS / SSL ===
    # =========================================================================
    "certhostname": "certHostName", "tlscn": "certHostName",
    "certthumbprint": "certThumbprint", "certfingerprint": "certThumbprint",
    "sslcertfingerprint": "sslCertFingerprint",
    "certerr": "certErr", "sslcerterr": "certErr",
    "certinfo": "certInfo",
    "sslcertstatus": "sslCertStatus",
    "sslciphersuite": "sslCipherSuite", "cipher": "sslCipherSuite",
    "cipherstrength": "cipherStrength",
    "sslaction": "sslAction",
    "sslversion": "sslVersion", "tlsversion": "tlsVersion",
    "sslflowstatus": "sslFlowStatus",

    # =========================================================================
    # === Vulnerability / CVE ===
    # =========================================================================
    "cveid": "vulnCVEId", "cve": "vulnCVEId",
    "cvesummary": "vulnCVESummary", "vulndesc": "vulnCVESummary",
    "bugtraqid": "vulnBugTraqID",
    "isexploitable": "isExploitable",
    "exploitabilityease": "exploitabilityEase",
    "vulncount": "vulnCount", "vulncountcrit": "vulnCountCritical",
    "vulncounthigh": "vulnCountHigh", "vulncountmed": "vulnCountMedium",
    "vulncountlow": "vulnCountLow", "vulncountinfo": "vulnCountInfo",
    "exploitcount": "exploitCount",

    # =========================================================================
    # === DHCP ===
    # =========================================================================
    "dhcpreqtype": "dhcpReqType", "dhcpmsgtype": "dhcpReqType",
    "dhcpleasetime": "dhcpLeaseTime",
    "dhcpgateway": "dhcpGateway",
    "dhcpsubnetaddr": "dhcpSubnetAddr", "dhcpsubnet": "dhcpSubnetAddr",
    "dhcpsubnetmask": "dhcpSubnetMask",
    "dhcpendstatus": "dhcpEndStatus",
    "dhcpavail": "DHCPAvail", "dhcpused": "DHCPUsed",

    # =========================================================================
    # === Application / Service ===
    # =========================================================================
    "appname": "appName",
    # NOTE: 'application' below overrides the procName entry above for app-aware firewalls
    "application": "appName",
    "app": "appName",
    "appversion": "appVersion", "appver": "appVersion",
    "appvendor": "appVendor",
    "appport": "appPort",
    "appcategory": "appCategory", "appcategor": "appCategory",
    "appsubcategory": "appSubcategory",
    "appgroupname": "appGroupName",
    "appdesc": "appDesc",
    "appstatus": "appStatus",
    "approle": "appRole",
    "appprotoid": "appProtoId",
    "servicename": "serviceName", "service": "serviceName",
    "appid": "applicationId",

    # =========================================================================
    # === OS / Platform ===
    # =========================================================================
    "osname": "osName", "operatingsystem": "osName",
    "osversion": "osVersion", "osver": "osVersion",
    "ostype": "osType",
    "agentversion": "agentVersion", "agentver": "agentVersion",
    "kernelid": "kernelId",
    "devicetype": "deviceType", "devicename": "deviceName",
    "deviceowner": "deviceOwner",

    # =========================================================================
    # === Connection Mode / Status ===
    # =========================================================================
    "connmode": "connMode", "connectionmode": "connMode",
    "connstatus": "connMode", "connectionstatus": "connMode",

    # =========================================================================
    # === Alert / Incident ===
    # =========================================================================
    "alertname": "alertName", "alertcategory": "alertCategory",
    "alertid": "alertIdStr", "alertidstr": "alertIdStr",
    "incidentid": "incidentId", "incidentstatus": "incidentStatus",
    "incidentfirstseen": "incidentFirstSeen", "incidentlastseen": "incidentLastSeen",
    "incidentcount": "incidentCount", "incidentdetail": "incidentDetail",

    # =========================================================================
    # === Attack / MITRE ATT&CK ===
    # =========================================================================
    "attacktactic": "attackTactic", "tactic": "attackTactic",
    "attacktechnique": "attackTechnique", "technique": "attackTechnique",
    "attacktechniqueid": "attackTechniqueId", "techniqueid": "attackTechniqueId",
    "attackname": "attackName", "attacktype": "attackType",
    "attackinfo": "attackInfo", "attackcontext": "attackContext",
    "mitreatttck": "attackTactic", "mitretactic": "attackTactic",
    "mitretechnique": "attackTechnique",

    # =========================================================================
    # === IPS ===
    # =========================================================================
    "ipseventname": "ipsEventName", "ipsrulename": "ipsEventName",
    "ipssignatureid": "ipsSignatureId", "ipssigid": "ipsSignatureId",
    "ipsseverity": "ipsSeverity", "ipssig": "ipsEventName",
    "ipsprotectionname": "ipsProtectionName", "protectionname": "ipsProtectionName",
    "ipscount": "ipsCount", "ipsconfidence": "ipsConfidence",
    "ipspolicyid": "ipsPolicyId", "ipsalert": "ipsEventName",

    # =========================================================================
    # === Geolocation ===
    # =========================================================================
    "srccountry": "srcGeoCountry", "srcgeocountry": "srcGeoCountry",
    "srcgeocountrycodestr": "srcGeoCountryCodeStr", "srccountrycode": "srcGeoCountryCodeStr",
    "srccity": "srcGeoCity", "srcgeocity": "srcGeoCity",
    "srcorg": "srcGeoOrg", "srcgeoorg": "srcGeoOrg", "srcasisp": "srcGeoOrg",
    "srcasnum": "srcASNum", "srcas": "srcASNum",
    "srcasnum32": "srcASNum32",
    "srclat": "srcGeoLatitude", "srcgeolat": "srcGeoLatitude",
    "srclong": "srcGeoLongitude", "srcgeolong": "srcGeoLongitude",
    "srcstate": "srcGeoState", "srcgeostate": "srcGeoState",
    "srchostrep": "srcGeoHostReputation", "srcgeohostrep": "srcGeoHostReputation",
    "dstcountry": "destGeoCountry", "destgeocountry": "destGeoCountry",
    "destgeocountrycodestr": "destGeoCountryCodeStr", "dstcountrycode": "destGeoCountryCodeStr",
    "dstcity": "destGeoCity", "destgeocity": "destGeoCity",
    "dstorg": "destGeoOrg", "destgeoorg": "destGeoOrg", "dstasisp": "destGeoOrg",
    "dstasnum": "destASNum", "destas": "destASNum",
    "destasnum32": "destASNum32",
    "dstlat": "destGeoLatitude", "destgeolat": "destGeoLatitude",
    "dstlong": "destGeoLongitude", "destgeolong": "destGeoLongitude",
    "dststate": "destGeoState", "destgeostate": "destGeoState",
    "dsthostrep": "destGeoHostReputation", "destgeohostrep": "destGeoHostReputation",

    # =========================================================================
    # === NetFlow / IPFIX ===
    # =========================================================================
    "biflowdirection": "biflowDirection", "flowdirection": "biflowDirection",
    "flowendreason": "flowEndReason",
    # (bytes/pkts and VLAN already covered above)

    # =========================================================================
    # === Zeek / Bro ===
    # =========================================================================
    # uid already mapped above to sessionId
    # id.orig_h → srcIpAddr (normalised: idorigh — already mapped)
    # id.resp_h → destIpAddr (normalised: idresph — already mapped)
    # id.orig_p → srcIpPort (normalised: idorigp — already mapped)
    # id.resp_p → destIpPort (normalised: idrespp — already mapped)
    "connstate": "status",          # Zeek conn_state is a status string, not a connection mode
    "zeekservice": "serviceName",   # Zeek service field (zeekService not in DB)
    "missedbytes": "recvBytes",     # missedBytes not in DB; approximate with recvBytes
    "historyconn": "tcpFlags",      # zeekTcpFlags not in DB; keep tcpFlags

    # =========================================================================
    # === FortiGate-specific ===
    # =========================================================================
    # (many already covered: vdom, policyid, srcintfname, destintfname, etc.)
    "logid": "eventId",
    "subtype": "eventType",
    "fcgtype": "eventType",
    "devname": "deviceName",
    "devid": "deviceIdentification",

    # =========================================================================
    # === Palo Alto Networks-specific ===
    # =========================================================================
    # (appName/appCategory/policyName/ruleId already covered)
    "sessionendreason": "connMode",
    "repeatcnt": "count",           # PAN repeat count → generic count
    "natsrcport": "postNATSrcIpPort",
    "natdstport": "postNATDestIpPort",
    "panosruleuid": "ruleId",

    # =========================================================================
    # === CrowdStrike / EDR ===
    # =========================================================================
    "detectionid": "detection",     # CrowdStrike detection ID
    "agentid": "deviceIdentification",  # agent/sensor ID → deviceIdentification
    "deviceid": "deviceIdentification",
    "grandparentimagefilename": "parentProcName",
    # tactic/technique already mapped in Attack/MITRE section

    # =========================================================================
    # === Cloud (AWS / Azure / GCP) ===
    # =========================================================================
    "awseventid": "awsEventId", "awsregion": "awsRegion",
    "awsactionresult": "awsActionResult",
    "azureeventid": "azureEventId", "azurecorrelationid": "azureCorrelationId",
    "azureeventcategory": "azureEventCategory", "azuresubstatus": "azureSubstatus",
    "bucketname": "bucketName",
    "containerid": "containerId", "containername": "containerName",
    "instancename": "instanceName", "instancetype": "instanceType",
    "instancestatus": "instanceStatus",
    "compartmentid": "compartmentId", "compartmentname": "compartmentName",
    "accesskeyid": "accessKeyId",

    # =========================================================================
    # === Miscellaneous / Generic ===
    # =========================================================================
    "correlationid": "correlationId",
    "requestid": "requestID",
    "comment": "comment",
    "count": "count",
    "status": "status",
    "reasoncode": "reason",
    "code": "code",
    "browserversion": "browserName",
    "deviceexternalid": "deviceIdentification",    # CEF deviceExternalId
    "resourcepool": "destResourcePool",
    "cluster": "cluster", "clusterid": "clusterId", "clustername": "cluster",
    "clusterversion": "clusterVersion",

    # =========================================================================
    # === Reputation / Client ===
    # =========================================================================
    "clientreputationscore": "clientReputationScore",
    "clientreputationlevel": "clientReputationLevel",
    "clientreputationaction": "clientReputationAction",
    "srchostreputat": "srcGeoHostReputation",
    "desthostreputat": "destGeoHostReputation",

    # =========================================================================
    # === Connection / Auth Mode ===
    # =========================================================================
    "connlimit": "connLimit",
    "activeconns": "activeConns",
    "closedconns": "closedConns",

    # =========================================================================
    # === Device-reported source IP (built-in, auto-populated) ===
    # =========================================================================
    "reptdevipaddr": "reptDevIpAddr",
    "syslogsource": "reptDevIpAddr",

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
