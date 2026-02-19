# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Purpose

This repository is a **FortiSIEM custom parser development workspace**. It contains:
- A Bash utility (`parserFunctionator10.sh`) that runs interactively on a live FortiSIEM appliance to browse, search, and extract system/custom parsers from the FortiSIEM PostgreSQL database
- Custom parser XML files authored here for import into FortiSIEM
- A Python test simulator (`test_parser.py`) for validating parser logic offline
- Reference parsers downloaded from public GitHub repositories

## Testing a Parser

To simulate a parser against sample logs without a live FortiSIEM instance:

```bash
python3 test_parser.py
```

To validate that a parser XML file is well-formed:

```bash
xmllint --noout <parser_file>.xml
```

## FortiSIEM Parser XML Structure

Every custom parser XML file must conform to this structure:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<eventParser name="UniqueName">
  <deviceType>
    <Vendor>VendorName</Vendor>
    <Model>ModelName</Model>
    <Version>ANY</Version>
  </deviceType>
  <patternDefinitions>
    <pattern name="patFoo"><![CDATA[regex here]]></pattern>
  </patternDefinitions>
  <eventFormatRecognizer>
    <![CDATA[recognizer pattern using gPat* named captures]]>
  </eventFormatRecognizer>
  <parsingInstructions>
    <!-- field extraction and event attribute setting -->
  </parsingInstructions>
</eventParser>
```

**Critical XML rule:** Comments (`<!-- -->`) must never contain `--` internally. Use `=` or spaces as separators inside comments, not dashes.

## Parser XML Syntax Reference

### Global pattern names (used in recognizer and regex)
| Pattern | Matches |
|---|---|
| `gPatMon` | `\w{3}` (e.g. `Jul`) |
| `gPatDay` | `\d{1,2}` |
| `gPatTime` | `HH:MM:SS` |
| `gPatYear` | `\d{4}` |
| `gPatStr` | `\S+` (non-whitespace) |
| `gPatIpAddr` | IPv4 address |
| `gPatMesgBody` | `.+` (rest of line) |
| `gPatInt` | integer |
| `gPatWord` | word chars |

Named capture syntax: `<attrName:gPatternName>` — stores into `$attrName`.
Unnamed/discard: `<:gPatternName>`.
Private (temp, not persisted): prefix attr with `_` (e.g. `<_temp:gPatStr>`).

### Key parsingInstructions elements

```xml
<!-- Regex field extraction -->
<collectFieldsByRegex src="$_rawmsg">
  <regex><![CDATA[<field:gPatStr>\s+<other:gPatIpAddr>]]></regex>
</collectFieldsByRegex>

<!-- JSON extraction (supports dot notation for nested keys) -->
<collectAndSetAttrByJSON src="$_jsonBody">
  <attrKeyMap attr="srcHostName" key="data.computerName"/>
</collectAndSetAttrByJSON>

<!-- Set an attribute using a function or literal -->
<setEventAttribute attr="deviceTime">toDateTime($_mon, $_day, $_year, $_time)</setEventAttribute>
<setEventAttribute attr="_ageMs">minus(now(), $eventTime)</setEventAttribute>

<!-- Conditional logic -->
<when test="exist _someVar"> ... </when>
<when test="$var = 'value'"> ... </when>
<when test="$_ageMs &lt;= 432000000"> ... </when>   <!-- use &lt;= for <= in XML -->

<choose>
  <when test="$action = 'Block'"> ... </when>
  <otherwise> ... </otherwise>
</choose>

<switch>
  <case> ... </case>
  <default> ... </default>
</switch>
```

### `when test` condition operators
`= 'value'` | `!= 'value'` | `IN ('a','b')` | `matches($v, "regex")` | `not_matches(...)` | `exist varName` | `not_exist varName` | `private_ip varName` | `not_private_ip varName` | `&lt;=` / `&gt;=` (numeric, XML-escaped)

### Useful setEventAttribute functions
`toDateTime(mon, day, year, time)` | `toDateTime($str, "yyyy-MM-dd'T'HH:mm:ss")` | `now()` | `minus($a, $b)` | `toInt($str)` | `combineMsgId("prefix-", $var)` | `convertStrToIntIpProto($proto)` | `calcDomainEntropy($name)` | `matches($var, "regex")`

### Built-in event attributes (always available)
- `$_rawmsg` — full raw log line
- `$reptDevIpAddr` — syslog source IP (auto-populated)

### Standard FortiSIEM EATs used in parsers
`eventType` | `eventSeverity` (1-10) | `eventTime` | `deviceTime` | `srcIpAddr` | `destIpAddr` | `srcHostName` | `procName` | `procId` (UINT32) | `policyName` | `connMode` | `eventAction` (0=none,1=block,2=allow) | `user` | `msg` | `customer` | `ipProto`

## Workflow: Creating a New Parser

1. Identify the log format and sample log
2. Write `eventFormatRecognizer` — the regex that uniquely identifies this log source
3. Write `parsingInstructions` — extract fields step by step, set `eventType` and `eventSeverity` last
4. Validate XML: `xmllint --noout <file>.xml`
5. Write a test case in `test_parser.py` and run it
6. Register required event types in FortiSIEM: `ADMIN > Device Support > Event Types`
7. Import parser XML into FortiSIEM: `ADMIN > Device Support > Parsers`

## parserFunctionator10.sh

Runs **only on a live FortiSIEM appliance** (requires `/opt/phoenix/` paths and `phoenixdb` PostgreSQL). Version 10.0, tested on FSM 5.3.1. Useful for:
- Listing all `setEventAttribute` and `collectAndSet` functions available in the running FSM version
- Searching which parsers use a given function
- Extracting existing system or custom parser XML and test events from the database
- Checking which custom Event Attribute Types (EATs) a parser depends on

First run builds `<version>_SetFunctions` and `<version>_CollectFunctions` cache files. Subsequent runs use the cache.

## Reference Parsers

`downloaded_parsers/fortisiem-parsers/` — community parsers (Apache, Cisco ASA, Cisco WLC, OpenBSD, Zeek, Optelian, Transparency Logs)
`downloaded_parsers/FortiSIEM-Incapsula-Parser/` — Imperva Incapsula WAF parser

Use `zeek_parser.xml` as the primary reference for JSON-based log parsing with `collectAndSetAttrByJSON`.
Use `apache_parser.xml` as the primary reference for syslog-style parsing with `switch/case` multi-pattern matching.

## SentinelOne Singularity Integration Notes

- FSM ≤ 7.3: syslog CEF format, built-in system parser handles it
- FSM ≥ 7.4.1: HTTPS Advanced API poller (JSON, no traditional XML parser)
- `SentinelOneSingularity.xml` targets the syslog path with a `SENTINELONE_ACTIVITIES:` JSON payload
- The `incidentStatus` field is NOT present in activity-type events; it appears in threat events
- Time-based filtering (`createdAt` age) uses `minus(now(), $eventTime)` returning milliseconds; 5 days = 432,000,000 ms
