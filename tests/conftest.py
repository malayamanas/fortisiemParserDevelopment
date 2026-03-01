import pytest
import tempfile
import os

SAMPLE_SYSLOG_JSON = (
    'Jul 23 00:33:28 2025 host.example.com 1.2.3.4 SENTINELONE_THREATS: '
    '{"threatInfo":{"threatName":"Mimikatz","confidenceLevel":"malicious",'
    '"mitigationStatus":"not_mitigated"},"agentDetectionInfo":{"agentIp":"10.0.0.1"},'
    '"accountName":"LabCorp"}'
)

SAMPLE_SYSLOG_KV = (
    'Jul 23 10:05:15 2025 fw01 192.168.1.1 '
    'srcip=10.0.0.5 dstip=8.8.8.8 action=deny proto=tcp sport=54321 dport=443'
)

SAMPLE_SYSLOG_TEXT = (
    'Jul 23 10:05:15 2025 apache01 192.168.1.2 '
    '192.168.0.1 - frank [10/Oct/2000:13:55:36 -0700] '
    '"GET /apache_pb.gif HTTP/1.0" 200 2326'
)

SAMPLE_SYSLOG_BRACKET_KV = (
    'Jul 23 10:05:15 2025 gw01 10.0.0.1 MORPHISEC_ATTACK '
    '{"Account Id":"[\\"abc123\\"]","Computer Name":"[\\"WORKSTATION01\\"]",'
    '"Protector IP":"[\\"192.168.0.139\\"]"}'
)

SAMPLE_PURE_JSON = (
    '{"id":"evt-001","type":"alert","severity":3,'
    '"srcIp":"10.0.0.5","destIp":"8.8.8.8","message":"Port scan detected"}'
)

@pytest.fixture
def tmp_db(tmp_path):
    """Returns path to a temporary SQLite database."""
    return str(tmp_path / "test.db")
