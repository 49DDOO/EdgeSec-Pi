import sys
from pathlib import Path

import pytest

BRIDGE_DIR = Path(__file__).resolve().parents[2] / "wazuh-llm-bridge"
sys.path.insert(0, str(BRIDGE_DIR))

import technical_evidence  # noqa: E402


def evidence(alert, llm=None):
    return technical_evidence.build_technical_evidence(
        row={
            "siem_source": "wazuh",
            "rule_id": alert["rule"]["id"],
            "rule_level": alert["rule"]["level"],
            "rule_description": alert["rule"]["description"],
            "agent_id": alert.get("agent", {}).get("id", ""),
            "agent_name": alert.get("agent", {}).get("name", ""),
            "agent_ip": alert.get("agent", {}).get("ip", ""),
            "full_log": alert.get("full_log", ""),
            "llm_action": "Block source IP and verify successful logins.",
        },
        raw_alert=alert,
        llm=llm or {"iocs": [], "mitre": None, "action": ""},
    )


@pytest.mark.unit
def test_authentication_evidence_extracts_source_ip_and_username():
    item = evidence({
        "rule": {"id": "5712", "level": 10, "description": "sshd: brute force"},
        "agent": {"id": "003", "name": "web-prod", "ip": "10.0.0.10"},
        "full_log": "Failed password for invalid user admin from 203.0.113.45 port 55512 ssh2",
    })

    assert item["module"] == "authentication"
    assert item["indicators"]["source_ip"] == "203.0.113.45"
    assert item["indicators"]["username"] == "admin"
    assert item["endpoint"]["name"] == "web-prod"


@pytest.mark.unit
def test_sca_evidence_uses_wazuh_remediation():
    item = evidence({
        "rule": {"id": "19007", "level": 7, "description": "CIS benchmark failed"},
        "agent": {"id": "001", "name": "wazuh.manager"},
        "data": {
            "sca": {
                "check": {
                    "title": "Ensure gpgcheck is globally activated.",
                    "result": "failed",
                    "description": "Ensure packages are verified before install.",
                    "rationale": "Packages should be verified before install.",
                    "condition": "all",
                    "checks": [
                        "c:grep ^gpgcheck /etc/yum.conf -> r:^gpgcheck=1$",
                    ],
                    "compliance": {
                        "cis": ["1.2.3"],
                        "pci_dss_v3.2.1": ["6.2"],
                    },
                    "remediation": "Set gpgcheck=1 in /etc/yum.conf.",
                }
            }
        },
        "full_log": "SCA check failed",
    })

    assert item["module"] == "sca"
    assert item["module_context"]["check_title"] == "Ensure gpgcheck is globally activated."
    assert item["module_context"]["description"] == "Ensure packages are verified before install."
    assert item["module_context"]["checks_condition"] == "all"
    assert "grep ^gpgcheck /etc/yum.conf" in item["module_context"]["checks"]
    assert "cis: 1.2.3" in item["module_context"]["compliance"]
    assert "pci_dss_v3.2.1: 6.2" in item["module_context"]["compliance"]
    assert item["module_context"]["remediation"] == "Set gpgcheck=1 in /etc/yum.conf."
    assert item["remediation"]["wazuh"] == "Set gpgcheck=1 in /etc/yum.conf."


@pytest.mark.unit
def test_fim_evidence_extracts_path_user_and_process():
    item = evidence({
        "rule": {"id": "550", "level": 12, "description": "Integrity checksum changed."},
        "agent": {"id": "001", "name": "db-prod"},
        "data": {
            "syscheck": {
                "path": "/etc/shadow",
                "event": "modified",
                "audit": {
                    "user": {"name": "root"},
                    "process": {"name": "vim"},
                },
                "sha256_after": "abc123",
            }
        },
        "full_log": "File '/etc/shadow' checksum changed.",
    })

    assert item["module"] == "fim"
    assert item["indicators"]["file_path"] == "/etc/shadow"
    assert item["indicators"]["username"] == "root"
    assert item["indicators"]["process"] == "vim"
    assert "abc123" in item["indicators"]["hashes"]


@pytest.mark.unit
def test_vulnerability_evidence_extracts_cve_and_package():
    item = evidence({
        "rule": {"id": "23502", "level": 13, "description": "Vulnerability detected"},
        "agent": {"id": "003", "name": "web-prod"},
        "data": {
            "vulnerability": {
                "cve": "CVE-2024-38476",
                "cvss3": "9.8",
                "package": {"name": "httpd", "version": "2.4.58-1.el9"},
                "reference": "https://nvd.nist.gov/vuln/detail/CVE-2024-38476",
            }
        },
        "full_log": "Vulnerable package: httpd. CVE-2024-38476.",
    })

    assert item["module"] == "vulnerability"
    assert item["indicators"]["cve"] == "CVE-2024-38476"
    assert item["indicators"]["package"] == "httpd"
    assert item["module_context"]["cvss"] == "9.8"


@pytest.mark.unit
def test_windows_evidence_extracts_user_and_process():
    item = evidence({
        "rule": {
            "id": "92020",
            "level": 11,
            "description": "Suspicious PowerShell",
            "mitre": {"id": ["T1059.001"]},
        },
        "agent": {"id": "200", "name": "win-finance"},
        "data": {
            "win": {
                "eventdata": {
                    "TargetUserName": "alice",
                    "Image": "C:\\Windows\\System32\\powershell.exe",
                }
            }
        },
        "full_log": "EventID 4688 process create",
    })

    assert item["module"] == "windows"
    assert item["indicators"]["username"] == "alice"
    assert item["indicators"]["process"].endswith("powershell.exe")
    assert "T1059.001" in item["rule"]["mitre"]


@pytest.mark.unit
def test_syscollector_like_network_change_is_not_reduced_to_ioc_only():
    item = evidence({
        "rule": {"id": "533", "level": 7, "description": "Listened ports status changed"},
        "agent": {"id": "004", "name": "MB-TitanCheng", "ip": "192.168.50.106"},
        "data": {"port": "8080"},
        "full_log": "netstat: new listening port 8080/tcp detected",
    })

    assert item["module"] == "syscollector"
    assert item["indicators"]["port"] == "8080"
    assert item["endpoint"]["ip"] == "192.168.50.106"
