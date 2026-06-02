from __future__ import annotations

import json

import pytest

from support import fresh_bridge_import


@pytest.mark.unit
def test_wazuh_ssh_alert_maps_to_canonical_signal() -> None:
    canonical_signal = fresh_bridge_import(["canonical_signal"])["canonical_signal"]

    signal = canonical_signal.from_alert(
        {
            "id": "1730000000.12345",
            "timestamp": "2026-05-30T10:14:00Z",
            "rule": {
                "id": "5712",
                "level": 10,
                "description": "sshd: brute force trying to get access",
                "groups": ["authentication_failed", "sshd"],
                "mitre": {"id": ["T1110"]},
            },
            "agent": {"id": "002", "name": "web-prod", "ip": "192.0.2.10", "os": {"platform": "linux"}},
            "data": {"srcip": "203.0.113.45", "dstuser": "admin"},
            "full_log": "Failed password for admin from 203.0.113.45 port 55512 ssh2",
            "_edgesec": {"siem_source": "wazuh", "siem_product": "Wazuh"},
        },
        received_at=1760000000,
    )

    assert signal["schema_version"] == "1.0"
    assert signal["source"] == "wazuh"
    assert signal["signal_type"] == "authentication.bruteforce"
    assert signal["asset"]["name"] == "web-prod"
    assert signal["asset"]["os"] == "linux"
    assert signal["actor"]["user"] == "admin"
    assert signal["actor"]["source_ip"] == "203.0.113.45"
    assert signal["target"]["service"] == "ssh"
    assert "203.0.113.45" in signal["observables"]["ips"]
    assert signal["source_context"]["rule_id"] == "5712"
    assert signal["source_context"]["mitre"] == ["T1110"]
    assert signal["source_specific"]["wazuh"]["rule"]["id"] == "5712"


@pytest.mark.unit
def test_wazuh_fim_canonical_preserves_source_specific_file_context() -> None:
    canonical_signal = fresh_bridge_import(["canonical_signal"])["canonical_signal"]

    signal = canonical_signal.from_alert(
        {
            "id": "fim-1",
            "rule": {
                "id": "550",
                "level": 12,
                "description": "Integrity checksum changed.",
                "groups": ["syscheck"],
            },
            "agent": {"id": "001", "name": "db-prod"},
            "data": {
                "syscheck": {
                    "path": "/etc/shadow",
                    "event": "modified",
                    "old_md5": "old-md5",
                    "new_md5": "new-md5",
                    "sha256_after": "new-sha256",
                    "audit": {
                        "process": {"name": "vim"},
                        "user": {"name": "root"},
                    },
                }
            },
            "full_log": "File '/etc/shadow' checksum changed.",
            "_edgesec": {"siem_source": "wazuh", "siem_product": "Wazuh"},
        },
        received_at=1760000000,
    )

    assert signal["signal_type"] == "endpoint.file_integrity"
    assert "/etc/shadow" in signal["observables"]["files"]
    assert "old-md5" in signal["observables"]["hashes"]
    assert "new-md5" in signal["observables"]["hashes"]
    assert "new-sha256" in signal["observables"]["hashes"]
    assert "vim" in signal["observables"]["processes"]
    syscheck = signal["source_specific"]["wazuh"]["syscheck"]
    assert syscheck["path"] == "/etc/shadow"
    assert syscheck["audit"]["user"]["name"] == "root"
    assert syscheck["audit"]["process"]["name"] == "vim"


@pytest.mark.unit
def test_wazuh_sca_canonical_preserves_check_context() -> None:
    canonical_signal = fresh_bridge_import(["canonical_signal"])["canonical_signal"]

    signal = canonical_signal.from_alert(
        {
            "id": "sca-1",
            "rule": {"id": "19007", "level": 7, "description": "CIS check failed", "groups": ["sca"]},
            "agent": {"id": "002", "name": "macbook-01"},
            "data": {
                "sca": {
                    "policy": "CIS Apple macOS",
                    "check": {
                        "id": "5.2.3",
                        "title": "Ensure Firewall is Enabled",
                        "result": "failed",
                        "description": "Firewall should be enabled.",
                        "rationale": "A firewall protects against unauthorized network access.",
                        "remediation": "Open System Settings > Network > Firewall and toggle on.",
                        "checks": ["c: /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate"],
                    },
                }
            },
            "full_log": "SCA: CIS 5.2.3 Firewall check failed",
            "_edgesec": {"siem_source": "wazuh", "siem_product": "Wazuh"},
        },
        received_at=1760000000,
    )

    assert signal["signal_type"] == "compliance.sca"
    sca = signal["source_specific"]["wazuh"]["sca"]
    assert sca["policy"] == "CIS Apple macOS"
    assert sca["check"]["title"] == "Ensure Firewall is Enabled"
    assert "Firewall and toggle on" in sca["check"]["remediation"]
    assert "socketfilterfw" in sca["check"]["checks"][0]


@pytest.mark.unit
def test_splunk_auth_payload_maps_after_normalization() -> None:
    modules = fresh_bridge_import(["siem", "canonical_signal"])
    siem = modules["siem"]
    canonical_signal = modules["canonical_signal"]

    alert = siem.normalize_alert(
        {
            "sourcetype": "linux_secure",
            "event_id": "splunk-5712",
            "severity": "high",
            "host": {"name": "branch-file-server", "ip": "10.0.2.10"},
            "source_ip": "198.51.100.8",
            "message": "Failed password for admin from 198.51.100.8",
        },
        source_hint="splunk",
    )
    signal = canonical_signal.from_alert(alert, received_at=1760000000)

    assert signal["source"] == "splunk"
    assert signal["source_product"] == "Splunk"
    assert signal["signal_type"] == "authentication.bruteforce"
    assert signal["asset"]["name"] == "branch-file-server"
    assert signal["actor"]["source_ip"] == "198.51.100.8"
    assert signal["actor"]["user"] == "admin"
    assert signal["native_severity"] == "12"
    assert signal["raw_ref"]["id"] == "splunk-5712"
    assert signal["source_specific"]["splunk"]["sourcetype"] == "linux_secure"


@pytest.mark.unit
def test_elastic_process_payload_keeps_process_context() -> None:
    modules = fresh_bridge_import(["siem", "canonical_signal"])
    siem = modules["siem"]
    canonical_signal = modules["canonical_signal"]

    payload = {
        "@timestamp": "2026-05-31T10:00:00Z",
        "event": {"id": "elastic-4104", "kind": "alert", "severity": "warning", "reason": "Suspicious process"},
        "host": {"name": "macbook-01"},
        "source": {"ip": "203.0.113.99"},
        "process": {
            "name": "powershell.exe",
            "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "command_line": "powershell -enc SQBFAFgA",
            "parent": {"name": "winword.exe"},
        },
        "file": {"hash": {"sha256": "abc123"}},
    }
    alert = siem.normalize_alert(payload, source_hint="elastic")
    signal = canonical_signal.from_alert(alert, received_at=1760000000)

    assert signal["source"] == "elastic"
    assert signal["signal_type"] == "endpoint.process"
    assert signal["event_time"] == "2026-05-31T10:00:00Z"
    assert "powershell.exe" in signal["observables"]["processes"]
    assert "winword.exe" in signal["observables"]["processes"]
    assert "powershell -enc SQBFAFgA" in signal["observables"]["commands"]
    assert "abc123" in signal["observables"]["hashes"]
    assert signal["source_specific"]["elastic"]["process"]["parent"]["name"] == "winword.exe"


@pytest.mark.unit
def test_microsoft_365_risky_signin_maps_identity_context() -> None:
    modules = fresh_bridge_import(["siem", "canonical_signal"])
    siem = modules["siem"]
    canonical_signal = modules["canonical_signal"]

    payload = {
        "id": "m365-risk-1",
        "severity": "critical",
        "userPrincipalName": "alice@example.com",
        "ipAddress": "198.51.100.44",
        "riskLevel": "high",
        "riskEventType": "impossibleTravel",
        "Operation": "UserLoggedIn",
        "message": "Risky sign-in from impossible travel.",
        "properties": {"userPrincipalName": "alice@example.com", "ipAddress": "198.51.100.44"},
    }
    alert = siem.normalize_alert(payload, source_hint="m365")
    signal = canonical_signal.from_alert(alert, received_at=1760000000)

    assert signal["source"] == "microsoft_365"
    assert signal["source_product"] == "Microsoft 365"
    assert signal["signal_type"] == "identity.risky_signin"
    assert signal["actor"]["user"] == "alice@example.com"
    assert signal["actor"]["source_ip"] == "198.51.100.44"
    assert signal["target"]["service"] == "UserLoggedIn"
    assert signal["native_severity"] == "15"
    assert signal["source_specific"]["microsoft_365"]["riskEventType"] == "impossibleTravel"


@pytest.mark.unit
def test_db_persists_canonical_signal(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.setenv("DB_PATH", str(tmp_path / "alerts.db"))
    db = fresh_bridge_import(["db"])["db"]
    db.init_db_sync()

    alert_id = db._save_alert_sync(
        {
            "rule": {"id": "550", "level": 12, "description": "Integrity checksum changed.", "groups": ["syscheck"]},
            "agent": {"id": "001", "name": "db-prod"},
            "data": {"syscheck": {"path": "/etc/shadow", "sha256_after": "abc123"}},
            "full_log": "File '/etc/shadow' checksum changed.",
            "_edgesec": {"siem_source": "wazuh", "siem_product": "Wazuh"},
        },
        "{}",
        {"severity": "high"},
        1,
        None,
    )

    row = db._get_alert_sync(alert_id)
    assert row is not None
    signal = json.loads(row["canonical_signal"])
    assert signal["source"] == "wazuh"
    assert signal["signal_type"] == "endpoint.file_integrity"
    assert signal["asset"]["name"] == "db-prod"
    assert "/etc/shadow" in signal["observables"]["files"]
    assert "abc123" in signal["observables"]["hashes"]
    assert signal["source_specific"]["wazuh"]["syscheck"]["path"] == "/etc/shadow"
