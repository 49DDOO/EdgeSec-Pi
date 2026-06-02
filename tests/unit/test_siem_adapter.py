from __future__ import annotations

import pytest

from support import fresh_bridge_import


def _siem():
    return fresh_bridge_import(["siem"])["siem"]


@pytest.mark.unit
def test_wazuh_payload_passes_through_with_edgesec_metadata() -> None:
    siem = _siem()
    payload = {
        "rule": {"id": "5712", "level": 10, "description": "SSH brute force"},
        "agent": {"id": "002", "name": "web-prod"},
        "data": {"srcip": "203.0.113.45"},
        "full_log": "Failed password for admin from 203.0.113.45",
    }

    alert = siem.normalize_alert(payload)

    assert alert["rule"] == payload["rule"]
    assert alert["agent"] == payload["agent"]
    assert alert["data"]["srcip"] == "203.0.113.45"
    assert alert["_edgesec"] == {
        "siem_source": "wazuh",
        "siem_product": "Wazuh",
        "normalized": False,
    }
    assert "_vendor_payload" not in alert


@pytest.mark.unit
def test_splunk_payload_normalizes_common_aliases() -> None:
    siem = _siem()
    payload = {
        "sourcetype": "linux_secure",
        "event_id": "splunk-5712",
        "severity": "high",
        "host": {"name": "branch-file-server", "ip": "10.0.2.10"},
        "source_ip": "198.51.100.8",
        "message": "Failed password for admin from 198.51.100.8",
    }

    alert = siem.normalize_alert(payload, source_hint="splunk")

    assert alert["rule"]["id"] == "splunk-5712"
    assert alert["rule"]["level"] == 12
    assert alert["rule"]["description"] == payload["message"]
    assert alert["agent"]["name"] == "branch-file-server"
    assert alert["agent"]["ip"] == "10.0.2.10"
    assert alert["data"]["srcip"] == "198.51.100.8"
    assert alert["_edgesec"]["siem_source"] == "splunk"
    assert alert["_edgesec"]["normalized"] is True
    assert alert["_vendor_payload"] == payload


@pytest.mark.unit
def test_elastic_payload_auto_detects_and_preserves_raw_payload() -> None:
    siem = _siem()
    payload = {
        "@timestamp": "2026-05-31T10:00:00Z",
        "event": {"kind": "alert", "severity": "warning", "reason": "Suspicious process"},
        "host": {"name": "macbook-01"},
        "source": {"ip": "203.0.113.99"},
        "process": {"name": "curl"},
    }

    alert = siem.normalize_alert(payload)

    assert alert["_edgesec"]["siem_source"] == "elastic"
    assert alert["rule"]["level"] == 8
    assert alert["rule"]["description"] == "Suspicious process"
    assert alert["agent"]["name"] == "macbook-01"
    assert alert["data"]["srcip"] == "203.0.113.99"
    assert alert["_vendor_payload"] == payload


@pytest.mark.unit
def test_explicit_source_aliases_are_normalized() -> None:
    siem = _siem()

    alert = siem.normalize_alert(
        {"severity": "critical", "message": "Risky sign-in", "user": "alice@example.com"},
        source_hint="m365",
    )

    assert alert["_edgesec"]["siem_source"] == "microsoft_365"
    assert alert["_edgesec"]["siem_product"] == "Microsoft 365"
    assert alert["rule"]["level"] == 15


@pytest.mark.unit
def test_unknown_explicit_source_is_rejected() -> None:
    siem = _siem()

    with pytest.raises(ValueError, match="unsupported SIEM source"):
        siem.normalize_alert({"message": "hello"}, source_hint="not-a-real-source")


@pytest.mark.unit
def test_non_object_payload_is_rejected() -> None:
    siem = _siem()

    with pytest.raises(ValueError, match="alert payload must be a JSON object"):
        siem.normalize_alert(["not", "an", "object"])  # type: ignore[arg-type]
