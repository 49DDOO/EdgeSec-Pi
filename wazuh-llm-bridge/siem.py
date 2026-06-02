"""SIEM adapter boundary for EdgeSec-Pi.

The bridge started with Wazuh, but the core pipeline should not care which
SIEM produced the event. Adapters normalize vendor-specific payloads into the
internal shape already used by the LLM, DB, Slack, and dashboard:

    rule:  {id, level, description}
    agent: {id, name, ip}
    data:  {srcip, ...}
    full_log: str

Wazuh keeps passing through as-is. Other SIEMs can be added here without
touching the worker queue, persistence, or owner UI. Stage-1 prompting now
projects this compatibility envelope into `canonical_signal` before building
the LLM prompt.
"""
from __future__ import annotations

import json
from typing import Any


SOURCE_LABELS = {
    "wazuh": "Wazuh",
    "generic": "Generic SIEM",
    "splunk": "Splunk",
    "elastic": "Elastic Security",
    "sentinel": "Microsoft Sentinel",
    "qradar": "IBM QRadar",
    "google_workspace": "Google Workspace",
    "microsoft_365": "Microsoft 365",
    "firewall": "Firewall / Edge",
    "edr": "EDR",
}

SEVERITY_TO_LEVEL = {
    "critical": 15,
    "fatal": 15,
    "high": 12,
    "medium": 10,
    "moderate": 10,
    "warn": 8,
    "warning": 8,
    "low": 6,
    "info": 3,
    "informational": 3,
}


def _source_key(value: str | None) -> str:
    key = (value or "auto").strip().lower().replace("-", "_")
    aliases = {
        "ms_sentinel": "sentinel",
        "microsoft_sentinel": "sentinel",
        "elastic_security": "elastic",
        "generic_siem": "generic",
        "m365": "microsoft_365",
        "o365": "microsoft_365",
        "office_365": "microsoft_365",
        "google": "google_workspace",
        "gworkspace": "google_workspace",
    }
    return aliases.get(key, key)


def _as_int(value: Any, default: int = 3) -> int:
    if isinstance(value, bool):
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _severity_level(value: Any) -> int:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return max(0, min(15, int(value)))
    text = str(value or "").strip().lower()
    return SEVERITY_TO_LEVEL.get(text, 3)


def _pick(*values: Any) -> Any:
    for value in values:
        if value not in (None, "", [], {}):
            return value
    return None


def detect_source(payload: dict[str, Any]) -> str:
    if "rule" in payload and (
        "agent" in payload
        or "manager" in payload
        or "decoder" in payload
        or "predecoder" in payload
        or "full_log" in payload
    ):
        return "wazuh"
    source_value = payload.get("source")
    if isinstance(source_value, str) and _source_key(source_value) in SOURCE_LABELS:
        return _source_key(source_value)
    if payload.get("sourcetype") or payload.get("index"):
        return "splunk"
    if payload.get("@timestamp") and payload.get("event"):
        return "elastic"
    return "generic"


def source_label(source: str | None) -> str:
    key = _source_key(source)
    return SOURCE_LABELS.get(key, key.upper() if key else "SIEM")


def normalize_alert(payload: dict[str, Any], source_hint: str = "auto") -> dict[str, Any]:
    """Return an internal EdgeSec-Pi alert.

    `source_hint` is used by `/webhook/{source}`. Existing `/webhook` calls use
    auto-detection and remain compatible with Wazuh's native alert JSON.
    """
    if not isinstance(payload, dict):
        raise ValueError("alert payload must be a JSON object")

    hint = _source_key(source_hint)
    source = detect_source(payload) if hint == "auto" else hint
    if source not in SOURCE_LABELS:
        raise ValueError(f"unsupported SIEM source: {source_hint}")
    if source == "wazuh":
        alert = dict(payload)
        alert.setdefault("rule", {})
        alert.setdefault("agent", {})
        alert.setdefault("data", payload.get("data") or {})
        previous_meta = payload.get("_edgesec") if isinstance(payload.get("_edgesec"), dict) else {}
        alert["_edgesec"] = {
            **previous_meta,
            "siem_source": "wazuh",
            "siem_product": "Wazuh",
            "normalized": False,
        }
        if payload.get("@sampledata") is True:
            alert["_edgesec"]["sampledata"] = True
        return alert

    event = payload.get("event") if isinstance(payload.get("event"), dict) else {}
    rule = payload.get("rule") if isinstance(payload.get("rule"), dict) else {}
    host = payload.get("host") if isinstance(payload.get("host"), dict) else {}
    observer = payload.get("observer") if isinstance(payload.get("observer"), dict) else {}
    source_obj = payload.get("source") if isinstance(payload.get("source"), dict) else {}

    severity = _pick(
        payload.get("severity"),
        payload.get("risk"),
        event.get("severity"),
        rule.get("level"),
        rule.get("severity"),
    )
    level = _as_int(rule.get("level"), _severity_level(severity))
    description = _pick(
        rule.get("description"),
        rule.get("name"),
        payload.get("description"),
        payload.get("message"),
        event.get("reason"),
        event.get("action"),
        "Security event",
    )
    host_name = _pick(
        host.get("name"),
        payload.get("host_name"),
        payload.get("hostname"),
        observer.get("name"),
        source_label(source),
    )
    srcip = _pick(
        payload.get("srcip"),
        payload.get("src_ip"),
        payload.get("source_ip"),
        source_obj.get("ip"),
    )
    full_log = _pick(
        payload.get("full_log"),
        payload.get("raw_log"),
        payload.get("message"),
        payload.get("_raw"),
        json.dumps(payload, ensure_ascii=False),
    )

    return {
        "rule": {
            "id": str(_pick(rule.get("id"), rule.get("rule_id"), payload.get("event_id"), payload.get("id"), "generic")),
            "level": level,
            "description": str(description),
        },
        "agent": {
            "id": str(_pick(host.get("id"), payload.get("agent_id"), payload.get("host_id"), "")),
            "name": str(host_name),
            "ip": _pick(host.get("ip"), payload.get("host_ip"), observer.get("ip")),
        },
        "data": {
            **(payload.get("data") if isinstance(payload.get("data"), dict) else {}),
            **({"srcip": srcip} if srcip else {}),
        },
        "full_log": str(full_log),
        "_edgesec": {
            "siem_source": source,
            "siem_product": source_label(source),
            "normalized": True,
        },
        "_vendor_payload": payload,
    }
