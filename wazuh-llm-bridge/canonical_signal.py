"""Source-neutral signal contract for EdgeSec-Pi.

This is the first multi-source preparation layer. Existing SIEM adapters still
normalize payloads into the internal alert shape, then this module converts that
shape into a canonical signal that future prompts, playbooks, and storage can
consume without depending on Wazuh-only field names.
"""
from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from typing import Any


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value in (None, "", [], {}):
        return []
    return [value]


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _first(*values: Any) -> str:
    for value in values:
        text = _text(value)
        if text:
            return text
    return ""


def _nested(mapping: dict[str, Any], *path: str) -> Any:
    current: Any = mapping
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _clean(value: Any) -> Any:
    if isinstance(value, dict):
        cleaned = {str(key): _clean(item) for key, item in value.items()}
        return {key: item for key, item in cleaned.items() if item not in (None, "", [], {})}
    if isinstance(value, list):
        return [item for item in (_clean(item) for item in value) if item not in (None, "", [], {})]
    return value


def _epoch_iso(value: float | int | None) -> str:
    if value is None:
        return ""
    return datetime.fromtimestamp(float(value), timezone.utc).isoformat()


def _groups(rule: dict[str, Any]) -> list[str]:
    return [_text(item).lower() for item in _list(rule.get("groups")) if _text(item)]


def _mitre(rule: dict[str, Any]) -> list[str]:
    mitre = _dict(rule.get("mitre"))
    return [_text(item) for item in _list(mitre.get("id")) if _text(item)]


def _source_ip(data: dict[str, Any], full_log: str) -> str:
    direct = _first(
        data.get("srcip"),
        data.get("src_ip"),
        data.get("source_ip"),
        data.get("source.ip"),
        data.get("clientip"),
        data.get("client_ip"),
    )
    if direct:
        return direct
    match = re.search(r"\bfrom\s+((?:\d{1,3}\.){3}\d{1,3})\b", full_log or "", re.I)
    return match.group(1) if match else ""


def _vendor_source_ip(payload: dict[str, Any]) -> str:
    return _first(
        _nested(payload, "source", "ip"),
        _nested(payload, "client", "ip"),
        _nested(payload, "properties", "ipAddress"),
        payload.get("source_ip"),
        payload.get("src_ip"),
        payload.get("client_ip"),
        payload.get("ipAddress"),
        payload.get("ClientIP"),
    )


def _destination_ip(data: dict[str, Any], agent: dict[str, Any]) -> str:
    return _first(
        data.get("dstip"),
        data.get("dst_ip"),
        data.get("destination_ip"),
        data.get("destination.ip"),
        agent.get("ip"),
    )


def _vendor_destination_ip(payload: dict[str, Any]) -> str:
    return _first(
        _nested(payload, "destination", "ip"),
        _nested(payload, "server", "ip"),
        _nested(payload, "host", "ip"),
        payload.get("destination_ip"),
        payload.get("dst_ip"),
        payload.get("host_ip"),
    )


def _username(data: dict[str, Any], full_log: str) -> str:
    win_event = _dict(_dict(data.get("win")).get("eventdata"))
    direct = _first(
        data.get("dstuser"),
        data.get("srcuser"),
        data.get("user"),
        data.get("username"),
        win_event.get("TargetUserName"),
        win_event.get("SubjectUserName"),
    )
    if direct:
        return direct
    patterns = [
        r"invalid user\s+([^\s]+)",
        r"Failed password for(?: invalid user)?\s+([^\s]+)",
        r"sudo:\s+([^\s]+)\s+:",
    ]
    for pattern in patterns:
        match = re.search(pattern, full_log or "", re.I)
        if match:
            return match.group(1)
    return ""


def _vendor_username(payload: dict[str, Any]) -> str:
    return _first(
        _nested(payload, "user", "name"),
        _nested(payload, "user", "email"),
        _nested(payload, "user", "id"),
        _nested(payload, "actor", "user"),
        _nested(payload, "properties", "userPrincipalName"),
        payload.get("user"),
        payload.get("username"),
        payload.get("userPrincipalName"),
        payload.get("UserId"),
        payload.get("account"),
        payload.get("identity"),
    )


def _service(data: dict[str, Any], groups: list[str], full_log: str) -> str:
    direct = _first(data.get("service"), data.get("protocol"), data.get("app"))
    if direct:
        return direct
    if "sshd" in groups or "ssh" in (full_log or "").lower():
        return "ssh"
    return ""


def _vendor_service(payload: dict[str, Any]) -> str:
    return _first(
        _nested(payload, "network", "protocol"),
        _nested(payload, "url", "scheme"),
        _nested(payload, "destination", "service"),
        payload.get("service"),
        payload.get("protocol"),
        payload.get("Operation"),
        payload.get("eventName"),
    )


def _signal_type(alert: dict[str, Any]) -> str:
    data = _dict(alert.get("data"))
    rule = _dict(alert.get("rule"))
    meta = _dict(alert.get("_edgesec"))
    payload = _dict(alert.get("_vendor_payload"))
    groups = set(_groups(rule))
    description = _text(rule.get("description")).lower()
    full_log = _text(alert.get("full_log")).lower()
    win_system = _dict(_dict(_dict(data.get("win")).get("system")))
    channel = _text(win_system.get("channel")).lower()

    if _dict(data.get("sca")) or "sca" in groups or "cis" in description:
        return "compliance.sca"
    if _dict(data.get("vulnerability")) or "vulnerability" in groups or "cve-" in full_log:
        return "vulnerability.detected"
    if _dict(data.get("syscheck")) or {"syscheck", "fim"} & groups:
        return "endpoint.file_integrity"
    if "sysmon" in groups or "sysmon" in channel or "sysmon" in description:
        return "endpoint.process"
    if _dict(data.get("win")) or "windows" in groups:
        return "endpoint.windows_event"
    if "rootcheck" in groups or "rootkit" in description:
        return "endpoint.rootcheck"
    if any(group in groups for group in ("authentication_failed", "authentication_success", "sshd", "pam")):
        if any(token in full_log or token in description for token in ("brute", "failed", "invalid")):
            return "authentication.bruteforce"
        return "authentication.event"
    if re.search(r"\b(sshd|failed password|invalid user|authentication failure|sudo)\b", full_log):
        return "authentication.bruteforce"
    if "syscollector" in groups or any(token in description for token in ("netstat", "listening", "port")):
        return "network.exposure"
    source = _text(meta.get("siem_source"))
    if payload:
        event = _dict(payload.get("event"))
        event_category = " ".join(_text(item).lower() for item in _list(event.get("category")))
        event_action = _text(event.get("action")).lower()
        if _dict(payload.get("process")):
            return "endpoint.process"
        if _dict(payload.get("network")) or _dict(payload.get("destination")):
            return "network.connection"
        if source in {"microsoft_365", "google_workspace"} or _vendor_username(payload):
            if any(token in " ".join([event_action, description, full_log]) for token in ("risk", "risky", "impossible", "anomal")):
                return "identity.risky_signin"
            return "identity.event"
        if "authentication" in event_category:
            return "authentication.event"
    return "security.alert"


def _observables(alert: dict[str, Any], source_ip: str, destination_ip: str) -> dict[str, list[str]]:
    data = _dict(alert.get("data"))
    payload = _dict(alert.get("_vendor_payload"))
    syscheck = _dict(data.get("syscheck"))
    vulnerability = _dict(data.get("vulnerability"))
    package = _dict(vulnerability.get("package"))
    win_event = _dict(_dict(data.get("win")).get("eventdata"))
    audit = _dict(syscheck.get("audit"))
    audit_process = _dict(audit.get("process"))

    ips = []
    for value in (
        source_ip,
        destination_ip,
        _nested(payload, "source", "ip"),
        _nested(payload, "destination", "ip"),
        _nested(payload, "client", "ip"),
        _nested(payload, "server", "ip"),
        payload.get("source_ip"),
        payload.get("src_ip"),
        payload.get("destination_ip"),
        payload.get("dst_ip"),
        payload.get("ipAddress"),
        payload.get("ClientIP"),
    ):
        text = _text(value)
        if text and text not in ips:
            ips.append(text)

    hashes = []
    hash_sources = [
        syscheck,
        data,
        _dict(_nested(payload, "file", "hash")),
        _dict(payload.get("hash")),
    ]
    for source in hash_sources:
        for key in (
            "sha1",
            "sha256",
            "md5",
            "sha1_before",
            "sha256_before",
            "md5_before",
            "sha1_after",
            "sha256_after",
            "md5_after",
            "old_sha1",
            "old_sha256",
            "old_md5",
            "new_sha1",
            "new_sha256",
            "new_md5",
            "old_md5sum",
            "new_md5sum",
        ):
            value = _text(source.get(key))
            if value and value not in hashes:
                hashes.append(value)

    files = []
    for value in (
        syscheck.get("path"),
        data.get("file"),
        data.get("file_path"),
        win_event.get("Image"),
        win_event.get("TargetFilename"),
        _nested(payload, "file", "path"),
        _nested(payload, "process", "executable"),
    ):
        text = _text(value)
        if text and text not in files:
            files.append(text)

    processes = []
    for value in (
        audit_process.get("name"),
        win_event.get("Image"),
        data.get("process"),
        package.get("name"),
        _nested(payload, "process", "name"),
        _nested(payload, "process", "parent", "name"),
    ):
        text = _text(value)
        if text and text not in processes:
            processes.append(text)

    commands = []
    for value in (
        data.get("command"),
        data.get("cmd"),
        win_event.get("CommandLine"),
        _nested(payload, "process", "command_line"),
        _nested(payload, "process", "args"),
        payload.get("CommandLine"),
    ):
        text = _text(value)
        if text and text not in commands:
            commands.append(text)

    domains = []
    for value in (
        data.get("domain"),
        data.get("url"),
        _nested(payload, "destination", "domain"),
        _nested(payload, "url", "domain"),
        _nested(payload, "dns", "question", "name"),
        payload.get("domain"),
    ):
        text = _text(value)
        if text and text not in domains:
            domains.append(text)

    return {
        "ips": ips,
        "domains": domains,
        "hashes": hashes,
        "files": files,
        "processes": processes,
        "commands": commands,
    }


def _source_specific(alert: dict[str, Any], source: str) -> dict[str, Any]:
    """Keep source-native structured context without making it the core schema."""
    data = _dict(alert.get("data"))
    rule = _dict(alert.get("rule"))
    payload = _dict(alert.get("_vendor_payload"))

    if source == "wazuh":
        wazuh_specific: dict[str, Any] = {
            "rule": {
                "id": rule.get("id"),
                "level": rule.get("level"),
                "description": rule.get("description"),
                "groups": rule.get("groups"),
                "mitre": rule.get("mitre"),
            },
            "decoder": alert.get("decoder"),
            "manager": alert.get("manager"),
        }
        for key in ("syscheck", "sca", "vulnerability", "win"):
            if isinstance(data.get(key), dict):
                wazuh_specific[key] = data[key]
        return {"wazuh": _clean(wazuh_specific)}

    selected_keys = (
        "event",
        "rule",
        "host",
        "source",
        "destination",
        "client",
        "server",
        "observer",
        "user",
        "process",
        "network",
        "file",
        "url",
        "dns",
        "email",
        "cloud",
        "properties",
        "sourcetype",
        "index",
        "risk",
        "severity",
        "userPrincipalName",
        "UserId",
        "ClientIP",
        "Operation",
        "AppId",
        "ipAddress",
        "riskLevel",
        "riskEventType",
    )
    source_specific = {key: payload.get(key) for key in selected_keys if key in payload}
    return {source: _clean(source_specific)} if source_specific else {}


def from_alert(alert: dict[str, Any], *, received_at: float | int | None = None) -> dict[str, Any]:
    """Build a source-neutral signal from the current internal alert shape."""
    if not isinstance(alert, dict):
        raise ValueError("alert must be a dict")

    rule = _dict(alert.get("rule"))
    agent = _dict(alert.get("agent"))
    data = _dict(alert.get("data"))
    meta = _dict(alert.get("_edgesec"))
    payload = _dict(alert.get("_vendor_payload"))
    full_log = _text(alert.get("full_log"))
    groups = _groups(rule)
    source = _text(meta.get("siem_source")) or "wazuh"
    source_product = _text(meta.get("siem_product")) or source
    source_ip = _source_ip(data, full_log) or _vendor_source_ip(payload)
    destination_ip = _destination_ip(data, agent) or _vendor_destination_ip(payload)
    username = _username(data, full_log) or _vendor_username(payload)
    event_time = _first(
        alert.get("timestamp"),
        alert.get("@timestamp"),
        data.get("timestamp"),
        payload.get("@timestamp"),
        _nested(payload, "event", "created"),
        _nested(payload, "properties", "createdDateTime"),
    )
    source_event_id = _first(
        alert.get("id"),
        alert.get("_id"),
        data.get("id"),
        rule.get("id"),
        payload.get("id"),
        payload.get("event_id"),
        _nested(payload, "event", "id"),
    )

    return {
        "schema_version": "1.0",
        "source": source,
        "source_product": source_product,
        "source_event_id": source_event_id,
        "event_time": event_time,
        "received_time": _epoch_iso(received_at if received_at is not None else time.time()),
        "signal_type": _signal_type(alert),
        "title": _text(rule.get("description")) or "Security event",
        "native_severity": _text(rule.get("level")),
        "asset": {
            "id": _text(agent.get("id")),
            "name": _text(agent.get("name")) or source_product,
            "ip": _text(agent.get("ip")),
            "os": _text(_dict(agent.get("os")).get("platform") or _dict(agent.get("os")).get("name")),
            "business_criticality": "",
        },
        "actor": {
            "user": username,
            "source_ip": source_ip,
            "source_geo": _text(data.get("srcgeo") or data.get("source_geo")),
            "identity_provider": "",
        },
        "target": {
            "user": _first(data.get("dstuser"), username),
            "destination_ip": destination_ip,
            "service": _service(data, groups, full_log) or _vendor_service(payload),
        },
        "observables": _observables(alert, source_ip, destination_ip),
        "source_context": {
            "rule_id": _text(rule.get("id")),
            "rule_groups": groups,
            "mitre": _mitre(rule),
            "native_level": _text(rule.get("level")),
            "decoder": _text(_dict(alert.get("decoder")).get("name")),
            "manager": _text(_dict(alert.get("manager")).get("name")),
        },
        "raw_ref": {
            "kind": "raw_alert",
            "id": source_event_id,
        },
        "source_specific": _source_specific(alert, source),
    }


def safe_from_alert(alert: dict[str, Any], *, received_at: float | int | None = None) -> dict[str, Any]:
    try:
        return from_alert(alert, received_at=received_at)
    except Exception as exc:
        return {
            "schema_version": "1.0",
            "source": "unknown",
            "source_product": "unknown",
            "source_event_id": "",
            "event_time": "",
            "received_time": _epoch_iso(received_at if received_at is not None else time.time()),
            "signal_type": "security.alert",
            "title": "Security event",
            "native_severity": "",
            "asset": {"id": "", "name": "", "ip": "", "os": "", "business_criticality": ""},
            "actor": {"user": "", "source_ip": "", "source_geo": "", "identity_provider": ""},
            "target": {"user": "", "destination_ip": "", "service": ""},
            "observables": {"ips": [], "domains": [], "hashes": [], "files": [], "processes": [], "commands": []},
            "source_context": {"rule_id": "", "rule_groups": [], "mitre": [], "native_level": "", "decoder": "", "manager": ""},
            "raw_ref": {"kind": "raw_alert", "id": ""},
            "source_specific": {},
            "error": repr(exc),
        }
