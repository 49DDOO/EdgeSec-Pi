"""Normalize Wazuh alert evidence for dashboard IT handoff.

This module is intentionally deterministic: it reads Wazuh raw alert fields
and LLM output, then exposes a stable evidence contract. It does not call the
LLM and it does not format UI copy.
"""
from __future__ import annotations

import re
from typing import Any

import canonical_context
import fim_risk_profile


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value in (None, ""):
        return []
    return [value]


def _first(*values: Any) -> str:
    for value in values:
        text = _text(value)
        if text:
            return text
    return ""


def _format_context_value(value: Any) -> str:
    if value in (None, "", [], {}):
        return ""
    if isinstance(value, dict):
        parts = []
        for key, item in value.items():
            rendered = _format_context_value(item)
            if rendered:
                parts.append(f"{key}: {rendered}")
        return "\n".join(parts)
    if isinstance(value, list):
        return "\n".join(
            rendered
            for item in value
            if (rendered := _format_context_value(item))
        )
    return _text(value)


def _extract_ip(text: str) -> str:
    match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text or "")
    return match.group(0) if match else ""


def _extract_source_ip(text: str) -> str:
    """從 log 文字保守抽取「來源 IP」：只認 `from <ip>` 樣式（典型認證失敗 log），
    並排除 loopback，避免把 netstat 之類的 127.0.0.1 誤判為來源。"""
    match = re.search(r"\bfrom\s+((?:\d{1,3}\.){3}\d{1,3})\b", text or "", re.I)
    if not match:
        return ""
    ip = match.group(1)
    return "" if ip.startswith("127.") else ip


def _guess_module(alert: dict[str, Any]) -> str:
    data = _dict(alert.get("data"))
    rule = _dict(alert.get("rule"))
    groups = {str(item).lower() for item in _list(rule.get("groups"))}
    description = _text(rule.get("description")).lower()
    full_log = _text(alert.get("full_log")).lower()

    if _dict(data.get("sca")) or "sca" in groups or "cis" in description:
        return "sca"
    if _dict(data.get("vulnerability")) or "vulnerability" in groups or "cve-" in full_log:
        return "vulnerability"
    if _dict(data.get("syscheck")) or {"syscheck", "fim"} & groups:
        return "fim"
    if "rootcheck" in groups or "rootkit" in description:
        return "rootcheck"
    if _dict(data.get("win")) or "windows" in groups:
        return "windows"
    if any(key in groups for key in ("authentication_failed", "authentication_success", "sshd", "pam")):
        return "authentication"
    if re.search(r"\b(sshd|failed password|invalid user|authentication failure|sudo)\b", full_log):
        return "authentication"
    if any(key in description for key in ("netstat", "listening", "port", "network connection")):
        return "syscollector"
    return "other"


def _mitre(rule: dict[str, Any], llm: dict[str, Any]) -> list[str]:
    mitre = _dict(rule.get("mitre"))
    values = [*_list(mitre.get("id")), llm.get("mitre")]
    return [str(item).strip() for item in values if str(item or "").strip()]


def _canonical_from(row: dict[str, Any], raw_alert: dict[str, Any]) -> dict[str, Any]:
    return canonical_context.signal_from_row(row, raw_alert)


def _canonical_module(signal: dict[str, Any]) -> str:
    signal_type = _text(signal.get("signal_type"))
    if signal_type.startswith("authentication."):
        return "authentication"
    if signal_type == "compliance.sca":
        return "sca"
    if signal_type == "vulnerability.detected":
        return "vulnerability"
    if signal_type == "endpoint.file_integrity":
        return "fim"
    if signal_type == "endpoint.rootcheck":
        return "rootcheck"
    if signal_type == "endpoint.windows_event":
        return "windows"
    if signal_type == "endpoint.process":
        return "process"
    if signal_type.startswith("identity."):
        return "identity"
    if signal_type.startswith("network."):
        return "network"
    return ""


def _merge_canonical_indicators(indicators: dict[str, Any], signal: dict[str, Any]) -> dict[str, Any]:
    merged = dict(indicators)
    actor = canonical_context.actor(signal)
    target = canonical_context.target(signal)
    observables = canonical_context.observables(signal)

    fallback_values = {
        "source_ip": actor.get("source_ip"),
        "destination_ip": target.get("destination_ip"),
        "username": _first(actor.get("user"), target.get("user")),
        "process": canonical_context.first_observable(signal, "processes"),
        "domain": canonical_context.first_observable(signal, "domains"),
    }
    for key, value in fallback_values.items():
        if not merged.get(key) and value:
            merged[key] = value

    if not merged.get("hashes") and observables.get("hashes"):
        merged["hashes"] = [str(item) for item in _list(observables.get("hashes")) if _text(item)]
    return merged


def _canonical_summary(signal: dict[str, Any]) -> dict[str, Any]:
    return {
        "source": _text(signal.get("source")),
        "source_product": _text(signal.get("source_product")),
        "signal_type": _text(signal.get("signal_type")),
        "title": _text(signal.get("title")),
        "asset": canonical_context.asset(signal),
        "actor": canonical_context.actor(signal),
        "target": canonical_context.target(signal),
        "observables": canonical_context.observables(signal),
        "source_context": canonical_context.source_context(signal),
    }


def _extract_username(alert: dict[str, Any]) -> str:
    data = _dict(alert.get("data"))
    full_log = _text(alert.get("full_log"))
    syscheck = _dict(data.get("syscheck"))
    audit = _dict(syscheck.get("audit"))
    audit_user = _dict(audit.get("user"))
    win_event = _dict(_dict(data.get("win")).get("eventdata"))
    direct = _first(
        data.get("dstuser"),
        data.get("srcuser"),
        data.get("user"),
        win_event.get("TargetUserName"),
        win_event.get("SubjectUserName"),
        audit_user.get("name"),
    )
    if direct:
        return direct
    patterns = [
        r"invalid user\s+([^\s]+)",
        r"Failed password for(?: invalid user)?\s+([^\s]+)",
        r"sudo:\s+([^\s]+)\s+:",
        r"user(?:name)?[=:]\s*([^\s,;]+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, full_log, re.I)
        if match:
            return match.group(1)
    return ""


def _indicators(alert: dict[str, Any], llm: dict[str, Any], module: str) -> dict[str, Any]:
    data = _dict(alert.get("data"))
    vuln = _dict(data.get("vulnerability"))
    package = _dict(vuln.get("package"))
    syscheck = _dict(data.get("syscheck"))
    audit = _dict(syscheck.get("audit"))
    process = _dict(audit.get("process"))
    win_event = _dict(_dict(data.get("win")).get("eventdata"))
    full_log = _text(alert.get("full_log"))

    # data.srcip 由 decoder 填入；若 decoder 未解析，退回從 full_log 文字抽取來源 IP
    src_ip = _first(data.get("srcip"), data.get("src_ip")) or _extract_source_ip(full_log)
    dst_ip = _first(data.get("dstip"), data.get("dst_ip"))
    username = _extract_username(alert)
    file_path = _first(syscheck.get("path"), data.get("file"), win_event.get("TargetFilename"))
    process_name = _first(process.get("name"), win_event.get("Image"), data.get("process"))
    port = _first(data.get("dstport"), data.get("srcport"), data.get("port"))
    cve = _first(vuln.get("cve"))
    package_name = _first(package.get("name"), vuln.get("package"))
    package_version = _first(package.get("version"))
    hash_before = {
        "md5": _first(syscheck.get("md5_before"), syscheck.get("old_md5"), syscheck.get("old_md5sum")),
        "sha1": _first(syscheck.get("sha1_before"), syscheck.get("old_sha1")),
        "sha256": _first(syscheck.get("sha256_before"), syscheck.get("old_sha256")),
    }
    hash_after = {
        "md5": _first(syscheck.get("md5_after"), syscheck.get("md5"), syscheck.get("new_md5"), syscheck.get("new_md5sum")),
        "sha1": _first(syscheck.get("sha1_after"), syscheck.get("sha1"), syscheck.get("new_sha1")),
        "sha256": _first(syscheck.get("sha256_after"), syscheck.get("sha256"), syscheck.get("new_sha256")),
    }
    hashes = [*hash_before.values(), *hash_after.values()]
    iocs = [str(item).strip() for item in _list(llm.get("iocs")) if str(item or "").strip()]

    return {
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "username": username,
        "file_path": file_path,
        "process": process_name,
        "port": port,
        "hashes": [item for item in hashes if item],
        "hash_before": {key: value for key, value in hash_before.items() if value},
        "hash_after": {key: value for key, value in hash_after.items() if value},
        "domain": _first(data.get("domain"), data.get("url")),
        "cve": cve,
        "package": package_name,
        "package_version": package_version,
        "iocs": iocs,
    }


def _module_context(module: str, alert: dict[str, Any]) -> dict[str, Any]:
    data = _dict(alert.get("data"))
    if module == "sca":
        check = _dict(_dict(data.get("sca")).get("check"))
        return {
            "check_title": _text(check.get("title")),
            "result": _text(check.get("result")),
            "description": _text(check.get("description")),
            "rationale": _text(check.get("rationale")),
            "checks_condition": _text(check.get("condition")),
            "checks": _format_context_value(
                check.get("checks")
                or check.get("rules")
                or check.get("check")
                or check.get("commands")
            ),
            "compliance": _format_context_value(
                check.get("compliance")
                or check.get("compliance_refs")
                or check.get("requirements")
            ),
            "remediation": _text(check.get("remediation")),
        }
    if module == "vulnerability":
        vuln = _dict(data.get("vulnerability"))
        package = _dict(vuln.get("package"))
        return {
            "cve": _text(vuln.get("cve")),
            "cvss": _first(vuln.get("cvss3"), vuln.get("cvss2")),
            "package": _first(package.get("name"), vuln.get("package")),
            "installed_version": _text(package.get("version")),
            "reference": _text(vuln.get("reference")),
        }
    if module == "fim":
        syscheck = _dict(data.get("syscheck"))
        audit = _dict(syscheck.get("audit"))
        return {
            "path": _text(syscheck.get("path")),
            "event": _text(syscheck.get("event")),
            "mode": _text(syscheck.get("mode")),
            "process": _text(_dict(audit.get("process")).get("name")),
            "user": _text(_dict(audit.get("user")).get("name")),
        }
    if module == "authentication":
        return {
            "source_ip": _first(data.get("srcip"), data.get("src_ip")),
            "username": _extract_username(alert),
            "authentication_result": "failed" if "fail" in _text(alert.get("full_log")).lower() else "",
        }
    return {}


def _event_label_zh(event: str) -> str:
    normalized = _text(event).lower()
    if normalized in {"added", "created"}:
        return "新增"
    if normalized in {"modified", "changed"}:
        return "修改"
    if normalized in {"deleted", "removed"}:
        return "刪除"
    if normalized in {"readded"}:
        return "重新出現"
    return _text(event) or "異動"


def _fim_brief(alert: dict[str, Any], row: dict[str, Any], indicators: dict[str, Any]) -> dict[str, Any] | None:
    data = _dict(alert.get("data"))
    syscheck = _dict(data.get("syscheck"))
    path = _first(syscheck.get("path"), indicators.get("file_path"))
    if not path:
        return None

    audit = _dict(syscheck.get("audit"))
    profile = fim_risk_profile.classify(path)
    event = _first(syscheck.get("event"), syscheck.get("mode"), "modified")
    changed_by = _first(indicators.get("username"), _dict(audit.get("user")).get("name"))
    process = _first(indicators.get("process"), _dict(audit.get("process")).get("name"))
    changed_at = _first(alert.get("timestamp"), row.get("timestamp"), row.get("received_at"))
    return {
        "title_zh": f"{profile['risk_label_zh']} - 需要確認",
        "category": profile["category"],
        "severity": profile["severity"],
        "risk_label_zh": profile["risk_label_zh"],
        "file_path": path,
        "event": event,
        "event_zh": _event_label_zh(event),
        "changed_by": changed_by or "Wazuh 未提供修改者",
        "process": process or "Wazuh 未提供程序",
        "changed_at": _text(changed_at),
        "business_meaning_zh": profile["business_meaning_zh"],
        "impact_zh": profile["impact_zh"],
        "recommended_steps_zh": profile["recommended_steps_zh"],
        "it_checks": profile["it_checks"],
        "hash_before": indicators.get("hash_before") or {},
        "hash_after": indicators.get("hash_after") or {},
        "matched_pattern": profile.get("matched_pattern", ""),
    }


def build_technical_evidence(
    *,
    row: dict[str, Any],
    raw_alert: dict[str, Any],
    llm: dict[str, Any],
) -> dict[str, Any]:
    """Build a stable evidence object for the dashboard."""
    signal = _canonical_from(row, raw_alert)
    rule = _dict(raw_alert.get("rule"))
    agent = _dict(raw_alert.get("agent"))
    module = _guess_module(raw_alert)
    if module == "other":
        module = _canonical_module(signal) or module
    groups = [str(item) for item in _list(rule.get("groups")) if str(item).strip()]
    indicators = _merge_canonical_indicators(_indicators(raw_alert, llm, module), signal)
    row_iocs = [str(item).strip() for item in _list(row.get("llm_iocs")) if str(item or "").strip()]
    if row_iocs and not indicators.get("iocs"):
        indicators["iocs"] = row_iocs
    remediation_wazuh = _first(
        _dict(_dict(raw_alert.get("data")).get("sca")).get("check", {}).get("remediation")
        if isinstance(_dict(_dict(raw_alert.get("data")).get("sca")).get("check"), dict)
        else "",
        _dict(_dict(raw_alert.get("data")).get("vulnerability")).get("reference"),
    )
    asset = _dict(signal.get("asset"))
    agent_os = _dict(agent.get("os"))

    evidence = {
        "source": _text(row.get("siem_source") or signal.get("source") or "wazuh"),
        "canonical": _canonical_summary(signal),
        "module": module,
        "rule": {
            "id": _text(rule.get("id") or row.get("rule_id")),
            "level": int(rule.get("level") or row.get("rule_level") or 0),
            "description": _text(rule.get("description") or row.get("rule_description")),
            "groups": groups,
            "mitre": _mitre(rule, llm),
        },
        "endpoint": {
            "agent_id": _text(agent.get("id") or row.get("agent_id") or asset.get("id")),
            "name": _text(agent.get("name") or row.get("agent_name") or asset.get("name")),
            "ip": _text(agent.get("ip") or row.get("agent_ip") or asset.get("ip")),
            "os": _text(agent_os.get("name") or agent_os.get("platform") or asset.get("os")),
            "version": _text(agent_os.get("version")),
        },
        "indicators": indicators,
        "module_context": _module_context(module, raw_alert),
        "remediation": {
            "wazuh": remediation_wazuh,
            "llm": _text(row.get("llm_action") or llm.get("action")),
        },
        "raw": {
            "full_log": _text(row.get("full_log") or raw_alert.get("full_log")),
        },
    }
    if module == "fim":
        brief = _fim_brief(raw_alert, row, indicators)
        if brief:
            evidence["fim_brief"] = brief
    return evidence
