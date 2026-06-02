"""Wazuh rule context helpers for owner-facing investigations."""
from __future__ import annotations

import json
import logging
import re
from typing import Any

import wazuh

log = logging.getLogger("investigation-rules")


async def prefetch_rule_context(
    clean_messages: list[dict[str, str]],
    evidence: list[dict[str, Any]],
) -> str:
    """Attach current Wazuh rule details when the alert context includes a rule."""
    rule_id = extract_rule_id_from_messages(clean_messages)
    if not rule_id:
        return ""
    try:
        details = await wazuh.get_rule_details(rule_id)
    except Exception as exc:
        log.warning("failed to prefetch Wazuh rule details rule_id=%s: %s", rule_id, exc)
        evidence.append({
            "tool": "get_wazuh_rule_details",
            "args": {"rule_id": rule_id},
            "result_preview": f"查詢 Wazuh rule 失敗：{exc}",
            "result_log": f"查詢 Wazuh rule 失敗：{exc}",
        })
        return ""

    preview = rule_details_preview(details)
    evidence.append({
        "tool": "get_wazuh_rule_details",
        "args": {"rule_id": rule_id},
        "result_preview": preview[:240].replace("\n", " "),
        "result_log": preview,
    })
    if not details.get("ok"):
        return f"Wazuh rule context：Rule ID {rule_id} 目前無法從 Wazuh Manager API 找到。"
    return (
        "Wazuh rule context（即時從 Wazuh Manager API 查詢，不使用本地舊快取）：\n"
        f"{preview}"
    )


async def call_wazuh_rule_tool(args: dict[str, Any]) -> str:
    rule_id = str(args.get("rule_id") or "").strip()
    if not rule_id:
        return "rule_id is required"
    details = await wazuh.get_rule_details(rule_id)
    return rule_details_preview(details)


def rule_details_preview(details: dict[str, Any]) -> str:
    if not details.get("ok"):
        return str(details.get("error") or "Wazuh rule not found")
    metadata = details.get("metadata") or {}
    groups = metadata.get("groups") or metadata.get("group") or []
    mitre = metadata.get("mitre") or {}
    compliance_keys = ("pci_dss", "gdpr", "gpg13", "hipaa", "nist_800_53", "nist-800-53", "tsc")
    compliance = {
        key: metadata.get(key)
        for key in compliance_keys
        if metadata.get(key)
    }
    parts = [
        f"Rule ID: {metadata.get('id') or details.get('rule_id')}",
        f"Level: {metadata.get('level', '')}",
        f"Description: {metadata.get('description', '')}",
        f"Groups: {', '.join(groups) if isinstance(groups, list) else groups}",
        f"File: {details.get('relative_dirname') or ''}/{details.get('filename') or ''}".strip("/"),
    ]
    if mitre:
        parts.append(f"MITRE: {json.dumps(mitre, ensure_ascii=False)}")
    if compliance:
        parts.append(f"Compliance: {json.dumps(compliance, ensure_ascii=False)}")
    if details.get("rule_xml"):
        parts.append(f"Rule XML:\n{details['rule_xml'][:3000]}")
    return "\n".join(str(part) for part in parts if str(part).strip())


def extract_rule_id_from_messages(messages: list[dict[str, str]]) -> str:
    text = "\n".join(str(message.get("content") or "") for message in messages[-4:])
    patterns = [
        r"(?:Rule ID|rule_id|rule id|規則\s*ID)\s*[:：#]?\s*([A-Za-z0-9_.-]+)",
        r"(?:Rule|規則)\s*[:：#]?\s*([0-9]{3,})\b",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, re.I)
        if match:
            return match.group(1).strip()
    return ""
