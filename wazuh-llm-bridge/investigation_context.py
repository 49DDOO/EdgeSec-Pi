"""Prompt context builders for owner-facing investigations."""
from __future__ import annotations

import os
import time
from datetime import datetime
from typing import Any

import canonical_context
import investigation_evidence
import prompt_safety


FAST_PLAYBOOK_ALERT_LOG_MAX_CHARS = int(os.getenv("INVESTIGATION_CHAT_FAST_ALERT_LOG_MAX", "600"))


def alert_facts(row: dict[str, Any]) -> dict[str, Any]:
    raw_alert = investigation_evidence.json_obj(row.get("raw_alert"))
    signal = canonical_context.signal_from_row(row, raw_alert)
    source_context = canonical_context.source_context(signal)
    asset = canonical_context.asset(signal)
    actor = canonical_context.actor(signal)
    target = canonical_context.target(signal)
    observables = canonical_context.observables(signal)
    data = investigation_evidence.as_dict(raw_alert.get("data"))
    agent = investigation_evidence.as_dict(raw_alert.get("agent"))
    rule = investigation_evidence.as_dict(raw_alert.get("rule"))
    mitre = investigation_evidence.as_dict(rule.get("mitre"))
    indicators = {
        "source_ip": investigation_evidence.text(
            actor.get("source_ip")
            or data.get("srcip")
            or data.get("src_ip")
            or data.get("source_ip")
        ),
        "destination_ip": investigation_evidence.text(
            target.get("destination_ip")
            or data.get("dstip")
            or data.get("dst_ip")
            or data.get("destination_ip")
        ),
        "username": investigation_evidence.text(
            actor.get("user")
            or target.get("user")
            or data.get("srcuser")
            or data.get("dstuser")
            or data.get("user")
            or data.get("username")
        ),
        "file_path": investigation_evidence.text(
            canonical_context.first_observable(signal, "files")
            or investigation_evidence.as_dict(data.get("syscheck")).get("path")
        ),
        "process": investigation_evidence.text(
            canonical_context.first_observable(signal, "processes")
            or investigation_evidence.as_dict(
                investigation_evidence.as_dict(data.get("syscheck")).get("audit")
            ).get("process")
        ),
        "domain": investigation_evidence.text(canonical_context.first_observable(signal, "domains")),
        "port": investigation_evidence.text(data.get("srcport") or data.get("dstport") or data.get("port")),
    }
    for key in ("ips", "hashes", "commands"):
        values = [investigation_evidence.text(item) for item in canonical_context.as_list(observables.get(key))]
        if values:
            indicators[f"observables_{key}"] = ", ".join(item for item in values if item)
    module_lines = []
    for key, value in indicators.items():
        if value:
            module_lines.append(f"- {key}: {value}")

    event_time = (
        investigation_evidence.text(signal.get("event_time"))
        or investigation_evidence.text(raw_alert.get("timestamp"))
        or investigation_evidence.text(raw_alert.get("@timestamp"))
        or datetime.fromtimestamp(float(row.get("received_at") or time.time())).astimezone().isoformat(timespec="seconds")
    )
    full_log = investigation_evidence.cap_text(
        investigation_evidence.text(row.get("full_log") or raw_alert.get("full_log")),
        2400,
    )
    source_ip = indicators["source_ip"]
    agent_ip = investigation_evidence.text(row.get("agent_ip") or asset.get("ip") or agent.get("ip"))
    agent_id = investigation_evidence.text(row.get("agent_id") or asset.get("id") or agent.get("id"))
    agent_name = investigation_evidence.text(row.get("agent_name") or asset.get("name") or agent.get("name"))
    rule_id = investigation_evidence.text(row.get("rule_id") or source_context.get("rule_id") or rule.get("id"))
    rule_level = investigation_evidence.text(
        row.get("rule_level") or signal.get("native_severity") or rule.get("level")
    )
    rule_description = investigation_evidence.text(
        row.get("rule_description") or signal.get("title") or rule.get("description")
    )
    mitre_ids = canonical_context.mitre_ids(signal) or mitre.get("id") or []
    if isinstance(mitre_ids, str):
        mitre_ids = [mitre_ids]

    return {
        "alert_id": row.get("id"),
        "source": investigation_evidence.text(signal.get("source") or row.get("siem_source") or "wazuh"),
        "source_product": investigation_evidence.text(signal.get("source_product") or row.get("siem_source") or "Wazuh"),
        "source_event_id": investigation_evidence.text(signal.get("source_event_id")),
        "signal_type": investigation_evidence.text(signal.get("signal_type")),
        "event_time": event_time,
        "agent_name": agent_name,
        "agent_id": agent_id,
        "agent_ip": agent_ip,
        "source_ip": source_ip,
        "destination_ip": indicators["destination_ip"],
        "target_service": investigation_evidence.text(target.get("service")),
        "username": indicators["username"],
        "rule_id": rule_id,
        "rule_level": rule_level,
        "rule_description": rule_description,
        "severity": investigation_evidence.text(row.get("llm_severity")),
        "mitre_ids": mitre_ids if isinstance(mitre_ids, list) else [],
        "source_specific_keys": canonical_context.source_specific_keys(signal),
        "indicators": indicators,
        "module_lines": module_lines,
        "full_log": full_log,
    }


def build_alert_question_context(row: dict[str, Any], question: str) -> str:
    facts = alert_facts(row)
    current_values = "\n".join([
        f"- 發生時間: {facts['event_time']}",
        f"- 電腦名稱: {facts['agent_name'] or 'unknown'}",
        f"- Agent ID: {facts['agent_id']}",
        f"- Agent IP: {facts['agent_ip']}（端點 IP，不可當作來源 IP / srcip 查詢）" if facts["agent_ip"] else "",
        f"- 來源 IP: {facts['source_ip']}" if facts["source_ip"] else "",
        f"- 目的 IP: {facts['destination_ip']}" if facts["destination_ip"] else "",
        f"- 使用者: {facts['username']}" if facts["username"] else "",
        f"- 服務: {facts['target_service']}" if facts["target_service"] else "",
        f"- Rule 描述: {facts['rule_description']}" if facts["rule_description"] else "",
    ])

    return "\n".join([
        f"使用者問題：{question}",
        "",
        "請針對以下這筆資安事件調查。這段事件上下文由 bridge 從 SQLite 的 canonical_signal 與原始告警資料建立；Dashboard 沒有組 LLM prompt。",
        prompt_safety.UNTRUSTED_DATA_INSTRUCTIONS,
        "",
        "目前事件 canonical 控制欄位：",
        f"- Alert ID: {facts['alert_id']}",
        f"- Source: {facts['source_product']} ({facts['source']})",
        f"- Source event ID: {facts['source_event_id']}" if facts["source_event_id"] else "",
        f"- Signal type: {facts['signal_type'] or '-'}",
        f"- Rule ID: {facts['rule_id']}" if facts["rule_id"] else "",
        f"- Native level: {facts['rule_level']}",
        f"- MITRE: {', '.join(str(item) for item in facts['mitre_ids'])}" if facts["mitre_ids"] else "",
        f"- Source-specific context: {', '.join(facts['source_specific_keys'])}" if facts["source_specific_keys"] else "",
        f"- 目前嚴重度: {facts['severity']}" if facts["severity"] else "",
        "",
        "目前事件 canonical 值：",
        prompt_safety.untrusted_data_block(
            "current canonical signal values",
            "\n".join(line for line in current_values.splitlines() if line.strip()) or "- none",
        ),
        "",
        "目前事件內的結構化證據：",
        prompt_safety.untrusted_data_block(
            "current alert structured evidence",
            "\n".join(facts["module_lines"]) if facts["module_lines"] else "- none",
        ),
        "",
        "目前事件原始 full_log：",
        prompt_safety.untrusted_data_block("current alert full_log", facts["full_log"] or "(empty)"),
        "",
        "調查規則：",
        "- MCP 查詢只用來補歷史關聯、規則原文、端點狀態、程序或連接埠；目前事件本身已經存在。",
        "- 如果 MCP 沒查到歷史關聯，不可推論成目前事件不存在，也不可直接說不用處理。",
        "- 目前查證工具以 Wazuh MCP 為主；若 Source 不是 Wazuh，只能說 Wazuh 端未查到額外紀錄，不可推論來源系統也沒有紀錄。",
        "- 不要說你已經封鎖、隔離、停用帳號或修改任何設備。",
        "- Agent IP / 電腦 IP 是被監控主機，不是來源 IP；只有明確的來源 IP 才能當 srcip 查詢。",
        "- 回答請用繁體中文，第一句先給管理者結論：是否需要立刻請 IT 處理。",
    ]).replace("\n\n\n", "\n\n")


def build_fast_playbook_prompt(
    facts: dict[str, Any],
    question: str,
    plan: dict[str, Any],
    model_result: str,
) -> str:
    current_values = "\n".join([
        f"- 發生時間: {facts['event_time'] or '-'}",
        f"- 電腦名稱: {facts['agent_name'] or '-'}",
        f"- Agent ID: {facts['agent_id'] or '-'}",
        f"- Agent IP: {facts['agent_ip'] or '-'}（端點 IP，不是來源 IP）",
        f"- 來源 IP: {facts['source_ip'] or '-'}",
        f"- 目的 IP: {facts['destination_ip'] or '-'}",
        f"- 使用者: {facts['username'] or '-'}",
        f"- 服務: {facts['target_service'] or '-'}",
        f"- Rule 描述: {facts['rule_description'] or '-'}",
    ])
    return "\n".join([
        "你是 EdgeSec-Pi 的 MDR 調查助理。以下是後端 playbook 已經直接完成的一次唯讀 Wazuh MCP 查證結果。",
        "請用繁體中文台灣用語回答，第一句先給管理者結論：是否需要立刻請 IT 處理。",
        prompt_safety.UNTRUSTED_DATA_INSTRUCTIONS,
        "不要輸出 JSON、Markdown 表格、工具名稱、查詢語法或參數名稱。",
        "不要說你已經封鎖、隔離、停用帳號、刪檔、修改防火牆或改設備設定；你現在只能調查與建議。",
        "如果沒有成功登入、惡意程式、rootkit、漏洞利用或未授權變更的明確證據，不要寫成已確認入侵。",
        "如果同一來源 IP 命中多台電腦，可以說需要 IT 優先確認或持續監控；但仍不可直接說已入侵。",
        "如果查詢結果沒有資料，只能說未查到額外 Wazuh 歷史紀錄；不可說目前告警不存在或完全正常。",
        "",
        f"使用者問題：{question}",
        "",
        "目前事件：",
        f"- Alert ID: {facts['alert_id'] or '-'}",
        f"- Source: {facts['source_product']} ({facts['source']})",
        f"- Signal type: {facts['signal_type'] or '-'}",
        f"- Rule ID: {facts['rule_id'] or '-'}",
        f"- Native level: {facts['rule_level'] or '-'}",
        f"- 目前嚴重度: {facts['severity'] or '-'}",
        "- Canonical 值:",
        prompt_safety.untrusted_data_block(
            "current canonical signal values",
            current_values,
            limit=FAST_PLAYBOOK_ALERT_LOG_MAX_CHARS,
        ),
        "- 原始 log:",
        prompt_safety.untrusted_data_block(
            "current alert full_log",
            facts["full_log"],
            limit=FAST_PLAYBOOK_ALERT_LOG_MAX_CHARS,
        ),
        "",
        "已執行的 playbook：",
        f"- 查證類型: {plan['label']}",
        f"- 查證目的: {plan['reason']}",
        "",
        "Wazuh MCP 查證結果：",
        model_result,
        "",
        "請用以下格式回答：",
        "結論：",
        "證據：",
        "下一步：",
    ])
