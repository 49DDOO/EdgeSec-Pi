"""Detection category settings for the management dashboard and LLM routing.

Disabled categories are still ingested and stored, but the bridge skips LLM
analysis for new alerts in that category to reduce local model load.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


SETTINGS_PATH = Path(__file__).resolve().parent / "data" / "detection_categories.json"

CATEGORIES: list[dict[str, str]] = [
    {
        "key": "authentication",
        "label_zh": "登入 / 帳號",
        "description_zh": "跨 Windows、macOS、Linux 的登入失敗、暴力嘗試、權限與帳號異常。",
    },
    {
        "key": "sca",
        "label_zh": "安全設定檢查",
        "description_zh": "CIS/SCA 基準、系統設定、密碼政策、防火牆與自動更新等姿態檢查。",
    },
    {
        "key": "vulnerability",
        "label_zh": "漏洞偵測",
        "description_zh": "CVE、弱點套件、修補版本與暴露風險。",
    },
    {
        "key": "fim",
        "label_zh": "檔案 / 設定異動",
        "description_zh": "重要檔案、設定檔、登錄檔或權限異動。",
    },
    {
        "key": "network",
        "label_zh": "網路服務變動",
        "description_zh": "開放 port、listening service、連線狀態或網路盤點變動；量大時可關閉以降低 LLM 負載。",
    },
    {
        "key": "process",
        "label_zh": "可疑程序 / 指令",
        "description_zh": "PowerShell、shell、未知程序、可疑命令列與執行行為。",
    },
    {
        "key": "malware",
        "label_zh": "惡意程式 / 入侵跡象",
        "description_zh": "惡意程式、rootkit、後門、C2、入侵或已知攻擊技術。",
    },
    {
        "key": "system",
        "label_zh": "Agent / 平台狀態",
        "description_zh": "Wazuh Agent 連線、平台健康、磁碟與作業系統狀態。",
    },
    {
        "key": "compliance",
        "label_zh": "合規 / 稽核",
        "description_zh": "PCI、NIST、ISO 27001、SOC 2、GDPR 等控制要求與稽核對應事件。",
    },
    {
        "key": "other",
        "label_zh": "其他",
        "description_zh": "尚未對應到上述分頁的 Wazuh 群組或自訂規則，例如一般 syslog/ossec 狀態、整合測試或低優先級錯誤。",
    },
]

DEFAULT_ENABLED = {item["key"]: True for item in CATEGORIES}
CATEGORY_KEYS = set(DEFAULT_ENABLED)


def _text(value: Any) -> str:
    return str(value or "").strip()


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value in (None, ""):
        return []
    return [value]


def _coerce_enabled(raw: Any) -> dict[str, bool]:
    values = DEFAULT_ENABLED.copy()
    if isinstance(raw, dict):
        source = raw.get("enabled", raw)
        if isinstance(source, dict):
            for key in values:
                if key in source:
                    values[key] = bool(source[key])
    return values


def load() -> dict[str, Any]:
    enabled = DEFAULT_ENABLED.copy()
    if SETTINGS_PATH.exists():
        try:
            enabled = _coerce_enabled(json.loads(SETTINGS_PATH.read_text(encoding="utf-8")))
        except Exception:
            enabled = DEFAULT_ENABLED.copy()
    return {"categories": CATEGORIES, "enabled": enabled}


def category_for_alert(alert: dict[str, Any]) -> str:
    data = _dict(alert.get("data"))
    rule = _dict(alert.get("rule"))
    groups = {str(item).lower() for item in _list(rule.get("groups"))}
    description = _text(rule.get("description")).lower()
    full_log = _text(alert.get("full_log")).lower()
    text = " ".join([description, full_log, " ".join(groups)])

    if _dict(data.get("sca")) or "sca" in groups or "cis" in description:
        return "sca"
    if _dict(data.get("vulnerability")) or "vulnerability" in groups or "cve-" in full_log:
        return "vulnerability"
    if _dict(data.get("syscheck")) or {"syscheck", "fim"} & groups:
        return "fim"
    if "rootcheck" in groups or "rootkit" in description:
        return "malware"
    if "windows" in groups and re.search(r"4624|4625|logon|登入|authentication", text):
        return "authentication"
    if any(key in groups for key in ("authentication_failed", "authentication_success", "sshd", "pam")):
        return "authentication"
    if re.search(r"\b(sshd|failed password|invalid user|authentication failure|sudo)\b", full_log):
        return "authentication"
    if re.search(r"powershell|script|command|process|exec|程序|指令|t1059", text):
        return "process"
    if re.search(r"malware|trojan|backdoor|c2|intrusion|attack|惡意|入侵|後門", text):
        return "malware"
    if re.search(r"netstat|listening|opened ports?|port status|network|網路連接|連接埠", text):
        return "network"
    if re.search(r"pci|nist|iso ?27001|iso ?27002|soc ?2|gdpr|hipaa|compliance|稽核|合規", text):
        return "compliance"
    if re.search(r"agent|ossec|disk|filesystem|system|disconnect|keepalive|系統|磁碟", text):
        return "system"
    return "other"


def is_enabled_for_alert(alert: dict[str, Any]) -> tuple[bool, str]:
    category = category_for_alert(alert)
    settings = load()
    enabled = settings.get("enabled") if isinstance(settings.get("enabled"), dict) else {}
    return bool(enabled.get(category, True)), category


def label_for_category(key: str) -> str:
    return next((item["label_zh"] for item in CATEGORIES if item["key"] == key), key)


def lightweight_verdict(alert: dict[str, Any], category: str) -> dict[str, Any]:
    rule = _dict(alert.get("rule"))
    agent = _dict(alert.get("agent"))
    data = _dict(alert.get("data"))
    agent_name = _text(agent.get("name")) or "受監控電腦"
    rule_desc = _text(rule.get("description")) or "Wazuh 告警"
    category_label = label_for_category(category)
    result = _text(_dict(data.get("sca")).get("check", {}))
    if category == "sca":
        check = _dict(_dict(data.get("sca")).get("check"))
        title = _text(check.get("title")) or rule_desc
        summary = f"{agent_name} 有一項安全設定檢查未通過：{title}"
        impact = "此類別目前未送 LLM 深度解析；事件已保留，可由 IT 依原始檢查內容判斷是否需要修正。"
        action = "請 IT 查看安全設定檢查證據與原始 Log；需要完整解讀時，先重新啟用此類別再分析新事件。"
    elif category == "network":
        summary = f"{agent_name} 有一筆網路服務或連線狀態變動。"
        impact = "此類別目前未送 LLM 深度解析，避免大量 netstat 或連線變動消耗本機模型資源。"
        action = "若不是預期的安裝、測試或服務啟動，請 IT 直接檢查原始 Log 中的 port 與程序。"
    else:
        summary = f"{agent_name} 有一筆「{category_label}」事件：{rule_desc}"
        impact = "此類別目前未送 LLM 深度解析；事件仍已入庫供稽核與追溯。"
        action = "請 IT 依 Wazuh 規則、技術證據與原始 Log 判斷是否需要處理。"
    return {
        "severity": "info",
        "summary_zh": summary,
        "impact_zh": impact,
        "next_step_zh": action,
        "root_cause": f"LLM analysis skipped because detection category '{category}' is disabled.",
        "iocs": [],
        "action": action,
        "mitre": None,
        "needs_investigation": False,
        "investigation_reason": "",
        "llm_skipped": True,
        "detection_category": category,
        "detection_category_zh": category_label,
        "raw_result": result,
    }


def save(enabled: dict[str, Any]) -> dict[str, Any]:
    current = _coerce_enabled({"enabled": enabled})
    if not any(current.values()):
        raise ValueError("至少需要啟用一個偵測類別")
    SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    SETTINGS_PATH.write_text(
        json.dumps({"enabled": current}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return {"categories": CATEGORIES, "enabled": current, "message": "偵測類別設定已儲存"}
