"""Detection category settings for the management dashboard and LLM routing.

Disabled categories are still ingested and stored, but the bridge skips LLM
analysis for new alerts in that category to reduce local model load.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any


SETTINGS_PATH = Path(__file__).resolve().parent / "data" / "detection_categories.json"

CATEGORIES: list[dict[str, str]] = [
    {
        "key": "authentication",
        "label_zh": "登入 / 帳號",
        "description_zh": "跨 Windows、macOS、Linux 的登入失敗、暴力嘗試、權限與帳號異常。",
        "detail_zh": "對應 Wazuh authentication、sshd、pam、Windows 4624/4625 等登入事件。適合用來發現暴力破解、異常帳號、非上班時間登入、權限濫用與帳號被猜測。",
    },
    {
        "key": "sca",
        "label_zh": "安全設定檢查",
        "description_zh": "CIS/SCA 基準、系統設定、密碼政策、防火牆與自動更新等姿態檢查。",
        "detail_zh": "對應 Wazuh SCA / CIS benchmark。這通常是設定姿態或合規缺口，不一定代表正在被攻擊；重點是把 rationale、remediation、checks 與 compliance 對應翻成 IT 可修復清單。",
    },
    {
        "key": "vulnerability",
        "label_zh": "漏洞偵測",
        "description_zh": "CVE、弱點套件、修補版本與暴露風險。",
        "detail_zh": "對應 Wazuh Vulnerability Detection。系統會依 CVE、CVSS、套件名稱、目前版本與資產重要性排序，適合形成修補優先級工作單。",
    },
    {
        "key": "fim",
        "label_zh": "檔案 / 設定異動",
        "description_zh": "重要檔案、設定檔、登入金鑰、啟動項或網站檔案被新增、修改、刪除。",
        "detail_zh": "對應 Wazuh FIM / syscheck。用來監控 critical files、configuration files、content files，例如帳號檔、sudoers、authorized_keys、啟動項、網站目錄與系統執行檔；若有 whodata，會顯示誰用什麼程序改了什麼。",
    },
    {
        "key": "network",
        "label_zh": "網路服務變動",
        "description_zh": "開放 port、listening service、連線狀態或網路盤點變動；量大時可關閉以降低 LLM 負載。",
        "detail_zh": "對應網路盤點、netstat、listening port 與服務狀態變更。適合找出新開放的管理介面、未知服務、C2 連線跡象或非預期的對外連線。",
    },
    {
        "key": "process",
        "label_zh": "可疑程序 / 指令",
        "description_zh": "PowerShell、shell、未知程序、可疑命令列與執行行為。",
        "detail_zh": "對應命令執行、PowerShell、shell、未知二進位、可疑參數與 MITRE T1059 類行為。適合判斷下載執行、橫向移動、權限提升或腳本濫用。",
    },
    {
        "key": "malware",
        "label_zh": "惡意程式 / 入侵跡象",
        "description_zh": "惡意程式、rootkit、後門、C2、入侵或已知攻擊技術。",
        "detail_zh": "對應 rootcheck、malware、rootkit、後門、C2 與已知攻擊技術。這類事件通常要提高處理層級：先降低擴散風險，再保全證據並交由 IT 深查。",
    },
    {
        "key": "system",
        "label_zh": "Agent / 平台狀態",
        "description_zh": "Wazuh Agent 連線、平台健康、磁碟與作業系統狀態。",
        "detail_zh": "對應 Wazuh agent 連線、平台健康、磁碟、作業系統與監控能力狀態。它不一定是攻擊，但會影響是否能即時看見風險。",
    },
    {
        "key": "compliance",
        "label_zh": "合規 / 稽核",
        "description_zh": "PCI、NIST、ISO 27001、SOC 2、GDPR 等控制要求與稽核對應事件。",
        "detail_zh": "對應稽核控制、政策要求與證據留存，例如 PCI、NIST、ISO 27001、SOC 2、GDPR。重點是管理缺口、補強證據與例外追蹤。",
    },
    {
        "key": "other",
        "label_zh": "其他",
        "description_zh": "尚未對應到上述分頁的 Wazuh 群組或自訂規則，例如一般 syslog/ossec 狀態、整合測試或低優先級錯誤。",
        "detail_zh": "用來承接尚未歸類的 Wazuh 群組、自訂規則、整合測試或低優先級系統事件。後續可依實際事件再拆成新的類別。",
    },
]

DEFAULT_ENABLED = {item["key"]: True for item in CATEGORIES}
CATEGORY_KEYS = set(DEFAULT_ENABLED)
CORE_SIGNAL_KEYS = {"authentication", "vulnerability", "fim", "process", "malware"}
NOISY_KEYS = {"sca", "network", "system", "compliance", "other"}

PRESETS: list[dict[str, Any]] = [
    {
        "key": "conservative",
        "label_zh": "保守",
        "description_zh": "只開高信號類別，適合剛上線或模型效能較弱的環境。",
        "noise_level": "low",
        "enabled": {
            "authentication": True,
            "sca": False,
            "vulnerability": True,
            "fim": True,
            "network": False,
            "process": True,
            "malware": True,
            "system": False,
            "compliance": False,
            "other": False,
        },
    },
    {
        "key": "recommended",
        "label_zh": "建議",
        "description_zh": "平衡偵測覆蓋與告警噪音，保留 SCA 與網路服務變動，但關閉低信號雜項。",
        "noise_level": "medium",
        "enabled": {
            "authentication": True,
            "sca": True,
            "vulnerability": True,
            "fim": True,
            "network": True,
            "process": True,
            "malware": True,
            "system": False,
            "compliance": False,
            "other": False,
        },
    },
    {
        "key": "expanded",
        "label_zh": "強化",
        "description_zh": "所有類別都顯示並送分析，適合已有調校與誤報處理流程的環境。",
        "noise_level": "high",
        "enabled": DEFAULT_ENABLED.copy(),
    },
]
PRESET_BY_KEY = {str(item["key"]): item for item in PRESETS}


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


def _fp_suppression_enabled() -> bool:
    return os.getenv("FP_SUPPRESSION_ENABLED", "1").strip().lower() not in {"0", "false", "no", "off"}


def _coerce_preset_key(value: Any) -> str:
    key = _text(value)
    return key if key in PRESET_BY_KEY else "custom"


def _settings_payload(enabled: dict[str, bool], preset: str = "custom", message: str = "") -> dict[str, Any]:
    active_preset = active_preset_for_enabled(enabled, fallback=preset)
    payload = {
        "categories": CATEGORIES,
        "enabled": enabled,
        "presets": preset_options(),
        "active_preset": active_preset,
        "noise": noise_profile(enabled),
    }
    if message:
        payload["message"] = message
    return payload


def load() -> dict[str, Any]:
    enabled = DEFAULT_ENABLED.copy()
    preset = "custom"
    if SETTINGS_PATH.exists():
        try:
            raw = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
            enabled = _coerce_enabled(raw)
            preset = _coerce_preset_key(raw.get("preset") if isinstance(raw, dict) else "")
        except Exception:
            enabled = DEFAULT_ENABLED.copy()
            preset = "custom"
    return _settings_payload(enabled, preset)


def preset_options() -> list[dict[str, Any]]:
    return [
        {
            "key": item["key"],
            "label_zh": item["label_zh"],
            "description_zh": item["description_zh"],
            "noise_level": item["noise_level"],
            "enabled": item["enabled"].copy(),
        }
        for item in PRESETS
    ]


def preset_enabled(preset_key: str) -> dict[str, bool]:
    preset = PRESET_BY_KEY.get(preset_key)
    if not preset:
        raise ValueError(f"未知的偵測 preset：{preset_key}")
    return _coerce_enabled(preset.get("enabled"))


def active_preset_for_enabled(enabled: dict[str, bool], fallback: str = "custom") -> str:
    current = _coerce_enabled(enabled)
    for item in PRESETS:
        if current == _coerce_enabled(item.get("enabled")):
            return str(item["key"])
    return fallback if fallback in PRESET_BY_KEY else "custom"


def noise_profile(enabled: dict[str, bool]) -> dict[str, Any]:
    current = _coerce_enabled(enabled)
    noisy_enabled = [key for key in current if key in NOISY_KEYS and current[key]]
    core_disabled = [key for key in current if key in CORE_SIGNAL_KEYS and not current[key]]
    warnings: list[str] = []
    if noisy_enabled and not _fp_suppression_enabled():
        warnings.append("已啟用高噪音類別，但 FP suppression 目前關閉，誤報不會自動形成短期抑制規則。")
    if core_disabled:
        warnings.append("部分核心資安訊號被關閉，可能降低入侵、惡意程式或可疑程序的可見度。")
    if len(noisy_enabled) >= 4:
        warnings.append("高噪音類別開啟較多，建議先確認告警量與本機 LLM 延遲。")
    return {
        "noisy_categories": noisy_enabled,
        "core_disabled": core_disabled,
        "false_positive_suppression": _fp_suppression_enabled(),
        "warnings": warnings,
    }


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


def save(enabled: dict[str, Any] | None = None, preset: str = "custom") -> dict[str, Any]:
    preset_key = _coerce_preset_key(preset)
    if preset_key != "custom":
        current = preset_enabled(preset_key)
    else:
        current = _coerce_enabled({"enabled": enabled or {}})
    if not any(current.values()):
        raise ValueError("至少需要啟用一個偵測類別")
    if not any(current.get(key) for key in CORE_SIGNAL_KEYS):
        raise ValueError("至少需要啟用一個核心資安偵測類別")
    active_preset = active_preset_for_enabled(current, fallback=preset_key)
    SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    SETTINGS_PATH.write_text(
        json.dumps({"preset": active_preset, "enabled": current}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    label = next((item["label_zh"] for item in PRESETS if item["key"] == active_preset), "自訂")
    return _settings_payload(current, active_preset, f"偵測類別設定已儲存（{label}）")
