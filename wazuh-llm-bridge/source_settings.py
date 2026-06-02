"""Event-source registry for Dashboard-facing multi-source readiness.

This module is intentionally a registry, not an ingestion framework. A source
is an upstream system that sends security events into EdgeSec-Pi. Wazuh Alert
remains the active event source today; Wazuh MCP/API and Active Response are
source capabilities used for evidence lookup and controlled remediation.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import wazuh_settings

CANONICAL_SCHEMA_VERSION = "1"
PRIMARY_SOURCE = "wazuh"


FUTURE_SOURCES: tuple[dict[str, Any], ...] = (
    {
        "key": "google_workspace",
        "label_zh": "Google Workspace",
        "product_zh": "Google Workspace",
        "category_zh": "雲端身分與協作",
        "agent_roles": ["security_source", "evidence_provider"],
        "summary_zh": "預留給登入、帳號異常與雲端協作事件。",
        "next_step_zh": "等來源 adapter、憑證保存與測試流程完成後再啟用。",
        "capabilities": [
            {"key": "identity_events", "label_zh": "身分事件", "state": "planned"},
            {"key": "evidence_lookup", "label_zh": "證據查詢", "state": "planned"},
        ],
    },
    {
        "key": "microsoft_365",
        "label_zh": "Microsoft 365",
        "product_zh": "Microsoft 365",
        "category_zh": "雲端身分與郵件",
        "agent_roles": ["security_source", "evidence_provider"],
        "summary_zh": "預留給登入、郵件與 Defender 類事件。",
        "next_step_zh": "等來源 adapter、憑證保存與測試流程完成後再啟用。",
        "capabilities": [
            {"key": "identity_events", "label_zh": "身分事件", "state": "planned"},
            {"key": "mail_events", "label_zh": "郵件事件", "state": "planned"},
        ],
    },
    {
        "key": "firewall",
        "label_zh": "Firewall / Edge",
        "product_zh": "防火牆或邊界設備",
        "category_zh": "網路邊界",
        "agent_roles": ["security_source", "evidence_provider", "response_provider"],
        "summary_zh": "預留給連線、阻擋、VPN 與出口流量事件。",
        "next_step_zh": "等 syslog/API adapter 與事件正規化完成後再啟用。",
        "capabilities": [
            {"key": "network_events", "label_zh": "網路事件", "state": "planned"},
            {"key": "block_ip", "label_zh": "封鎖 IP", "state": "planned"},
        ],
    },
    {
        "key": "edr",
        "label_zh": "EDR",
        "product_zh": "端點防護平台",
        "category_zh": "端點事件",
        "agent_roles": ["security_source", "evidence_provider", "response_provider"],
        "summary_zh": "預留給程序、檔案、惡意程式與主機隔離事件。",
        "next_step_zh": "等來源 adapter 與處置能力邊界完成後再啟用。",
        "capabilities": [
            {"key": "endpoint_events", "label_zh": "端點事件", "state": "planned"},
            {"key": "isolate_asset", "label_zh": "隔離端點", "state": "planned"},
        ],
    },
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _wazuh_source() -> dict[str, Any]:
    settings = wazuh_settings.values()
    deployment_mode = str(settings.get("WAZUH_DEPLOYMENT_MODE") or "existing")
    deployment_label = str(settings.get("WAZUH_DEPLOYMENT_LABEL_ZH") or "連接現有 Wazuh")
    manager_configured = bool(settings.get("WAZUH_API_PASS_configured"))
    indexer_configured = bool(settings.get("WAZUH_INDEXER_PASS_configured"))
    webhook_secret_configured = bool(settings.get("WEBHOOK_SECRET_configured"))
    configured = manager_configured and indexer_configured
    status = "active" if configured else "needs_setup"

    missing: list[str] = []
    if not manager_configured:
        missing.append("Manager 密碼")
    if not indexer_configured:
        missing.append("Indexer 密碼")

    if deployment_mode == "managed" and not configured:
        summary = "已選擇 EdgeSec 代管 Wazuh；此模式未來由平台開通，不要求老闆手動輸入 Wazuh 帳密。"
        next_step = "目前尚未接代管開通流程；若要立即測試，請改用「連接現有 Wazuh」或「本機快速體驗」。"
    elif configured:
        summary = "第一個已接上的事件來源；Wazuh Alert 送進事件，Wazuh MCP/API 補證據，Active Response 提供受控處置。"
        next_step = "維持端點部署、agent-groups 與 Wazuh Alert 事件流檢查；更深處理仍回到 Wazuh。"
    else:
        summary = f"Wazuh Alert 是第一個先鋒事件來源，目前使用方式為「{deployment_label}」，但連線設定尚未完成。"
        next_step = f"請先補齊 {', '.join(missing)}。"

    return {
        "key": "wazuh",
        "label_zh": "Wazuh",
        "product_zh": "Wazuh Manager / Indexer",
        "category_zh": "SIEM 與端點偵測",
        "deployment_mode": deployment_mode,
        "deployment_label_zh": deployment_label,
        "agent_roles": ["security_source", "evidence_provider", "response_provider"],
        "status": status,
        "enabled": configured,
        "configured": configured,
        "primary": True,
        "can_configure": True,
        "settings_href": "/settings/sources/wazuh/settings",
        "setup_href": "/settings/setup?source=wazuh",
        "test_supported": True,
        "summary_zh": summary,
        "next_step_zh": next_step,
        "evidence_zh": [
            f"使用方式：{deployment_label}",
            "Webhook 接收安全事件",
            "MCP 查 Wazuh 證據",
            "Active Response 透過 Wazuh Manager 派送",
            f"Webhook Secret：{'已設定' if webhook_secret_configured else '未設定'}",
        ],
        "capabilities": [
            {"key": "alert_ingest", "label_zh": "事件接收", "state": "ready"},
            {"key": "asset_inventory", "label_zh": "資產狀態", "state": "ready"},
            {"key": "evidence_lookup", "label_zh": "證據查詢", "state": "ready"},
            {"key": "active_response", "label_zh": "隔離/封鎖", "state": "ready"},
        ],
    }


def _planned_source(definition: dict[str, Any]) -> dict[str, Any]:
    return {
        **definition,
        "status": "planned",
        "enabled": False,
        "configured": False,
        "primary": False,
        "can_configure": False,
        "settings_href": "",
        "setup_href": "",
        "test_supported": False,
        "evidence_zh": ["canonical_signal 合約已預留", "尚未接實際來源 adapter"],
    }


def list_sources() -> dict[str, Any]:
    sources = [_wazuh_source(), *(_planned_source(item) for item in FUTURE_SOURCES)]
    active = sum(1 for item in sources if item.get("status") == "active")
    planned = sum(1 for item in sources if item.get("status") == "planned")
    response_ready = sum(
        1 for item in sources
        if item.get("status") == "active" and "response_provider" in item.get("agent_roles", [])
    )
    return {
        "generated_at": _now(),
        "canonical_schema_version": CANONICAL_SCHEMA_VERSION,
        "primary_source": PRIMARY_SOURCE,
        "response_providers_ready": response_ready,
        "sources": sources,
        "message_zh": f"目前 {active} 個已接事件來源、{response_ready} 個來源具備受控處置能力、{planned} 個預留來源。Dashboard 是 Agent 建議與決策介面；Wazuh Alert 是搶攻中小企業市場的第一個事件來源。",
    }


def get_source(source_key: str) -> dict[str, Any]:
    key = source_key.strip().lower()
    for source in list_sources()["sources"]:
        if source.get("key") == key:
            return source
    raise ValueError(f"unknown source: {source_key}")


def test_source(source_key: str) -> dict[str, Any]:
    source = get_source(source_key)
    if source["key"] != "wazuh":
        return {
            "ok": False,
            "source": source["key"],
            "status": source["status"],
            "message_zh": "此來源尚未實作連線測試。",
            "next_step_zh": source["next_step_zh"],
        }

    if source["configured"]:
        return {
            "ok": True,
            "source": "wazuh",
            "status": "configured",
            "message_zh": "Wazuh 來源設定已具備；實際 Manager/Indexer 連線請在 Wazuh 詳細設定頁測試。",
            "next_step_zh": "若要驗證事件流，請到流程測試送測試事件。",
        }
    return {
        "ok": False,
        "source": "wazuh",
        "status": "needs_setup",
        "message_zh": "Wazuh 來源尚未完成必要設定。",
        "next_step_zh": source["next_step_zh"],
    }
