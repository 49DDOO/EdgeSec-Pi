"""Operational and read-only API routes for EdgeSec-Pi.

Keep app.py focused on lifecycle and alert processing. Routes here are
supporting surfaces used by health checks, the dashboard, diagnostics, and
admin-triggered notification tests.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
import time
from datetime import datetime, timezone
from typing import Any, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

import admin_auth
import ai_settings
import db
import detection_settings
import digest
import investigation_chat
import llm_client
import notification_settings
import org_profile
import sample_data
import self_test
import siem
import slack_render
import technical_evidence
import wazuh

router = APIRouter(tags=["ops"])

QUEUE_MAXSIZE = int(os.getenv("QUEUE_MAXSIZE", "1000"))
WORKER_COUNT = int(os.getenv("WORKER_COUNT", "2"))
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "").strip() or None


class AlertCasePatch(BaseModel):
    status: str
    note: str = ""


class EndpointBusinessPatch(BaseModel):
    role: str = ""
    owner: str = ""
    criticality: str = ""
    business_hours: str = ""
    pci_scope: bool = False
    notes: str = ""


class NotificationSettingsPatch(BaseModel):
    values: dict[str, Any] = {}


class DetectionSettingsPatch(BaseModel):
    enabled: dict[str, bool] = {}


class AiSettingsPatch(BaseModel):
    enabled: Optional[bool] = None
    provider: Optional[str] = None
    base_url: Optional[str] = None
    model: Optional[str] = None
    api_key: Optional[str] = None
    clear_api_key: bool = False
    timeout_s: Optional[float] = None
    max_concurrent_requests: Optional[int] = None


class AiProviderUseRequest(BaseModel):
    provider: str


class AiModelListRequest(BaseModel):
    provider: str
    base_url: str
    api_key: Optional[str] = None


class SampleReplayRequest(BaseModel):
    category: str = "security"
    limit: int = 3
    min_level: int = 7


class InvestigationChatMessage(BaseModel):
    role: str
    content: str


class InvestigationChatRequest(BaseModel):
    messages: list[InvestigationChatMessage]


def _built_in_test_alert() -> dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    return {
        "timestamp": now,
        "@timestamp": now,
        "@sampledata": True,
        "rule": {
            "id": "edgesec-test-001",
            "level": 10,
            "description": "EdgeSec-Pi built-in notification flow test",
            "groups": ["edgesec", "test"],
        },
        "agent": {
            "id": "edgesec-test",
            "name": "EdgeSec-Pi 測試電腦",
            "ip": "192.0.2.10",
        },
        "data": {
            "srcip": "203.0.113.10",
            "dstuser": "demo-admin",
            "test": True,
        },
        "full_log": (
            "EdgeSec-Pi built-in test alert: simulated repeated login attempt "
            "from 203.0.113.10 to demo-admin on EdgeSec-Pi 測試電腦."
        ),
        "_edgesec": {
            "sampledata": True,
            "built_in_test": True,
            "sample_source": "edgesec_builtin",
            "sample_replayed_at": now,
            "business_context": {
                "role": "通知測試",
                "owner": "管理者",
                "criticality": "medium",
                "business_hours": "24/7",
                "notes": "這是 EdgeSec-Pi 內建測試告警，不代表公司真的被攻擊。",
            },
        },
    }


def _parse_llm_raw(raw: Any) -> dict[str, Any]:
    if not raw:
        return {}
    if isinstance(raw, dict):
        return raw
    try:
        data = json.loads(str(raw))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _normalize_severity(value: Any) -> str:
    severity = str(value or "").strip().lower()
    if severity in {"critical", "high", "medium", "low"}:
        return severity
    if severity in {"info", "informational"}:
        return "low"
    return "medium"


def _has_cjk(text: Any) -> bool:
    return bool(re.search(r"[\u4e00-\u9fff]", str(text or "")))


def _case_to_dashboard_status(value: Any) -> str:
    status = str(value or "").strip().lower()
    return {
        "open": "pending",
        "in_progress": "acknowledged",
        "normal": "resolved",
        "resolved": "resolved",
        "false_positive": "false_positive",
    }.get(status, "pending")


def _dashboard_to_case_status(value: Any) -> str:
    status = str(value or "").strip().lower()
    return {
        "pending": "open",
        "acknowledged": "in_progress",
        "resolved": "resolved",
        "false_positive": "false_positive",
    }.get(status, status)


def _format_agent_os(agent: dict[str, Any]) -> str:
    os_info = agent.get("os") if isinstance(agent.get("os"), dict) else {}
    platform = os_info.get("platform") or agent.get("os_platform") or ""
    version = os_info.get("version") or agent.get("os_version") or ""
    name = os_info.get("name") or ""
    os_names = {
        "darwin": "macOS",
        "macos": "macOS",
        "mac": "macOS",
        "ubuntu": "Ubuntu Linux",
        "debian": "Debian Linux",
        "amzn": "Amazon Linux",
        "amazon": "Amazon Linux",
        "centos": "CentOS Linux",
        "rhel": "Red Hat Enterprise Linux",
        "windows": "Windows",
        "linux": "Linux",
    }
    raw_label = name or platform or ""
    label = os_names.get(str(raw_label).strip().lower(), raw_label) or "unknown"
    return f"{label} {version}".strip()


def _endpoint_status(status: Any) -> str:
    normalized = str(status or "").strip().lower()
    if normalized in {"active", "online"}:
        return "online"
    if normalized in {"disconnected", "offline", "never_connected"}:
        return "offline"
    return "warning"


def _endpoint_connection_score(agent: dict[str, Any]) -> int:
    status = _endpoint_status(agent.get("status"))
    if status == "online":
        return 100
    if status == "warning":
        return 70
    return 35


def _format_endpoint_ip(value: Any) -> tuple[str, str, bool]:
    raw = str(value or "").strip()
    if not raw:
        return "", "", False
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return raw, raw, False
    if ip.is_loopback:
        return "未回報實際 IP", raw, True
    return str(ip), raw, False


def _notification_config() -> dict[str, bool]:
    values = notification_settings.values()
    return {
        "line": bool(values.get("line_channel_token") and values.get("line_user_id")),
        "slack": bool(values.get("slack_webhook") or (
            values.get("slack_bot") and values.get("slack_app") and values.get("slack_channel")
        )),
        "telegram": bool(values.get("telegram_bot_token") and values.get("telegram_chat_id")),
        "email": bool(values.get("smtp_host") and values.get("email_from") and values.get("email_to")),
    }


def _configured_channels(values: dict[str, Any]) -> dict[str, bool]:
    return {
        "line": bool(values.get("line_channel_token") and values.get("line_user_id")),
        "slack": bool(values.get("slack_webhook") or (
            values.get("slack_bot") and values.get("slack_app") and values.get("slack_channel")
        )),
        "telegram": bool(values.get("telegram_bot_token") and values.get("telegram_chat_id")),
        "email": bool(values.get("smtp_host") and values.get("email_from") and values.get("email_to")),
    }


def _notification_channel_status(channel: str, values: dict[str, Any]) -> dict[str, Any]:
    configured = _configured_channels(values).get(channel, False)
    tested_at = str(values.get(f"{channel}_tested_at") or "")
    field_map: dict[str, dict[str, Any]] = {
        "line": {
            "LINE_CHANNEL_ACCESS_TOKEN": {
                "label": "LINE 權杖",
                "secret": True,
                "configured": bool(values.get("line_channel_token")),
            },
            "LINE_USER_ID": {
                "label": "接收 LINE 的人",
                "value": values.get("line_user_id") or "",
            },
        },
        "slack": {
            "SLACK_WEBHOOK_URL": {
                "label": "Webhook URL",
                "secret": True,
                "configured": bool(values.get("slack_webhook")),
            },
            "SLACK_CHANNEL_ID": {
                "label": "Channel ID",
                "value": values.get("slack_channel") or "",
            },
            "SLACK_BOT_TOKEN": {
                "label": "Bot Token",
                "secret": True,
                "configured": bool(values.get("slack_bot")),
            },
            "SLACK_APP_TOKEN": {
                "label": "App Token",
                "secret": True,
                "configured": bool(values.get("slack_app")),
            },
            "BRIDGE_PUBLIC_URL": {
                "label": "公開連結",
                "value": values.get("bridge_public_url") or "",
            },
        },
        "telegram": {
            "TELEGRAM_BOT_TOKEN": {
                "label": "Bot Token",
                "secret": True,
                "configured": bool(values.get("telegram_bot_token")),
            },
            "TELEGRAM_CHAT_ID": {
                "label": "Chat ID",
                "value": values.get("telegram_chat_id") or "",
            },
        },
        "email": {
            "SMTP_HOST": {"label": "SMTP 主機", "value": values.get("smtp_host") or ""},
            "SMTP_PORT": {"label": "SMTP Port", "value": values.get("smtp_port") or "587"},
            "SMTP_USER": {"label": "SMTP 帳號", "value": values.get("smtp_user") or ""},
            "SMTP_PASS": {
                "label": "SMTP 密碼",
                "secret": True,
                "configured": bool(notification_settings.get_value("SMTP_PASS")),
            },
            "EMAIL_FROM": {"label": "寄件者", "value": values.get("email_from") or ""},
            "EMAIL_TO": {"label": "收件者", "value": values.get("email_to") or ""},
            "SMTP_SSL": {"label": "SSL", "value": bool(values.get("smtp_ssl"))},
            "SMTP_STARTTLS": {"label": "STARTTLS", "value": bool(values.get("smtp_starttls"))},
        },
    }
    return {
        "channel": channel,
        "configured": configured,
        "enabled": configured,
        "lastTested": tested_at or None,
        "fields": field_map.get(channel, {}),
    }


def _notifications_payload() -> dict[str, Any]:
    values = notification_settings.values()
    return {
        "channels": {
            channel: _notification_channel_status(channel, values)
            for channel in ("line", "slack", "telegram", "email")
        }
    }


def _notification_service_check() -> dict[str, Any]:
    channels = _notifications_payload()["channels"]
    configured = [
        str(channel.get("channel") or "").upper()
        for channel in channels.values()
        if channel.get("configured")
    ]
    tested = [
        str(channel.get("channel") or "").upper()
        for channel in channels.values()
        if channel.get("lastTested")
    ]
    status = "ok" if tested else "warn" if configured else "fail"
    summary = (
        f"已測通 {', '.join(tested)}。"
        if tested
        else f"已設定 {', '.join(configured)}，但尚未測試成功。"
        if configured
        else "尚未設定任何通知管道。"
    )
    next_step = (
        "至少測通 LINE、Slack、Telegram 或 Email 其中一個，收到告警才不需要一直盯著 Dashboard。"
        if status != "ok"
        else ""
    )
    return {
        "id": "notifications",
        "label_zh": "通知管道",
        "status": status,
        "summary_zh": summary,
        "next_step_zh": next_step,
        "detail_zh": f"configured={len(configured)}/4, tested={len(tested)}/4",
        "owner_zh": "管理者",
        "required": True,
    }


def _clean_notification_form(channel: str, values: dict[str, Any]) -> dict[str, str]:
    allowed = set(notification_settings.CHANNEL_KEYS.get(channel, []))
    form: dict[str, str] = {}
    for key, value in values.items():
        if key not in allowed and key not in {"SMTP_SSL", "SMTP_STARTTLS"}:
            continue
        if key in {"SMTP_SSL", "SMTP_STARTTLS"}:
            if bool(value):
                form[key] = "true"
            continue
        form[key] = str(value or "").strip()
    return form


def _risk_summary(stats: dict[str, Any]) -> dict[str, Any]:
    open_by_severity = stats.get("open_by_severity_24h") or {}
    counts = {
        "critical": int(open_by_severity.get("critical") or 0),
        "high": int(open_by_severity.get("high") or 0),
        "medium": int(open_by_severity.get("medium") or 0),
        "low": int(open_by_severity.get("low") or 0),
    }
    penalty = (
        counts["critical"] * 25
        + counts["high"] * 15
        + counts["medium"] * 8
        + counts["low"] * 3
    )
    score = max(0, 100 - min(penalty, 100))
    level = "normal"
    if counts["critical"]:
        level = "critical"
    elif counts["high"]:
        level = "high"
    elif counts["medium"]:
        level = "medium"
    elif counts["low"]:
        level = "low"
    return {
        "level": level,
        "score": score,
        "critical_count": counts["critical"],
        "high_count": counts["high"],
        "medium_count": counts["medium"],
        "low_count": counts["low"],
        "total_alerts_today": int(stats.get("alerts_last_24h") or 0),
        "pending_actions": int(stats.get("open_cases_24h") or 0),
        "score_basis": {
            "starts_at": 100,
            "deduct": {
                "critical": 25,
                "high": 15,
                "medium": 8,
                "low": 3,
            },
            "deducts_open_alerts_only": True,
        },
    }


def _management_fallback(row: dict[str, Any], raw_alert: dict[str, Any]) -> dict[str, str]:
    data = raw_alert.get("data") if isinstance(raw_alert.get("data"), dict) else {}
    rule_id = str(row.get("rule_id") or "")
    agent = str(row.get("agent_name") or "受監控電腦")
    srcip = str(data.get("srcip") or "").strip()
    user = str(data.get("srcuser") or data.get("dstuser") or "").strip()
    rule_desc = str(row.get("rule_description") or "")

    if rule_id in {"5712", "5763"}:
        target = f"帳號「{user}」" if user else "某個帳號"
        source = f"從 {srcip} " if srcip else ""
        return {
            "summary": f"{agent} 被人{source}多次嘗試登入{target}。",
            "impact": "如果對方猜中密碼，可能進入系統竊取資料、破壞服務或安裝後門。",
            "next_step": "請負責人確認是否為本人操作；若不是，請 IT 封鎖來源並回報處理結果。",
        }
    if rule_id == "533":
        return {
            "summary": f"{agent} 的網路連接狀態有變動，請確認是否為正常工作或開發測試。",
            "impact": "若不是預期操作，可能代表有未授權程式正在開啟連線或對外服務。",
            "next_step": "請該電腦使用者確認當下是否正在安裝、測試或啟動服務；若不是，請 IT 檢查程序。",
        }
    if rule_id == "510":
        return {
            "summary": f"{agent} 出現系統異常偵測，請 IT 確認是否為誤報或真的有可疑程序。",
            "impact": "若是真的異常，可能代表系統有被植入可疑程序或監控工具看不到的連線。",
            "next_step": "請 IT 先比對 Wazuh 原始告警與端點狀態，再決定是否隔離或排除誤報。",
        }
    if "CIS_" in rule_desc:
        return {
            "summary": f"{agent} 有一項安全設定不符合建議基準。",
            "impact": "通常不是立即入侵，但代表這台電腦的防護設定還可以加強。",
            "next_step": "請 IT 依安全基準修正設定，或確認此設定是公司允許的例外。",
        }
    return {
        "summary": f"{agent} 有一筆資安事件需要確認。",
        "impact": "若這不是預期行為，可能代表系統設定異常或有人嘗試未授權存取。",
        "next_step": "請負責人或 IT 查看原始告警，確認是否需要處理。",
    }


def _alert_to_dashboard(row: dict[str, Any]) -> dict[str, Any]:
    raw_llm = _parse_llm_raw(row.get("llm_raw_reply"))
    raw_alert = _parse_llm_raw(row.get("raw_alert"))
    data = raw_alert.get("data") if isinstance(raw_alert.get("data"), dict) else {}
    raw_meta = raw_alert.get("_edgesec") if isinstance(raw_alert.get("_edgesec"), dict) else {}
    is_sampledata = raw_alert.get("@sampledata") is True or bool(raw_meta.get("sampledata"))
    iocs = row.get("llm_iocs") or []
    if isinstance(iocs, str):
        iocs = [iocs]
    fallback = _management_fallback(row, raw_alert)
    llm_summary = raw_llm.get("summary_zh")
    llm_impact = raw_llm.get("impact_zh")
    llm_action = raw_llm.get("next_step_zh")
    summary = llm_summary if _has_cjk(llm_summary) else fallback["summary"]
    impact = llm_impact if _has_cjk(llm_impact) else fallback["impact"]
    action = llm_action if _has_cjk(llm_action) else fallback["next_step"]
    evidence = technical_evidence.build_technical_evidence(
        row=row,
        raw_alert=raw_alert,
        llm=raw_llm,
    )
    raw_agent = raw_alert.get("agent") if isinstance(raw_alert.get("agent"), dict) else {}
    return {
        "id": str(row.get("id")),
        "timestamp": datetime.fromtimestamp(float(row.get("received_at") or time.time()), timezone.utc).isoformat(),
        "rule_id": str(row.get("rule_id") or ""),
        "rule_level": int(row.get("rule_level") or 0),
        "rule_description": str(row.get("rule_description") or summary),
        "siem_source": str(row.get("siem_source") or "wazuh"),
        "agent_id": str(raw_agent.get("id") or evidence.get("endpoint", {}).get("agent_id") or ""),
        "severity": _normalize_severity(row.get("llm_severity")),
        "agent_name": str(row.get("agent_name") or "unknown"),
        "agent_ip": str(row.get("agent_ip") or ""),
        "source_ip": str(data.get("srcip") or ""),
        "summary": str(summary),
        "business_impact": str(impact),
        "recommended_action": str(action),
        "status": _case_to_dashboard_status(row.get("case_status")),
        "purpose": str(raw_llm.get("business_context") or ""),
        "mitre": str(row.get("llm_mitre") or ""),
        "iocs": [str(item) for item in iocs if str(item).strip()],
        "root_cause": str(row.get("llm_root_cause") or raw_llm.get("root_cause") or ""),
        "technical_action": str(row.get("llm_action") or raw_llm.get("action") or ""),
        "full_log": str(row.get("full_log") or ""),
        "sampledata": is_sampledata,
        "technical_evidence": evidence,
    }


async def _dashboard_endpoints() -> tuple[list[dict[str, Any]], str]:
    try:
        agents = await wazuh.list_agents()
    except Exception:
        return [], "disconnected"
    endpoints = []
    for agent in agents:
        name = str(agent.get("name") or "unknown")
        agent_id = str(agent.get("id") or agent.get("name") or "")
        display_ip, raw_ip, loopback_ip = _format_endpoint_ip(agent.get("ip"))
        asset = org_profile.find_asset(name) or {}
        role = str(asset.get("role") or "").strip()
        owner = str(asset.get("owner") or "").strip()
        criticality = str(asset.get("criticality") or "").strip()
        business_hours = str(asset.get("business_hours") or "").strip()
        notes = str(asset.get("notes") or "").strip()
        try:
            sca = await wazuh.get_agent_sca_summary(agent_id)
        except Exception:
            sca = {
                "score": None,
                "policy": "",
                "policy_id": "",
                "passed": 0,
                "failed": 0,
                "invalid": 0,
                "total": 0,
                "last_scan": "",
                "failed_checks": [],
                "plain_failed_checks": [],
                "available": False,
            }
        connection_score = _endpoint_connection_score(agent)
        sca_score = sca.get("score")
        endpoints.append({
            "id": agent_id,
            "name": name,
            "ip": display_ip,
            "raw_ip": raw_ip,
            "ip_is_loopback": loopback_ip,
            "os": _format_agent_os(agent),
            "version": str(agent.get("version") or ""),
            "status": _endpoint_status(agent.get("status")),
            "last_sync": str(agent.get("lastKeepAlive") or datetime.now(timezone.utc).isoformat()),
            "purpose": role or "尚未設定",
            "connection_score": connection_score,
            # Deprecated legacy alias. Keep it tied to SCA, not connectivity,
            # so old consumers do not mistake "online" for "secure".
            "health_score": sca_score,
            "sca_score": sca_score,
            "sca": sca,
            "business_context": {
                "role": role,
                "owner": owner,
                "criticality": criticality,
                "business_hours": business_hours,
                "pci_scope": bool(asset.get("pci_scope")),
                "notes": notes,
                "configured": bool(asset),
            },
        })
    return endpoints, "connected"


@router.get("/health")
async def health(request: Request) -> dict[str, Any]:
    queue: Optional[asyncio.Queue] = getattr(request.app.state, "queue", None)
    return {
        "status": "ok",
        "queue_size": queue.qsize() if queue else 0,
        "queue_max": QUEUE_MAXSIZE,
        "workers": WORKER_COUNT,
    }


@router.get("/alerts")
async def get_alerts(
    limit: int = 50,
    severity: Optional[str] = None,
    rule_id: Optional[str] = None,
    include_sampledata: bool = False,
) -> list[dict[str, Any]]:
    """Recent alerts, newest first."""
    limit = max(1, min(int(limit), 500))
    return await db.list_alerts(
        limit=limit,
        severity=severity,
        rule_id=rule_id,
        include_sampledata=include_sampledata,
    )


@router.get("/stats")
async def get_stats() -> dict[str, Any]:
    """Aggregate counts: total, last 24h, by severity, top rules, avg latency."""
    return await db.compute_stats()


@router.get("/status")
async def get_status() -> dict[str, Any]:
    """On-demand JSON form of the daily freshness digest."""
    return await digest.collect_status()


@router.get("/api/dashboard/service-status")
async def get_dashboard_service_status(request: Request) -> dict[str, Any]:
    """Service status contract for the Next.js dashboard.

    This is intentionally poll-friendly. The dashboard does not need a
    WebSocket here: these checks change on the scale of seconds to minutes, and
    polling keeps the local install path easier to debug.
    """
    queue: Optional[asyncio.Queue] = getattr(request.app.state, "queue", None)
    queue_size = queue.qsize() if queue else 0
    self_status = await self_test.run_self_test(
        queue_size=queue_size,
        queue_max=QUEUE_MAXSIZE,
    )
    checks = list(self_status.get("checks") or [])
    checks.append(_notification_service_check())

    required_fail = [c for c in checks if c.get("required") and c.get("status") == "fail"]
    warnings = [c for c in checks if c.get("status") == "warn"]
    if required_fail:
        overall = {
            "overall": "fail",
            "title_zh": "系統需要處理",
            "message_zh": "有必要服務未完成或未回應，告警可能無法完整送達或分析。",
            "next_step_zh": "先處理紅色項目，處理完再重新整理狀態。",
        }
    elif warnings:
        overall = {
            "overall": "warn",
            "title_zh": "可以使用，但需要確認",
            "message_zh": "核心服務可用，但有部分設定或資料狀態需要補齊。",
            "next_step_zh": "請依黃色項目的說明逐一確認。",
        }
    else:
        overall = {
            "overall": "ok",
            "title_zh": "系統可以正常使用",
            "message_zh": "告警接收、AI 分析與通知狀態目前正常。",
            "next_step_zh": "維持監控即可。",
        }

    channels = _notifications_payload()["channels"]
    return {
        **overall,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "refresh_interval_s": 15,
        "services": checks,
        "metrics": {
            "queue_size": queue_size,
            "queue_max": QUEUE_MAXSIZE,
            "workers": WORKER_COUNT,
            "notifications_configured": sum(1 for c in channels.values() if c.get("configured")),
            "notifications_tested": sum(1 for c in channels.values() if c.get("lastTested")),
        },
    }


@router.post("/api/dashboard/investigation/chat")
async def investigation_chat_reply(payload: InvestigationChatRequest) -> dict[str, Any]:
    try:
        result = await investigation_chat.answer(
            [message.dict() for message in payload.messages]
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except httpx.HTTPStatusError as exc:
        detail = f"AI 或 MCP 服務回應錯誤：HTTP {exc.response.status_code}"
        raise HTTPException(status_code=502, detail=detail) from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"AI 或 MCP 服務連線失敗：{exc}") from exc
    except TimeoutError as exc:
        raise HTTPException(status_code=504, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"調查對話失敗：{exc}") from exc
    return result


@router.get("/api/dashboard/summary")
async def get_dashboard_summary(request: Request) -> dict[str, Any]:
    """Single JSON contract for the new management Dashboard.

    The dashboard should not recalculate risk from mock data. This endpoint
    bundles the already-known bridge state and Wazuh inventory into one stable
    shape for the Next.js UI.
    """
    stats, status, alerts, alert_trends = await asyncio.gather(
        db.compute_stats(),
        digest.collect_status(),
        db.list_alerts(limit=80, include_sampledata=False),
        db.alert_trends(days=7, include_sampledata=False),
    )
    queue: Optional[asyncio.Queue] = getattr(request.app.state, "queue", None)
    endpoints, wazuh_connection = await _dashboard_endpoints()
    notifications = _notification_config()
    cve = status.get("cve_feed") or {}

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "alerts": [_alert_to_dashboard(row) for row in alerts],
        "riskSummary": _risk_summary(stats),
        "endpoints": endpoints,
        "systemHealth": {
            "notification_service": "healthy" if any(notifications.values()) else "degraded",
            "analysis_queue": queue.qsize() if queue else 0,
            "cve_database_updated": cve.get("last_update") or datetime.now(timezone.utc).isoformat(),
            "wazuh_connection": wazuh_connection,
            "llm_service": "degraded" if int(stats.get("errors_last_24h") or 0) else "healthy",
        },
        "notifications": notifications,
        "detectionCategories": detection_settings.load(),
        "install": {
            "manager_host": os.getenv("MANAGER_HOST", "").strip() or "localhost",
            "bridge_public_url": os.getenv("BRIDGE_PUBLIC_URL", "").strip(),
            "wazuh_agent_version": os.getenv("WAZUH_AGENT_VERSION", "4.14.5"),
        },
        "alertTrends": alert_trends,
    }


@router.patch("/api/dashboard/alerts/{alert_id}/case")
async def patch_dashboard_alert_case(alert_id: int, payload: AlertCasePatch) -> dict[str, Any]:
    """Update alert case state from the new Dashboard."""
    status = _dashboard_to_case_status(payload.status)
    note = payload.note.strip()
    try:
        updated = await db.update_alert_case(alert_id, status, note, actor="dashboard-v2")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not updated:
        raise HTTPException(status_code=404, detail="alert not found")
    return {"ok": True, "id": alert_id, "status": _case_to_dashboard_status(status)}


@router.get("/api/dashboard/endpoints")
async def get_dashboard_endpoints() -> dict[str, Any]:
    endpoints, status = await _dashboard_endpoints()
    return {"status": status, "endpoints": endpoints}


@router.post("/api/dashboard/endpoints/{agent_id}/recheck")
async def post_endpoint_recheck(agent_id: str) -> dict[str, Any]:
    """Request a fresh Wazuh agent check for one endpoint.

    This intentionally uses a management-friendly API name. The Wazuh operation
    underneath is an agent restart, which causes configuration reload and a new
    SCA run when the agent policy has scan_on_start enabled. It does not promise
    that old logs are replayed.
    """
    agent_id = agent_id.strip()
    if not agent_id:
        raise HTTPException(status_code=400, detail="missing agent id")
    if agent_id == "000":
        raise HTTPException(status_code=400, detail="manager itself cannot be rechecked this way")

    before: dict[str, Any] = {}
    try:
        before = await wazuh.get_agent_sca_summary(agent_id)
    except Exception as exc:
        before = {"score": None, "last_scan": "", "available": False, "error": str(exc)}

    try:
        wazuh_response = await wazuh.restart_agent(agent_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except httpx.HTTPStatusError as exc:
        detail = str(exc)
        try:
            body = exc.response.json()
            detail = str(body.get("detail") or body.get("message") or body)
        except Exception:
            pass
        raise HTTPException(status_code=502, detail=f"Wazuh 重新檢查請求失敗：{detail}")
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Wazuh 重新檢查請求失敗：{exc}")

    return {
        "ok": True,
        "agent_id": agent_id,
        "status": "requested",
        "previous_score": before.get("score"),
        "previous_last_scan": before.get("last_scan") or "",
        "message": "已要求 Wazuh 重新檢查這台電腦；分數通常需要 1 到 5 分鐘才會更新。",
        "wazuh_response": wazuh_response,
    }


@router.put("/api/dashboard/endpoints/{agent_name}/business-context")
async def put_endpoint_business_context(
    agent_name: str,
    payload: EndpointBusinessPatch,
) -> dict[str, Any]:
    fields = {
        "role": payload.role.strip(),
        "owner": payload.owner.strip(),
        "criticality": payload.criticality.strip(),
        "business_hours": payload.business_hours.strip(),
        "pci_scope": payload.pci_scope,
        "notes": payload.notes.strip(),
    }
    try:
        asset = org_profile.upsert_asset(agent_name, fields)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"ok": True, "agent": agent_name, "asset": asset}


@router.get("/api/dashboard/notifications")
async def get_dashboard_notifications() -> dict[str, Any]:
    return _notifications_payload()


@router.get("/api/dashboard/detection-categories")
async def get_dashboard_detection_categories() -> dict[str, Any]:
    return detection_settings.load()


@router.put("/api/dashboard/detection-categories")
async def put_dashboard_detection_categories(payload: DetectionSettingsPatch) -> dict[str, Any]:
    try:
        return detection_settings.save(payload.enabled)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/api/dashboard/ai-settings")
async def get_dashboard_ai_settings() -> dict[str, Any]:
    return ai_settings.load()


@router.put("/api/dashboard/ai-settings")
async def put_dashboard_ai_settings(payload: AiSettingsPatch) -> dict[str, Any]:
    values = payload.dict(exclude_none=True)
    try:
        return ai_settings.save(values)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/api/dashboard/ai-settings/use")
async def post_dashboard_ai_settings_use(payload: AiProviderUseRequest) -> dict[str, Any]:
    try:
        return ai_settings.use_provider(payload.provider)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/api/dashboard/ai-settings/test")
async def post_dashboard_ai_settings_test() -> dict[str, Any]:
    try:
        async with httpx.AsyncClient() as client:
            result = await llm_client.test_connection(client)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"AI 模型連線測試失敗：{exc}")
    result["message"] = "AI 模型連線測試成功"
    return result


@router.post("/api/dashboard/ai-settings/models")
async def post_dashboard_ai_settings_models(payload: AiModelListRequest) -> dict[str, Any]:
    try:
        current = ai_settings.load(include_secret=True)
        provider_config = next(
            (item for item in current.get("providers", []) if item.get("key") == payload.provider),
            {},
        )
        api_key = str(payload.api_key or provider_config.get("api_key") or "")
        async with httpx.AsyncClient() as client:
            models = await llm_client.list_models(client, payload.base_url, api_key=api_key)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"讀取模型清單失敗：{exc}")
    return {"models": models, "message": f"找到 {len(models)} 個模型"}


@router.put("/api/dashboard/notifications/{channel}")
async def put_dashboard_notification_settings(
    channel: str,
    payload: NotificationSettingsPatch,
) -> dict[str, Any]:
    channel = channel.strip().lower()
    if channel not in notification_settings.CHANNEL_KEYS:
        raise HTTPException(status_code=404, detail="unknown notification channel")
    message = notification_settings.save(_clean_notification_form(channel, payload.values), channel)
    if "尚未儲存" in message:
        raise HTTPException(status_code=400, detail=message)
    result = _notifications_payload()
    result["message"] = message
    return result


@router.post("/api/dashboard/notifications/{channel}/test")
async def post_dashboard_notification_test(channel: str) -> dict[str, Any]:
    channel = channel.strip().lower()
    if channel not in notification_settings.CHANNEL_KEYS:
        raise HTTPException(status_code=404, detail="unknown notification channel")
    try:
        message = await notification_settings.test_channel(channel)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    result = _notifications_payload()
    result["message"] = message
    return result


@router.get("/api/dashboard/sample-data/status")
async def get_dashboard_sample_data_status(category: str = "security") -> dict[str, Any]:
    """Tell the Dashboard whether Wazuh Sample Data is loaded.

    This checks Wazuh Indexer only for documents carrying `@sampledata: true`.
    A missing sample index is not an application failure; it means the user has
    not clicked Wazuh Dashboard's "Add data" button yet.
    """
    try:
        return await sample_data.sample_status(category=category)
    except sample_data.SampleDataError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Wazuh Indexer sample data query failed: {exc}")


@router.post("/api/dashboard/sample-data/replay")
async def post_dashboard_sample_data_replay(
    request: Request,
    payload: SampleReplayRequest,
) -> dict[str, Any]:
    """Queue a small batch of Wazuh Sample Data through the real pipeline."""
    queue: Optional[asyncio.Queue] = getattr(request.app.state, "queue", None)
    if queue is None:
        raise HTTPException(status_code=503, detail="queue not initialized")

    try:
        alerts = await sample_data.load_sample_alerts(
            category=payload.category,
            limit=payload.limit,
            min_level=payload.min_level,
        )
    except sample_data.SampleDataError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Wazuh Indexer sample data query failed: {exc}")

    if not alerts:
        raise HTTPException(
            status_code=404,
            detail="No Wazuh sample alerts found. Add Sample Data in Wazuh Dashboard first.",
        )

    queued = 0
    for alert in alerts:
        if alert.get("@sampledata") is not True:
            continue
        try:
            normalized = siem.normalize_alert(alert, source_hint="wazuh")
            queue.put_nowait(normalized)
            queued += 1
        except asyncio.QueueFull:
            raise HTTPException(status_code=503, detail=f"queue full after queuing {queued} sample alerts")

    return {
        "queued": queued,
        "queue_size": queue.qsize(),
        "sampledata": True,
        "category": payload.category,
        "message": f"已送出 {queued} 筆 Wazuh 測試告警；通知內容會標示為測試資料。",
    }


@router.post("/api/dashboard/test-alert/replay")
async def post_dashboard_builtin_test_alert(request: Request) -> dict[str, Any]:
    """Queue one built-in test alert without requiring Wazuh Sample Data."""
    queue: Optional[asyncio.Queue] = getattr(request.app.state, "queue", None)
    if queue is None:
        raise HTTPException(status_code=503, detail="queue not initialized")

    try:
        normalized = siem.normalize_alert(_built_in_test_alert(), source_hint="wazuh")
        queue.put_nowait(normalized)
    except asyncio.QueueFull:
        raise HTTPException(status_code=503, detail="queue full")

    return {
        "queued": 1,
        "queue_size": queue.qsize(),
        "sampledata": True,
        "category": "edgesec_builtin",
        "message": "已送出 1 筆 EdgeSec-Pi 內建測試告警；通知內容會標示為測試資料。",
    }


@router.get("/self-test")
async def get_self_test(request: Request) -> dict[str, Any]:
    """Management-facing readiness check."""
    queue = getattr(request.app.state, "queue", None)
    queue_size = queue.qsize() if queue else 0
    queue_max = getattr(queue, "maxsize", 0) or 0
    return await self_test.run_self_test(queue_size=queue_size, queue_max=queue_max)


@router.post("/test-slack")
async def test_slack(_: str = Depends(admin_auth.check_admin)) -> dict[str, Any]:
    """Send a canned Slack alert. Admin-only because it pushes notifications."""
    if not SLACK_WEBHOOK_URL:
        raise HTTPException(
            status_code=400,
            detail="SLACK_WEBHOOK_URL is not set in env. Restart the bridge with it set.",
        )
    fake_alert = {
        "rule": {
            "id": "5712",
            "level": 10,
            "description": "sshd: brute force trying to get access to the system. Non existent user.",
        },
        "agent": {"id": "001", "name": "wazuh-agent-01", "ip": "172.18.0.5"},
        "full_log": (
            "May 10 17:05:00 wazuh-agent-01 sshd[1234]: Failed password for invalid "
            "user admin from 192.0.2.111 port 55501 ssh2"
        ),
    }
    fake_parsed = {
        "severity": "high",
        "summary_zh": "有人從外部 IP（192.0.2.111）不斷用「admin」這個帳號嘗試登入你的伺服器，已連續失敗 8 次以上。",
        "impact_zh": "若對方繼續猜下去成功登入，可能會進入系統竊取或破壞資料、安裝後門程式。",
        "next_step_zh": "請聯絡 IT 把 192.0.2.111 這個 IP 暫時封鎖，並確認沒有任何人不小心成功登入。",
        "root_cause": "SSH brute-force from external IP targeting non-existent user 'admin'.",
        "iocs": ["192.0.2.111", "admin"],
        "action": (
            "Block 192.0.2.111 at the firewall; verify no successful auths "
            "from that IP in the last 24h; consider disabling SSH password auth in favour of keys."
        ),
        "mitre": "T1110",
    }
    async with httpx.AsyncClient() as client:
        await slack_render.send_to_slack(fake_alert, fake_parsed, client)
    return {"sent": True, "webhook": SLACK_WEBHOOK_URL[:40] + "..."}


@router.post("/test-digest")
async def test_digest(_: str = Depends(admin_auth.check_admin)) -> dict[str, Any]:
    """Send the freshness digest immediately. Admin-only notification action."""
    return await digest.send_digest(SLACK_WEBHOOK_URL)
