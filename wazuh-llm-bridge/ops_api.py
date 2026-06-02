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
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

import ai_settings
import dashboard_notifications_api
import dashboard_sample_data_api
import dashboard_sources_api
import dashboard_wazuh_settings_api
import db
import detection_settings
import digest
import investigation_chat
import llm_client
import org_profile
import self_test
import technical_evidence
import wazuh
from dashboard_notifications_api import (
    notification_config,
    notification_service_check,
    notifications_payload,
)

router = APIRouter(tags=["ops"])
router.include_router(dashboard_notifications_api.router)
router.include_router(dashboard_sample_data_api.router)
router.include_router(dashboard_sources_api.router)
router.include_router(dashboard_wazuh_settings_api.router)

QUEUE_MAXSIZE = int(os.getenv("QUEUE_MAXSIZE", "1000"))
WORKER_COUNT = int(os.getenv("WORKER_COUNT", "2"))


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


class DetectionSettingsPatch(BaseModel):
    enabled: dict[str, bool] = {}
    preset: Optional[str] = None


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


class InvestigationChatMessage(BaseModel):
    role: str
    content: str


class InvestigationChatRequest(BaseModel):
    messages: list[InvestigationChatMessage]
    alert_id: Optional[int] = None
    question: Optional[str] = None


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
    # 優先用已落地的結構化欄位；舊資料沒有欄位時再回退解析 llm_raw_reply。
    llm_summary = row.get("llm_summary_zh") or raw_llm.get("summary_zh")
    llm_impact = row.get("llm_impact_zh") or raw_llm.get("impact_zh")
    llm_action = row.get("llm_next_step_zh") or raw_llm.get("next_step_zh")
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
        "investigation_summary_zh": str(row.get("llm_investigation_zh") or raw_llm.get("investigation_summary_zh") or ""),
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
    checks.append(notification_service_check())

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

    channels = notifications_payload()["channels"]
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
        messages = [message.dict() for message in payload.messages]
        if payload.alert_id is not None:
            result = await investigation_chat.answer_for_alert(
                payload.alert_id,
                payload.question or "",
                history=messages,
            )
        else:
            result = await investigation_chat.answer(messages)
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
    notifications = notification_config()
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


@router.get("/api/dashboard/false-positive-suppressions")
async def list_dashboard_false_positive_suppressions(
    include_expired: bool = False,
) -> dict[str, Any]:
    """Expose active bridge-level false-positive feedback rules for audit."""
    return {
        "suppressions": await db.list_false_positive_suppressions(
            include_expired=include_expired
        )
    }


@router.delete("/api/dashboard/false-positive-suppressions/{suppression_id}")
async def delete_dashboard_false_positive_suppression(suppression_id: int) -> dict[str, Any]:
    """Disable a bridge-level false-positive feedback rule."""
    disabled = await db.disable_false_positive_suppression(suppression_id)
    if not disabled:
        raise HTTPException(status_code=404, detail="suppression not found")
    return {"ok": True, "id": suppression_id, "enabled": False}


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


@router.get("/api/dashboard/detection-categories")
async def get_dashboard_detection_categories() -> dict[str, Any]:
    return detection_settings.load()


@router.put("/api/dashboard/detection-categories")
async def put_dashboard_detection_categories(payload: DetectionSettingsPatch) -> dict[str, Any]:
    try:
        return detection_settings.save(payload.enabled, preset=payload.preset or "custom")
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


@router.get("/self-test")
async def get_self_test(request: Request) -> dict[str, Any]:
    """Management-facing readiness check."""
    queue = getattr(request.app.state, "queue", None)
    queue_size = queue.qsize() if queue else 0
    queue_max = getattr(queue, "maxsize", 0) or 0
    return await self_test.run_self_test(queue_size=queue_size, queue_max=queue_max)
