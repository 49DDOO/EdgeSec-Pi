"""Dashboard notification settings and delivery-test routes."""
from __future__ import annotations

from typing import Any

import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

import digest
import notification_settings
import slack_render

router = APIRouter(tags=["dashboard-notifications"])


class NotificationSettingsPatch(BaseModel):
    values: dict[str, Any] = {}


def configured_channels(values: dict[str, Any]) -> dict[str, bool]:
    return {
        "line": bool(values.get("line_channel_token") and values.get("line_user_id")),
        "slack": bool(values.get("slack_webhook") or (
            values.get("slack_bot") and values.get("slack_app") and values.get("slack_channel")
        )),
        "telegram": bool(values.get("telegram_bot_token") and values.get("telegram_chat_id")),
        "email": bool(values.get("smtp_host") and values.get("email_from") and values.get("email_to")),
    }


def notification_config() -> dict[str, bool]:
    return configured_channels(notification_settings.values())


def notification_channel_status(channel: str, values: dict[str, Any]) -> dict[str, Any]:
    configured = configured_channels(values).get(channel, False)
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


def notifications_payload() -> dict[str, Any]:
    values = notification_settings.values()
    return {
        "channels": {
            channel: notification_channel_status(channel, values)
            for channel in ("line", "slack", "telegram", "email")
        }
    }


def notification_service_check() -> dict[str, Any]:
    channels = notifications_payload()["channels"]
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


def clean_notification_form(channel: str, values: dict[str, Any]) -> dict[str, str]:
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


def slack_ai_bridge_test_payload() -> tuple[dict[str, Any], dict[str, Any]]:
    """Return a canned AI Bridge alert card without calling the LLM."""
    fake_alert = {
        "@sampledata": True,
        "rule": {
            "id": "5712",
            "level": 10,
            "description": "sshd: brute force trying to get access to the system. Non existent user.",
        },
        "agent": {"id": "001", "name": "EdgeSec-Pi 測試電腦", "ip": "192.0.2.10"},
        "data": {"srcip": "203.0.113.10", "dstuser": "demo-admin"},
        "full_log": (
            "EdgeSec-Pi Slack card test: Failed password for invalid user "
            "demo-admin from 203.0.113.10 port 55501 ssh2"
        ),
        "_edgesec": {
            "sampledata": True,
            "built_in_test": True,
            "business_context": {
                "role": "通知測試",
                "owner": "管理者",
                "criticality": "medium",
                "business_hours": "24/7",
                "notes": "這是 EdgeSec-Pi 內建 Slack 卡片測試，不代表公司真的被攻擊。",
            },
        },
    }
    fake_parsed = {
        "severity": "high",
        "summary_zh": "測試資料：有人從外部 IP（203.0.113.10）多次嘗試登入測試電腦的 demo-admin 帳號。",
        "impact_zh": "這是 AI Bridge Slack 卡片測試，用來確認正式告警格式、按鈕與通知管道可以送達。",
        "next_step_zh": "若收到這則訊息，代表 Slack 告警卡可正常送達；若沒有收到，請檢查 Slack Webhook、Bot Token、Channel ID 或 App Token。",
        "root_cause": "Built-in Slack card delivery test, no real attack.",
        "iocs": ["203.0.113.10", "demo-admin"],
        "action": "No remediation required. This is a notification delivery test.",
        "mitre": "T1110",
    }
    return fake_alert, fake_parsed


@router.get("/api/dashboard/notifications")
async def get_dashboard_notifications() -> dict[str, Any]:
    return notifications_payload()


@router.put("/api/dashboard/notifications/{channel}")
async def put_dashboard_notification_settings(
    channel: str,
    payload: NotificationSettingsPatch,
) -> dict[str, Any]:
    channel = channel.strip().lower()
    if channel not in notification_settings.CHANNEL_KEYS:
        raise HTTPException(status_code=404, detail="unknown notification channel")
    message = notification_settings.save(clean_notification_form(channel, payload.values), channel)
    if "尚未儲存" in message:
        raise HTTPException(status_code=400, detail=message)
    result = notifications_payload()
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
    result = notifications_payload()
    result["message"] = message
    return result


@router.post("/api/dashboard/notifications/slack/ai-bridge-test")
async def post_dashboard_slack_ai_bridge_test() -> dict[str, Any]:
    """Send a representative AI Bridge Slack alert card without waiting for LLM."""
    if not configured_channels(notification_settings.values()).get("slack"):
        raise HTTPException(status_code=400, detail="Slack 尚未設定。")
    fake_alert, fake_parsed = slack_ai_bridge_test_payload()
    async with httpx.AsyncClient() as client:
        await slack_render.send_to_slack(fake_alert, fake_parsed, client)
    return {
        "sent": True,
        "message": "AI Bridge Slack 告警卡已送出；這不會呼叫 LLM，也不會新增正式告警紀錄。",
    }


@router.post("/api/dashboard/notifications/slack/digest-test")
async def post_dashboard_slack_digest_test() -> dict[str, Any]:
    """Send the AI Bridge daily security status digest immediately."""
    values = notification_settings.values()
    if not values.get("slack_webhook"):
        raise HTTPException(status_code=400, detail="AI Bridge 每日狀態檢查目前需要 Slack Webhook URL。")
    status = await digest.send_digest(values.get("slack_webhook"))
    return {
        "sent": True,
        "status": status,
        "message": "AI Bridge 每日資安狀態檢查已送出。",
    }
