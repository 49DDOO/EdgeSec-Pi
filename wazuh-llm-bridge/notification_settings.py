"""Notification settings persistence and test delivery helpers."""
from __future__ import annotations

from datetime import datetime
from typing import Any
from urllib.parse import quote

import httpx

import notify_channels


CHANNEL_KEYS: dict[str, list[str]] = {
    "line": ["LINE_CHANNEL_ACCESS_TOKEN", "LINE_USER_ID"],
    "telegram": ["TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID"],
    "slack": [
        "SLACK_WEBHOOK_URL",
        "SLACK_BOT_TOKEN",
        "SLACK_APP_TOKEN",
        "SLACK_CHANNEL_ID",
        "BRIDGE_PUBLIC_URL",
    ],
    "email": ["SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASS", "EMAIL_FROM", "EMAIL_TO"],
}

SECRET_KEYS = {
    "SLACK_WEBHOOK_URL",
    "SLACK_BOT_TOKEN",
    "SLACK_APP_TOKEN",
    "LINE_CHANNEL_ACCESS_TOKEN",
    "TELEGRAM_BOT_TOKEN",
    "SMTP_PASS",
}

CHANNEL_NAMES = {"line": "LINE", "slack": "Slack", "telegram": "Telegram", "email": "Email"}


def get_value(key: str, default: str = "") -> str:
    return notify_channels.get_config(key, default)


def mask_status(value: str | None) -> str:
    return "已設定" if (value or "").strip() else "未設定"


def secret_placeholder(value: str) -> str:
    return "已設定，若要更換才貼新值" if value else "尚未設定"


def values() -> dict[str, Any]:
    return {
        "slack_webhook": get_value("SLACK_WEBHOOK_URL"),
        "slack_bot": get_value("SLACK_BOT_TOKEN"),
        "slack_app": get_value("SLACK_APP_TOKEN"),
        "slack_channel": get_value("SLACK_CHANNEL_ID"),
        "bridge_public_url": get_value("BRIDGE_PUBLIC_URL"),
        "line_channel_token": get_value("LINE_CHANNEL_ACCESS_TOKEN"),
        "line_user_id": get_value("LINE_USER_ID"),
        "telegram_bot_token": get_value("TELEGRAM_BOT_TOKEN"),
        "telegram_chat_id": get_value("TELEGRAM_CHAT_ID"),
        "smtp_host": get_value("SMTP_HOST"),
        "smtp_port": get_value("SMTP_PORT", "587"),
        "smtp_user": get_value("SMTP_USER"),
        "email_from": get_value("EMAIL_FROM"),
        "email_to": get_value("EMAIL_TO"),
        "slack_tested_at": get_value("SLACK_TESTED_AT"),
        "line_tested_at": get_value("LINE_TESTED_AT"),
        "telegram_tested_at": get_value("TELEGRAM_TESTED_AT"),
        "email_tested_at": get_value("EMAIL_TESTED_AT"),
        "smtp_ssl": get_value("SMTP_SSL").lower() in {"1", "true", "yes", "on"},
        "smtp_starttls": get_value("SMTP_STARTTLS", "true").lower() not in {"0", "false", "no", "off"},
    }


def _merged_form_value(settings: dict[str, Any], form: Any, key: str, secret: bool = False) -> str:
    submitted = str(form.get(key) or "").strip() if key in form else ""
    if secret and not submitted:
        return str(settings.get(key) or "").strip()
    return submitted


def _validate_channel_settings(settings: dict[str, Any], form: Any, channel: str) -> str | None:
    if channel == "line":
        missing = []
        if not _merged_form_value(settings, form, "LINE_CHANNEL_ACCESS_TOKEN", secret=True):
            missing.append("LINE 權杖")
        if not _merged_form_value(settings, form, "LINE_USER_ID"):
            missing.append("接收 LINE 的人")
        return f"LINE 尚未儲存：請先填 {', '.join(missing)}。" if missing else None
    if channel == "telegram":
        missing = []
        if not _merged_form_value(settings, form, "TELEGRAM_BOT_TOKEN", secret=True):
            missing.append("Bot Token")
        if not _merged_form_value(settings, form, "TELEGRAM_CHAT_ID"):
            missing.append("Chat ID")
        return f"Telegram 尚未儲存：請先填 {', '.join(missing)}。" if missing else None
    if channel == "email":
        missing = []
        for key, label in (("SMTP_HOST", "SMTP 主機"), ("EMAIL_FROM", "寄件者"), ("EMAIL_TO", "收件者")):
            if not _merged_form_value(settings, form, key):
                missing.append(label)
        return f"Email 尚未儲存：請先填 {', '.join(missing)}。" if missing else None
    if channel == "slack":
        webhook = _merged_form_value(settings, form, "SLACK_WEBHOOK_URL", secret=True)
        bot = _merged_form_value(settings, form, "SLACK_BOT_TOKEN", secret=True)
        app = _merged_form_value(settings, form, "SLACK_APP_TOKEN", secret=True)
        channel_id = _merged_form_value(settings, form, "SLACK_CHANNEL_ID")
        if not webhook and not (bot and app and channel_id):
            return "Slack 尚未儲存：請填 Webhook URL，或填 Bot Token + App Token + Channel ID。"
    return None


def save(form: Any, channel: str) -> str:
    keys = CHANNEL_KEYS.get(channel)
    if not keys:
        return "請選擇要儲存的通知管道。"

    settings = notify_channels.load_settings()
    validation_error = _validate_channel_settings(settings, form, channel)
    if validation_error:
        return validation_error

    for key in keys:
        if key in form:
            value = str(form.get(key) or "").strip()
            if key in SECRET_KEYS and not value and settings.get(key):
                continue
            settings[key] = value
    if channel == "email":
        settings["SMTP_SSL"] = "true" if "SMTP_SSL" in form else "false"
        settings["SMTP_STARTTLS"] = "true" if "SMTP_STARTTLS" in form else "false"
    notify_channels.save_settings(settings)
    return f"{CHANNEL_NAMES[channel]} 設定已儲存。請按測試確認通知能送達。"


async def test_channel(channel: str) -> str:
    message = "EdgeSec-Pi 通知測試：如果你收到這則訊息，代表此通知管道可以使用。"
    if channel == "slack":
        import slack_actions

        if slack_actions.is_enabled():
            res = await slack_actions.post_alert([
                {"color": "#2eb67d", "blocks": [
                    {"type": "section", "text": {"type": "mrkdwn", "text": f"*{message}*"}}
                ]}
            ])
            if not res:
                raise RuntimeError("Slack Bot 已設定但送出失敗，請檢查 bridge log。")
        else:
            webhook = notify_channels.get_config("SLACK_WEBHOOK_URL")
            if not webhook:
                raise RuntimeError("Slack 尚未設定。")
            async with httpx.AsyncClient() as client:
                response = await client.post(webhook, json={"text": message}, timeout=10)
                response.raise_for_status()
        tested_key = "SLACK_TESTED_AT"
        flash = "Slack 測試訊息已送出。"
    elif channel == "line":
        async with httpx.AsyncClient() as client:
            await notify_channels.send_line_message(message, client)
        tested_key = "LINE_TESTED_AT"
        flash = "LINE 測試訊息已送出。"
    elif channel == "telegram":
        async with httpx.AsyncClient() as client:
            await notify_channels.send_telegram_message(message, client)
        tested_key = "TELEGRAM_TESTED_AT"
        flash = "Telegram 測試訊息已送出。"
    elif channel == "email":
        await notify_channels.send_email_message("EdgeSec-Pi 通知測試", message)
        tested_key = "EMAIL_TESTED_AT"
        flash = "Email 測試訊息已送出。"
    else:
        raise RuntimeError("未知通知管道。")
    settings = notify_channels.load_settings()
    settings[tested_key] = datetime.now().strftime("%Y-%m-%d %H:%M")
    notify_channels.save_settings(settings)
    return flash


def channel_url(channel: str, token: str = "", flash: str = "") -> str:
    params = []
    if token:
        params.append(f"t={quote(token)}")
    if flash:
        params.append(f"flash={quote(flash)}")
    query = f"?{'&'.join(params)}" if params else ""
    return f"/admin/notifications/{channel}{query}"
