"""Additional notification channels for EdgeSec-Pi.

Slack is still handled by slack_render/slack_actions because it has Block Kit
and action buttons. This module covers simpler push channels used by owners:
LINE push messages, Telegram bot messages, and SMTP email.
"""
from __future__ import annotations

import asyncio
import json
import os
import smtplib
import ssl
from email.message import EmailMessage
from pathlib import Path
from typing import Any

import httpx

import owner_context


SETTINGS_PATH = Path(
    os.getenv("NOTIFICATION_SETTINGS_PATH", Path(__file__).parent / "data" / "notification_channels.json")
)


def load_settings() -> dict[str, Any]:
    try:
        if SETTINGS_PATH.exists():
            with SETTINGS_PATH.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
                if isinstance(data, dict):
                    return data
    except Exception:
        return {}
    return {}


def save_settings(settings: dict[str, Any]) -> None:
    SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with SETTINGS_PATH.open("w", encoding="utf-8") as fh:
        json.dump(settings, fh, ensure_ascii=False, indent=2)
    try:
        SETTINGS_PATH.chmod(0o600)
    except OSError:
        pass


def _config(key: str, default: str = "") -> str:
    env_value = os.getenv(key)
    if env_value is not None and env_value.strip():
        return env_value.strip()
    value = load_settings().get(key, default)
    return str(value).strip() if value is not None else ""


def get_config(key: str, default: str = "") -> str:
    return _config(key, default)


def _alert_text(alert: dict[str, Any], parsed: dict[str, Any] | None) -> str:
    data = parsed or {}
    severity = str(data.get("severity") or "unknown").upper()
    summary = data.get("summary_zh") or "EdgeSec-Pi 偵測到一筆資安事件。"
    impact = data.get("impact_zh") or ""
    next_step = data.get("next_step_zh") or ""
    endpoint_lines = owner_context.management_context_lines(alert, markdown=False)
    parts = [f"EdgeSec-Pi 告警 [{severity}]", "", "哪台電腦", *endpoint_lines, "", "發生什麼事", str(summary)]
    if impact:
        parts += ["", "不處理的後果", str(impact)]
    if next_step:
        parts += ["", "立刻該做的事", str(next_step)]
    return "\n".join(parts)


def line_configured() -> bool:
    return bool(
        _config("LINE_CHANNEL_ACCESS_TOKEN")
        and _config("LINE_USER_ID")
    )


def email_configured() -> bool:
    return bool(
        _config("SMTP_HOST")
        and _config("EMAIL_FROM")
        and _config("EMAIL_TO")
    )


def telegram_configured() -> bool:
    return bool(
        _config("TELEGRAM_BOT_TOKEN")
        and _config("TELEGRAM_CHAT_ID")
    )


async def send_line_message(text: str, client: httpx.AsyncClient) -> dict[str, Any]:
    token = _config("LINE_CHANNEL_ACCESS_TOKEN")
    to = _config("LINE_USER_ID")
    if not token or not to:
        return {"sent": False, "reason": "LINE_CHANNEL_ACCESS_TOKEN or LINE_USER_ID not set"}
    response = await client.post(
        "https://api.line.me/v2/bot/message/push",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json={"to": to, "messages": [{"type": "text", "text": text[:4900]}]},
        timeout=10,
    )
    response.raise_for_status()
    return {"sent": True}


async def send_telegram_message(text: str, client: httpx.AsyncClient) -> dict[str, Any]:
    token = _config("TELEGRAM_BOT_TOKEN")
    chat_id = _config("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        return {"sent": False, "reason": "TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID not set"}
    response = await client.post(
        f"https://api.telegram.org/bot{token}/sendMessage",
        json={"chat_id": chat_id, "text": text[:4096]},
        timeout=10,
    )
    response.raise_for_status()
    return {"sent": True}


def _send_email_sync(subject: str, body: str) -> None:
    host = _config("SMTP_HOST")
    port = int(_config("SMTP_PORT", "587") or "587")
    username = _config("SMTP_USER")
    password = _config("SMTP_PASS")
    sender = _config("EMAIL_FROM")
    recipients = [x.strip() for x in _config("EMAIL_TO").split(",") if x.strip()]
    use_ssl = _config("SMTP_SSL").lower() in {"1", "true", "yes", "on"}
    use_starttls = _config("SMTP_STARTTLS", "true").lower() not in {"0", "false", "no", "off"}
    if not host or not sender or not recipients:
        raise RuntimeError("SMTP_HOST, EMAIL_FROM, and EMAIL_TO are required")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    msg.set_content(body)

    if use_ssl:
        with smtplib.SMTP_SSL(host, port, context=ssl.create_default_context(), timeout=10) as smtp:
            if username or password:
                smtp.login(username, password)
            smtp.send_message(msg)
    else:
        with smtplib.SMTP(host, port, timeout=10) as smtp:
            if use_starttls:
                smtp.starttls(context=ssl.create_default_context())
            if username or password:
                smtp.login(username, password)
            smtp.send_message(msg)


async def send_email_message(subject: str, body: str) -> dict[str, Any]:
    if not email_configured():
        return {"sent": False, "reason": "SMTP_HOST, EMAIL_FROM, or EMAIL_TO not set"}
    await asyncio.to_thread(_send_email_sync, subject, body)
    return {"sent": True}


async def send_secondary_notifications(
    alert: dict[str, Any],
    parsed: dict[str, Any] | None,
    client: httpx.AsyncClient,
) -> dict[str, Any]:
    text = _alert_text(alert, parsed)
    results: dict[str, Any] = {}
    if line_configured():
        try:
            results["line"] = await send_line_message(text, client)
        except Exception as exc:
            results["line"] = {"sent": False, "error": str(exc)}
    if telegram_configured():
        try:
            results["telegram"] = await send_telegram_message(text, client)
        except Exception as exc:
            results["telegram"] = {"sent": False, "error": str(exc)}
    if email_configured():
        try:
            results["email"] = await send_email_message("EdgeSec-Pi 資安告警", text)
        except Exception as exc:
            results["email"] = {"sent": False, "error": str(exc)}
    return results
