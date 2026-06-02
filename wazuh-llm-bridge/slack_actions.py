"""Interactive Slack buttons via Socket Mode.

Slack incoming webhooks are one-way (we POST, nothing comes back). To
receive button clicks we need a Slack App with a Bot Token + an
App-Level Token, then connect outbound to Slack via WebSocket
(Socket Mode). No public HTTPS URL or tunnel required — perfect for
SMB on-prem deployments behind NAT.

What this module does:
  - posts alert messages with `🔒 Block <IP>` buttons via chat.postMessage
  - receives button clicks via Socket Mode listener
  - dispatches the click to wazuh.block_ip()
  - rewrites the original Slack message in place to "✅ blocked by <user>"

Falls back to no-op silently if SLACK_BOT_TOKEN / SLACK_APP_TOKEN /
SLACK_CHANNEL_ID aren't all set — the rest of the bridge still runs.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from typing import Any, Optional

import active_response_safety
import wazuh
import remote_action_tokens

log = logging.getLogger("slack-actions")

SLACK_BOT_TOKEN  = os.getenv("SLACK_BOT_TOKEN", "").strip() or None
SLACK_APP_TOKEN  = os.getenv("SLACK_APP_TOKEN", "").strip() or None
SLACK_CHANNEL_ID = os.getenv("SLACK_CHANNEL_ID", "").strip() or None
WAZUH_ISOLATE_COMMAND = os.getenv("WAZUH_ISOLATE_COMMAND", "").strip()

_app = None
_handler_task: Optional[asyncio.Task] = None


def is_enabled() -> bool:
    return bool(SLACK_BOT_TOKEN and SLACK_APP_TOKEN and SLACK_CHANNEL_ID)


def endpoint_isolation_enabled(platform: str = "", *, agent_id: str = "", agent_name: str = "") -> bool:
    return active_response_safety.isolation_actions_enabled(
        platform,
        agent_id=agent_id,
        agent_name=agent_name,
    )


# IPv4 detection — only show "block IP" button for IOCs that look like
# real IPv4 addresses. Skip usernames, file paths, hashes, IPv6 (those
# need different blocking strategies).
_IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def extract_blockable_ips(parsed_llm: dict[str, Any]) -> list[str]:
    iocs = parsed_llm.get("iocs") or []
    out = []
    for ioc in iocs:
        s = str(ioc).strip()
        if _IPV4_RE.match(s) and active_response_safety.is_blockable_ip_candidate(s):
            out.append(active_response_safety.normalize_ip(s))
    return out


# ────────────────────────────────────────────────────────────────────────
# Bolt app
# ────────────────────────────────────────────────────────────────────────
async def _get_app():
    """Lazy-create the Bolt app so importing this module doesn't fail
    when slack_bolt isn't installed (e.g. in webhook-only deployments)."""
    global _app
    if _app is not None:
        return _app
    if not is_enabled():
        return None

    from slack_bolt.async_app import AsyncApp
    _app = AsyncApp(token=SLACK_BOT_TOKEN)
    _register_handlers(_app)
    return _app


def _unblock_button(agent_id: str, ip: str) -> dict:
    """Block Kit element for the 🔓 unblock button shown after a block."""
    return {
        "type": "button",
        "action_id": "unblock_ip",
        "text": {"type": "plain_text", "text": "解除封鎖"},
        "value": remote_action_tokens.issue("unblock_ip", agent_id, target=ip),
        "confirm": {
            "title":   {"type": "plain_text", "text": "確認解除封鎖？"},
            "text":    {"type": "mrkdwn",
                        "text": (
                            f"只有在確認 `{ip}` 封錯、或事件已處理完成時才使用。\n"
                            "按下後，這個來源會恢復連線能力。"
                        )},
            "confirm": {"type": "plain_text", "text": "解除封鎖"},
            "deny":    {"type": "plain_text", "text": "取消"},
        },
    }


def _isolation_target(agent_name: str, platform: str = "") -> str:
    return json.dumps(
        {
            "name": str(agent_name or ""),
            "platform": str(platform or ""),
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )


def _parse_isolation_target(value: Any) -> tuple[str, str]:
    raw = str(value or "")
    try:
        parsed = json.loads(raw)
    except Exception:
        return raw, ""
    if not isinstance(parsed, dict):
        return raw, ""
    return str(parsed.get("name") or ""), str(parsed.get("platform") or "")


def _isolate_button(agent_id: str, agent_name: str, platform: str = "") -> dict:
    """Block Kit element for endpoint isolation."""
    return {
        "type": "button",
        "action_id": "isolate_endpoint",
        "style": "danger",
        "text": {"type": "plain_text", "text": "隔離端點"},
        "value": remote_action_tokens.issue(
            "isolate_endpoint",
            agent_id,
            target=_isolation_target(agent_name, platform),
        ),
        "confirm": {
            "title": {"type": "plain_text", "text": "確認隔離這台電腦？"},
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"這會嘗試暫停 *{agent_name or '這台電腦'}* 的網路連線，"
                    "避免疑似中毒或外洩擴大。\n"
                    "風險：使用者可能立刻不能工作；若是重要服務，可能影響營運。"
                ),
            },
            "confirm": {"type": "plain_text", "text": "隔離端點"},
            "deny": {"type": "plain_text", "text": "取消"},
        },
    }


def _release_isolation_button(agent_id: str, agent_name: str) -> dict:
    """Block Kit element for releasing endpoint isolation."""
    target = agent_name or agent_id
    return {
        "type": "button",
        "action_id": "release_isolation",
        "text": {"type": "plain_text", "text": "解除隔離"},
        "value": remote_action_tokens.issue("release_isolation", agent_id, target=agent_name),
        "confirm": {
            "title": {"type": "plain_text", "text": "確認解除隔離？"},
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"只有在 IT 確認 `{target}` 已處理完成、或隔離造成營運影響時才使用。\n"
                    "按下後會嘗試恢復這台端點的網路連線。"
                ),
            },
            "confirm": {"type": "plain_text", "text": "解除隔離"},
            "deny": {"type": "plain_text", "text": "取消"},
        },
    }


def _friendly_isolation_error(agent_name: str, error: Exception) -> str:
    raw = str(error)
    target = agent_name or "這台電腦"
    if "endpoint isolation is not enabled" in raw or "WAZUH_ISOLATE_COMMAND" in raw:
        return (
            f"⚠️ *尚未啟用端點隔離*\n"
            f"`{target}` 目前沒有安裝並設定端點隔離腳本，所以系統沒有真的隔離這台電腦。\n"
            "請 IT 先手動處理；若要啟用這個按鈕，請先完成隔離腳本部署並設定 `WAZUH_ISOLATE_COMMAND`。"
        )
    if "WAZUH_RELEASE_ISOLATE_COMMAND" in raw or "解除隔離命令" in raw:
        return (
            f"⚠️ *尚未啟用解除隔離*\n"
            f"`{target}` 目前沒有設定解除隔離腳本。為避免單向隔離，系統拒絕執行隔離。\n"
            "請先部署並設定 `WAZUH_RELEASE_ISOLATE_COMMAND`。"
        )
    if "管理通道" in raw or "management-channel" in raw:
        return (
            f"⚠️ *隔離腳本尚未通過安全確認*\n"
            f"`{target}` 的隔離腳本必須保留 Wazuh/管理通道，否則遠端可能救不回來。\n"
            "請先測試腳本，再設定 `ACTIVE_RESPONSE_ISOLATION_PRESERVE_CHANNELS_ACK=1`。"
        )
    if "真機隔離" in raw or "作業系統" in raw or "agent platform" in raw:
        return (
            f"⚠️ *端點隔離尚未對這個作業系統放行*\n"
            f"`{target}` 的 OS 還沒有被標記為真機測試通過，系統拒絕隔離。\n"
            "請 IT 完成 isolate/release/TTL/重開機測試後，再設定 `ACTIVE_RESPONSE_ISOLATION_VERIFIED_PLATFORMS`。"
        )
    return (
        f"❌ *隔離 `{target}` 未完成*\n"
        f"請 IT 手動處理，並查看 bridge log 確認原因。錯誤摘要：{raw}"
    )


def _friendly_release_isolation_error(agent_name: str, error: Exception) -> str:
    raw = str(error)
    target = agent_name or "這台電腦"
    if "找不到 EdgeSec-Pi" in raw:
        return f"⚠️ *沒有追蹤中的隔離紀錄* `{target}` 不是由 EdgeSec-Pi 目前這筆隔離流程管理。"
    if "WAZUH_RELEASE_ISOLATE_COMMAND" in raw:
        return (
            f"⚠️ *尚未啟用解除隔離*\n"
            f"`{target}` 需要 IT 手動恢復，或先部署 `WAZUH_RELEASE_ISOLATE_COMMAND`。"
        )
    return f"❌ *解除隔離 `{target}` 未完成*\n請 IT 手動處理，並查看 bridge log。錯誤摘要：{raw}"


def _rewrite_with_audit(attachments: list[dict],
                        confirm_line: str,
                        new_action_button: Optional[dict] = None) -> list[dict]:
    """Strip existing actions block, append an audit-trail context line,
    optionally add a fresh actions block (for the next available action)."""
    new_attachments = []
    for att in attachments:
        blocks = [b for b in (att.get("blocks") or [])
                  if b.get("type") != "actions"]
        blocks.append({
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": confirm_line}],
        })
        if new_action_button is not None:
            blocks.append({"type": "actions", "elements": [new_action_button]})
        new_attachments.append({**att, "blocks": blocks})
    return new_attachments


def _register_handlers(app) -> None:
    """All Bolt action_id handlers live here. To add a new button type
    (e.g. isolate-host, kill-process), add another @app.action() below."""

    @app.action("block_ip")
    async def handle_block_ip(ack, body, action, respond, client):
        await ack()                                  # required within 3s
        clicker = body.get("user", {}).get("username") or body.get("user", {}).get("id", "?")
        value = action.get("value", "")
        try:
            claims = remote_action_tokens.consume(value, "block_ip", clicker=clicker)
            agent_id = str(claims["agent_id"])
            ip = str(claims.get("target") or "")
            if not ip:
                raise remote_action_tokens.ActionTokenError("處置 token 缺少來源 IP，已拒絕執行。")
        except remote_action_tokens.ActionTokenError as e:
            await respond(replace_original=False,
                          text=f"⚠️ {e}")
            return

        log.warning("user=%s clicked block_ip agent=%s ip=%s", clicker, agent_id, ip)
        try:
            result = await wazuh.block_ip(agent_id, ip)
            if (result.get("data", {}) or {}).get("total_failed_items", 0):
                err = (result["data"]["failed_items"][0]
                       .get("error", {}).get("message", "unknown"))
                raise RuntimeError(f"Wazuh API: {err}")
        except active_response_safety.ActiveResponseDenied as e:
            await respond(replace_original=False, text=f"⚠️ 封鎖 `{ip}` 已拒絕：{e.message}")
            return
        except Exception as e:
            log.exception("block_ip failed")
            await respond(replace_original=False, text=f"❌ 封鎖 `{ip}` 失敗：{e}")
            return

        attachments = body.get("message", {}).get("attachments") or []
        rewritten = _rewrite_with_audit(
            attachments,
            confirm_line=(f"✅ *已封鎖* `{ip}` "
                          f"(by *{clicker}* · {time.strftime('%H:%M:%S')} "
                          f"· Wazuh active response)"),
            new_action_button=_unblock_button(agent_id, ip),
        )
        await respond(replace_original=True,
                      text=f"已封鎖 {ip}",
                      attachments=rewritten)

    @app.action("unblock_ip")
    async def handle_unblock_ip(ack, body, action, respond, client):
        await ack()
        clicker = body.get("user", {}).get("username") or body.get("user", {}).get("id", "?")
        value = action.get("value", "")
        try:
            claims = remote_action_tokens.consume(value, "unblock_ip", clicker=clicker)
            agent_id = str(claims["agent_id"])
            ip = str(claims.get("target") or "")
            if not ip:
                raise remote_action_tokens.ActionTokenError("處置 token 缺少來源 IP，已拒絕執行。")
        except remote_action_tokens.ActionTokenError as e:
            await respond(replace_original=False,
                          text=f"⚠️ {e}")
            return

        log.warning("user=%s clicked unblock_ip agent=%s ip=%s", clicker, agent_id, ip)
        try:
            result = await wazuh.unblock_ip(agent_id, ip)
            if not result.get("ok"):
                raise RuntimeError(result.get("error", "unknown"))
        except active_response_safety.ActiveResponseDenied as e:
            await respond(replace_original=False, text=f"⚠️ 解封 `{ip}` 已拒絕：{e.message}")
            return
        except Exception as e:
            log.exception("unblock_ip failed")
            await respond(replace_original=False, text=f"❌ 解封 `{ip}` 失敗：{e}")
            return

        attachments = body.get("message", {}).get("attachments") or []
        rewritten = _rewrite_with_audit(
            attachments,
            confirm_line=(f"🔓 *已解封* `{ip}` "
                          f"(by *{clicker}* · {time.strftime('%H:%M:%S')} "
                          f"· local pfctl)"),
            new_action_button=None,                # nothing more to do after unblock
        )
        await respond(replace_original=True,
                      text=f"已解封 {ip}",
                      attachments=rewritten)

    @app.action("isolate_endpoint")
    async def handle_isolate_endpoint(ack, body, action, respond, client):
        await ack()
        clicker = body.get("user", {}).get("username") or body.get("user", {}).get("id", "?")
        value = action.get("value", "")
        try:
            claims = remote_action_tokens.consume(value, "isolate_endpoint", clicker=clicker)
            agent_id = str(claims["agent_id"])
            agent_name, agent_platform = _parse_isolation_target(claims.get("target"))
        except remote_action_tokens.ActionTokenError as e:
            await respond(replace_original=False,
                          text=f"⚠️ {e}")
            return

        log.warning("user=%s clicked isolate_endpoint agent=%s", clicker, agent_id)
        try:
            result = await wazuh.isolate_agent(
                agent_id,
                reason=f"Slack emergency isolation requested by {clicker}",
                agent_name=agent_name,
                platform=agent_platform,
                actor=clicker,
            )
            if not result.get("ok"):
                raise RuntimeError(result.get("error", "unknown"))
        except Exception as e:
            log.exception("isolate_endpoint failed")
            attachments = body.get("message", {}).get("attachments") or []
            rewritten = _rewrite_with_audit(
                attachments,
                confirm_line=(
                    f"⚠️ *端點隔離未執行* `{agent_name or agent_id}` "
                    f"(by *{clicker}* · {time.strftime('%H:%M:%S')} · 尚未完成隔離腳本設定)"
                ),
                new_action_button=None,
            )
            await respond(replace_original=True,
                          text=_friendly_isolation_error(agent_name or agent_id, e),
                          attachments=rewritten)
            return

        attachments = body.get("message", {}).get("attachments") or []
        guardrails = (result.get("wazuh_response", {}).get("_edgesec") or {}).get("guardrails") or {}
        ttl_s = result.get("ttl_s") or guardrails.get("ttl_s")
        ttl_text = f" · TTL {int(ttl_s // 60)} 分鐘" if isinstance(ttl_s, (int, float)) else ""
        rewritten = _rewrite_with_audit(
            attachments,
            confirm_line=(f"⛔ *已送出端點隔離* `{agent_name or agent_id}` "
                          f"(by *{clicker}* · {time.strftime('%H:%M:%S')} "
                          f"· Wazuh active response{ttl_text})"),
            new_action_button=_release_isolation_button(agent_id, agent_name),
        )
        await respond(replace_original=True,
                      text=f"已送出端點隔離 {agent_name or agent_id}",
                      attachments=rewritten)

    @app.action("release_isolation")
    async def handle_release_isolation(ack, body, action, respond, client):
        await ack()
        clicker = body.get("user", {}).get("username") or body.get("user", {}).get("id", "?")
        value = action.get("value", "")
        try:
            claims = remote_action_tokens.consume(value, "release_isolation", clicker=clicker)
            agent_id = str(claims["agent_id"])
            agent_name = str(claims.get("target") or "")
        except remote_action_tokens.ActionTokenError as e:
            await respond(replace_original=False, text=f"⚠️ {e}")
            return

        log.warning("user=%s clicked release_isolation agent=%s", clicker, agent_id)
        try:
            result = await wazuh.release_isolation(
                agent_id,
                agent_name=agent_name,
                reason=f"Slack isolation release requested by {clicker}",
                actor=clicker,
            )
            if not result.get("ok"):
                raise RuntimeError(result.get("error", "unknown"))
        except Exception as e:
            log.exception("release_isolation failed")
            await respond(
                replace_original=False,
                text=_friendly_release_isolation_error(agent_name or agent_id, e),
            )
            return

        attachments = body.get("message", {}).get("attachments") or []
        rewritten = _rewrite_with_audit(
            attachments,
            confirm_line=(f"✅ *已送出解除隔離* `{agent_name or agent_id}` "
                          f"(by *{clicker}* · {time.strftime('%H:%M:%S')} "
                          f"· Wazuh active response)"),
            new_action_button=None,
        )
        await respond(
            replace_original=True,
            text=f"已送出解除隔離 {agent_name or agent_id}",
            attachments=rewritten,
        )


# ────────────────────────────────────────────────────────────────────────
# Public API used by app.py
# ────────────────────────────────────────────────────────────────────────
async def post_alert(attachments: list[dict[str, Any]]) -> Optional[dict[str, Any]]:
    """Post an alert message to the configured channel via chat.postMessage.

    Caller passes Slack-formatted attachments (color stripe + blocks).
    Returns Slack's response, or None if disabled / failed."""
    if not is_enabled():
        return None
    app = await _get_app()
    try:
        r = await app.client.chat_postMessage(
            channel=SLACK_CHANNEL_ID,
            text="Wazuh alert",  # fallback for notification preview
            attachments=attachments,
        )
        return r.data
    except Exception as e:
        log.warning("chat.postMessage failed: %s", e)
        return None


async def start_listener() -> None:
    """Spawn the Socket Mode WebSocket listener as an asyncio task.
    Call once during app startup (lifespan)."""
    global _handler_task
    if not is_enabled():
        log.info("slack actions disabled — set SLACK_BOT_TOKEN/APP_TOKEN/CHANNEL_ID to enable")
        return
    app = await _get_app()
    from slack_bolt.adapter.socket_mode.async_handler import AsyncSocketModeHandler
    handler = AsyncSocketModeHandler(app, SLACK_APP_TOKEN)
    _handler_task = asyncio.create_task(handler.start_async())
    log.info("Slack Socket Mode listener spawned")


async def stop_listener() -> None:
    if _handler_task is not None and not _handler_task.done():
        _handler_task.cancel()
        try:
            await _handler_task
        except asyncio.CancelledError:
            pass
