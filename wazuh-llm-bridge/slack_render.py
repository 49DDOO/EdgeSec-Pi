"""
Slack rendering for EdgeSec-Pi alerts.

Two payload formats:
  • build_slack_payload         — legacy attachment format (incoming webhook)
  • build_slack_blocks_payload  — pure Block Kit (bot mode chat.postMessage)

Single entry point: send_to_slack(alert, parsed, client, evidence). Bot mode
takes precedence when configured; otherwise falls back to webhook mode;
otherwise silently no-ops.

Extracted from app.py — purely mechanical move + signature tweak: builders
now take a pre-parsed verdict dict instead of the raw LLM reply string,
so the caller owns LLM parsing (avoids circular import with prompting).
"""
from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Optional
from urllib.parse import urlencode

import httpx

import admin_token
import org_profile
import owner_context
import remote_action_tokens
import slack_actions

log = logging.getLogger("wazuh-bridge")

# Env-driven config read independently from app.py.
LM_MODEL          = os.getenv("LM_MODEL", "local-model")
BRIDGE_PUBLIC_URL = os.getenv("BRIDGE_PUBLIC_URL", "").rstrip("/")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "").strip() or None
SLACK_TIMEOUT_S   = float(os.getenv("SLACK_TIMEOUT_S", "10"))


# Severity → (Slack attachment color, emoji prefix)
SEVERITY_STYLE: dict[str, tuple[str, str]] = {
    "critical": ("#dc2626", "🔥"),  # red
    "high":     ("#ea580c", "🚨"),  # orange
    "medium":   ("#ca8a04", "⚠️"),  # amber
    "low":      ("#2563eb", "ℹ️"),  # blue
    "info":     ("#6b7280", "💬"),  # gray
}

# Severity → 中文標題 (用給非技術主管看)
SEVERITY_TITLE_ZH: dict[str, str] = {
    "critical": "緊急",
    "high":     "警示",
    "medium":   "注意",
    "low":      "提醒",
    "info":     "訊息",
}


def _asset_context(alert: dict[str, Any]) -> dict[str, str]:
    """Boss-facing endpoint context shown at the top of every Slack card."""
    return owner_context.asset_context(alert)


def management_context_lines(alert: dict[str, Any], *, markdown: bool = True) -> list[str]:
    """Return compact endpoint context for owner-facing notifications."""
    return owner_context.management_context_lines(alert, markdown=markdown)


def _context_markdown(ctx: dict[str, str]) -> str:
    return owner_context.context_markdown(ctx)


def _slack_plain(text: str, limit: int = 130) -> str:
    text = " ".join(str(text or "").split())
    return text[:limit] if len(text) <= limit else text[: limit - 1] + "…"


def _is_sample_alert(alert: dict[str, Any]) -> bool:
    meta = alert.get("_edgesec") if isinstance(alert.get("_edgesec"), dict) else {}
    return alert.get("@sampledata") is True or bool(meta.get("sampledata"))


def _format_evidence_lines(evidence: list[dict[str, Any]] | None) -> str:
    """Render the agent's tool-call trace as a tidy bullet list for Slack."""
    if not evidence:
        return ""
    lines: list[str] = []
    for step in evidence:
        tool = step.get("tool", "?")
        if tool == "submit_final_verdict":
            continue
        args_snip = json.dumps(step.get("args") or {}, ensure_ascii=False)[:120]
        preview   = (step.get("result_preview") or "").strip()
        if preview:
            lines.append(f"• `{tool}` {args_snip} → {preview[:140]}")
        else:
            lines.append(f"• `{tool}` {args_snip}")
    return "\n".join(lines)


def build_slack_payload(alert: dict[str, Any],
                        parsed: Optional[dict[str, Any]],
                        evidence: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Render a Wazuh alert + Gemma's JSON triage as a Slack attachment.

    Layout philosophy: SMB owner (non-technical, reads Chinese) sees the
    headline + impact + immediate action up top. IT staff (technical,
    reads English) sees the rule/agent/IOC/MITRE/raw-log details in the
    fields section underneath. One message serves both audiences.

    Same payload also works on Discord — append `?slack=true` to the
    Discord webhook URL.
    """
    parsed = parsed or {}
    severity = str(parsed.get("severity", "info")).lower().strip()
    color, emoji = SEVERITY_STYLE.get(severity, SEVERITY_STYLE["info"])
    sev_zh = SEVERITY_TITLE_ZH.get(severity, "訊息")

    rule         = alert.get("rule") or {}
    rule_id      = rule.get("id", "?")
    level        = rule.get("level", "?")
    description  = rule.get("description", "")
    ctx          = _asset_context(alert)
    is_sample    = _is_sample_alert(alert)

    agent        = alert.get("agent") or {}
    agent_label  = agent.get("name", "?")
    if ip := agent.get("ip"):
        agent_label = f"{agent_label} ({ip})"

    full_log     = (alert.get("full_log") or "").strip()
    iocs         = parsed.get("iocs") or []
    iocs_str     = ", ".join(f"`{i}`" for i in iocs) if iocs else "_(無)_"
    mitre        = parsed.get("mitre") or "—"

    # ── Non-technical Chinese fields (management-readable) ──
    summary_zh   = (parsed.get("summary_zh")
                    or parsed.get("root_cause")
                    or "（LLM 未提供白話摘要，請看下方技術細節）")
    impact_zh    = parsed.get("impact_zh") or ""
    next_step_zh = (parsed.get("next_step_zh")
                    or parsed.get("action")
                    or "（LLM 未提供建議；請聯絡 IT 評估）")
    investigation_zh = (parsed.get("investigation_summary_zh") or "").strip()

    # Build the main body — what management reads first.
    # When the agentic loop ran, the 白話 investigation summary slots in
    # right after 立刻該做的事 so the reader can audit the AI's reasoning
    # without staring at Lucene syntax.
    body_lines = []
    if is_sample:
        body_lines += ["🧪 *測試資料*", "這是 Wazuh Sample Data，用來測試通知流程，不是真實攻擊。", ""]
    body_lines += [f"*哪台電腦 / 業務背景*\n{_context_markdown(ctx)}", "", f"*發生什麼事*\n{summary_zh}"]
    if impact_zh:
        body_lines += ["", f"📛 *不處理的後果*", impact_zh]
    body_lines += ["", f"🎯 *立刻該做的事*", next_step_zh]
    if investigation_zh:
        body_lines += ["", f"🔍 *AI 怎麼調查的*", investigation_zh]
    main_text = "\n".join(body_lines)

    # ── Technical fields (compact, for IT) ──
    fields = [
        {"title": "Wazuh Rule", "value": f"`{rule_id}` (level {level})", "short": True},
        {"title": "受影響主機 / Agent", "value": agent_label,             "short": True},
        {"title": "MITRE",      "value": str(mitre),                    "short": True},
        {"title": "IOCs",       "value": iocs_str,                       "short": True},
    ]
    if action_en := parsed.get("action"):
        fields.append({"title": "Technical action (for IT)", "value": action_en, "short": False})
    # Raw tool-call list — for IT only, demoted to the bottom of fields and
    # explicitly labelled so non-technical readers can skip it.
    if ev_text := _format_evidence_lines(evidence):
        fields.append({"title": "🛠 技術細節 (for IT) — AI 工具呼叫紀錄",
                       "value": ev_text,
                       "short": False})
    if full_log:
        snippet = full_log[:400] + ("…" if len(full_log) > 400 else "")
        fields.append({"title": "Raw log",
                       "value": f"```{snippet}```",
                       "short": False})

    return {
        "attachments": [{
            "color":     color,
            "title":     f"{'🧪 ' if is_sample else ''}{emoji} 【{sev_zh}】{ctx['name']} 需要確認",
            "pretext":   f"技術規則：{description}" if description else "",
            "text":      main_text,
            "fields":    fields,
            "footer":    f"EdgeSec-Pi · Wazuh + {LM_MODEL} 自動分流",
            "ts":        int(time.time()),
            "mrkdwn_in": ["text", "fields", "pretext"],
        }]
    }


def build_slack_blocks_payload(alert: dict[str, Any],
                               parsed: Optional[dict[str, Any]],
                               evidence: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Pure Block Kit version of the alert (no legacy `fields`).

    Used when posting via chat.postMessage with a bot token —
    Slack's API endpoint rejects payloads that mix legacy `fields`
    with new `blocks` (whereas incoming webhooks tolerate it).
    """
    parsed = parsed or {}
    severity = str(parsed.get("severity", "info")).lower().strip()
    color, emoji = SEVERITY_STYLE.get(severity, SEVERITY_STYLE["info"])
    sev_zh = SEVERITY_TITLE_ZH.get(severity, "訊息")

    rule         = alert.get("rule")  or {}
    rule_id      = rule.get("id", "?")
    level        = rule.get("level", "?")
    description  = rule.get("description", "")
    ctx          = _asset_context(alert)
    is_sample    = _is_sample_alert(alert)

    agent        = alert.get("agent") or {}
    agent_label  = agent.get("name", "?")
    if ip := agent.get("ip"):
        agent_label = f"{agent_label} ({ip})"

    summary_zh   = (parsed.get("summary_zh")
                    or parsed.get("root_cause")
                    or "（LLM 未提供白話摘要）")
    impact_zh    = parsed.get("impact_zh") or ""
    next_step_zh = (parsed.get("next_step_zh")
                    or parsed.get("action")
                    or "（請聯絡 IT 評估）")
    # NEW: Management-readable「AI 做了什麼」一句話 — only present when
    # the agentic loop ran and the LLM filled investigation_summary_zh.
    investigation_zh = (parsed.get("investigation_summary_zh") or "").strip()

    iocs        = parsed.get("iocs") or []
    iocs_str    = ", ".join(f"`{i}`" for i in iocs) if iocs else "_(無)_"
    mitre       = parsed.get("mitre") or "—"
    full_log    = (alert.get("full_log") or "").strip()

    blocks: list[dict[str, Any]] = [
        {"type": "header",
         "text": {"type": "plain_text",
                  "text": _slack_plain(f"{'測試資料 · ' if is_sample else ''}{emoji} 【{sev_zh}】{ctx['name']} 需要確認")}},
    ]
    if is_sample:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": "🧪 *測試資料*\n這是 Wazuh Sample Data，用來測試通知流程，不是真實攻擊。"},
        })
    blocks += [
        {"type": "section",
         "text": {"type": "mrkdwn",
                  "text": f"*哪台電腦 / 業務背景*\n{_context_markdown(ctx)}"}},
        {"type": "section",
         "text": {"type": "mrkdwn", "text": f"*發生什麼事*\n{summary_zh}"}},
    ]
    if impact_zh:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn",
                     "text": f"📛 *不處理的後果*\n{impact_zh}"}
        })
    blocks.append({
        "type": "section",
        "text": {"type": "mrkdwn",
                 "text": f"🎯 *立刻該做的事*\n{next_step_zh}"}
    })
    # 🔍 AI 怎麼調查的 — management-readable narrative of what the AI looked at
    # and why the verdict follows. Goes immediately after "立刻該做的事"
    # so non-technical readers can audit the AI's reasoning without
    # parsing tool calls.
    if investigation_zh:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn",
                     "text": f"🔍 *AI 怎麼調查的*\n{investigation_zh}"}
        })
    blocks.append({"type": "divider"})

    # 4-field grid for IT-facing technical info (Block Kit native)
    blocks.append({
        "type": "section",
        "fields": [
            {"type": "mrkdwn",
             "text": f"*Wazuh Rule*\n`{rule_id}` (level {level})"},
            {"type": "mrkdwn",
             "text": f"*原始規則名稱*\n{description or '—'}"},
            {"type": "mrkdwn",
             "text": f"*受影響主機*\n{agent_label}"},
            {"type": "mrkdwn",
             "text": f"*MITRE / IOC*\n{mitre} / {iocs_str}"},
        ],
    })
    if action_en := parsed.get("action"):
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn",
                     "text": f"*Technical action (for IT)*\n{action_en}"}
        })
    if full_log:
        snippet = full_log[:380] + ("…" if len(full_log) > 380 else "")
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn",
                     "text": f"*Raw log*\n```{snippet}```"}
        })
    # Raw tool-call trace — demoted to a SMALL grey context block so IT
    # can audit which queries the agent ran, while the management-readable
    # 白話 summary above carries the actual story. Context elements
    # cap at 3000 chars per element.
    if ev_text := _format_evidence_lines(evidence):
        blocks.append({
            "type": "context",
            "elements": [{"type": "mrkdwn",
                          "text": f"_🛠 技術細節 (for IT) — AI 工具呼叫紀錄_\n{ev_text[:2700]}"}]
        })
    footer = f"EdgeSec-Pi · Wazuh + {LM_MODEL} 自動分流"
    if evidence:
        # Count actual tool calls (exclude the terminal submit_final_verdict)
        n_tools = sum(1 for e in evidence if e.get("tool") != "submit_final_verdict")
        footer += f" · 🧠 Agentic ({n_tools} tool call{'s' if n_tools != 1 else ''})"
    blocks.append({
        "type": "context",
        "elements": [{"type": "mrkdwn", "text": footer}]
    })

    return {"attachments": [{"color": color, "blocks": blocks}]}


def _build_configure_agent_button(agent_name: str) -> Optional[dict[str, Any]]:
    """Build the 'configure this agent' Slack URL button, or None when the
    feature is disabled / not applicable.

    Two visual states:
      • unprofiled → primary (blue) CTA "⚠️ 設定 <agent>"
      • profiled   → plain "查看 <agent> 設定"
    Both go to /admin/quick-add with a short-lived signed token, so the
    management user does not need to log in.
    """
    if not BRIDGE_PUBLIC_URL or not agent_name:
        return None
    try:
        token = admin_token.sign(agent_name)
    except Exception as e:                              # pragma: no cover
        log.warning("admin token sign failed: %r", e)
        return None

    profiled = org_profile.is_profiled(agent_name)
    from urllib.parse import quote, urlencode
    qs = urlencode({"agent": agent_name, "t": token})
    url = f"{BRIDGE_PUBLIC_URL}/admin/quick-add?{qs}"

    if profiled:
        return {
            "type": "button",
            "text": {"type": "plain_text", "text": "查看業務背景"},
            "url":  url,
        }
    return {
        "type":  "button",
        "style": "primary",
        "text":  {"type": "plain_text", "text": "補端點業務背景"},
        "url":   url,
    }


def _action_ip_candidates(alert: dict[str, Any], parsed: Optional[dict[str, Any]]) -> list[str]:
    """Return source IP candidates for emergency Slack actions."""
    candidates: list[str] = []
    for ip in slack_actions.extract_blockable_ips(parsed or {}):
        candidates.append(ip)

    data = alert.get("data") or {}
    for key in ("srcip", "src_ip", "source_ip"):
        ip = str(data.get(key) or "").strip()
        if ip and ip not in candidates:
            candidates.extend(slack_actions.extract_blockable_ips({"iocs": [ip]}))
    return candidates


def _has_valid_wazuh_agent_id(agent_id: Any) -> bool:
    text = str(agent_id or "").strip()
    return text.isdigit() and 3 <= len(text) <= 5


def _emergency_help_block(has_ip: bool) -> dict[str, Any]:
    ip_text = (
        "*封鎖來源 IP*：擋住外部來源，不是關掉公司電腦。\n"
        "*解除封鎖*：封錯或處理完成後才用，會恢復該來源連線。\n"
        if has_ip
        else "*封鎖來源 IP / 解除封鎖*：這則告警沒有來源 IP，所以不顯示這兩個動作。\n"
    )
    return {
        "type": "context",
        "elements": [{
            "type": "mrkdwn",
            "text": (
                "*緊急處理按鈕說明*\n"
                f"{ip_text}"
                "*隔離端點*：暫停這台電腦連線，可能影響使用者工作；只在疑似中毒或外洩時使用。"
            ),
        }],
    }


def _augment_with_action_buttons(payload: dict[str, Any],
                                 alert: dict[str, Any],
                                 parsed: Optional[dict[str, Any]]) -> dict[str, Any]:
    """Append emergency Slack actions and business-context shortcut."""
    elements: list[dict[str, Any]] = []
    agent_name = (alert.get("agent") or {}).get("name", "")
    agent_id   = (alert.get("agent") or {}).get("id", "?")
    action_ips = _action_ip_candidates(alert, parsed)
    can_run_emergency_actions = (
        slack_actions.is_enabled()
        and not _is_sample_alert(alert)
        and _has_valid_wazuh_agent_id(agent_id)
    )
    can_isolate_endpoint = can_run_emergency_actions and slack_actions.endpoint_isolation_enabled()

    # Emergency action buttons (bot mode only).
    # Skip sample data and non-Wazuh ids — Wazuh Active Response expects a
    # numeric 3-5 digit agent id, and test cards should never expose live actions.
    if can_run_emergency_actions:
        if action_ips:
            ip = action_ips[0]
            elements.append({
                "type":      "button",
                "action_id": "block_ip",
                "style":     "danger",
                "text":      {"type": "plain_text", "text": "封鎖來源 IP"},
                "value":     remote_action_tokens.issue("block_ip", agent_id, target=ip),
                "confirm": {
                    "title":   {"type": "plain_text", "text": "確認封鎖來源 IP？"},
                    "text":    {"type": "mrkdwn",
                                "text": (
                                    f"將在 *{agent_name or '這台電腦'}* 的防火牆封鎖 `{ip}`。\n"
                                    "用途：先擋住可疑外部來源，不是關掉公司自己的電腦。"
                                )},
                    "confirm": {"type": "plain_text", "text": "封鎖來源 IP"},
                    "deny":    {"type": "plain_text", "text": "取消"},
                },
            })
            elements.append({
                "type": "button",
                "action_id": "unblock_ip",
                "text": {"type": "plain_text", "text": "解除封鎖"},
                "value": remote_action_tokens.issue("unblock_ip", agent_id, target=ip),
                "confirm": {
                    "title": {"type": "plain_text", "text": "確認解除封鎖？"},
                    "text": {"type": "mrkdwn",
                             "text": (
                                 f"只有在確認 `{ip}` 封錯、或事件已處理完成時才使用。\n"
                                 "按下後，這個來源會恢復連線能力。"
                             )},
                    "confirm": {"type": "plain_text", "text": "解除封鎖"},
                    "deny": {"type": "plain_text", "text": "取消"},
                },
            })
        if can_isolate_endpoint:
            elements.append({
                "type": "button",
                "action_id": "isolate_endpoint",
                "style": "danger",
                "text": {"type": "plain_text", "text": "隔離端點"},
                "value": remote_action_tokens.issue("isolate_endpoint", agent_id, target=agent_name),
                "confirm": {
                    "title": {"type": "plain_text", "text": "確認隔離這台電腦？"},
                    "text": {"type": "mrkdwn",
                             "text": (
                                 f"這會嘗試暫停 *{agent_name or '這台電腦'}* 的網路連線，"
                                 "避免疑似中毒或外洩擴大。\n"
                                 "風險：使用者可能立刻不能工作；若是重要服務，可能影響營運。"
                             )},
                    "confirm": {"type": "plain_text", "text": "隔離端點"},
                    "deny": {"type": "plain_text", "text": "取消"},
                },
            })

    # Configure-agent button (new, works in webhook mode too).
    cfg_btn = None if _is_sample_alert(alert) else _build_configure_agent_button(agent_name)
    if cfg_btn:
        elements.append(cfg_btn)

    if not elements:
        return payload

    # Inject into the existing attachment (so color stripe stays).
    att = payload["attachments"][0]
    blocks = att.get("blocks", [])
    if can_run_emergency_actions:
        blocks.append(_emergency_help_block(bool(action_ips)))
    att["blocks"] = blocks + [{"type": "actions", "elements": elements}]
    return payload


def build_quick_slack_payload(alert: dict[str, Any],
                                 parsed: Optional[dict[str, Any]]) -> dict[str, Any]:
    """Minimal attachment payload for quick (Stage-1 only / pipe) mode.

    What it includes:
      - Severity colour + emoji + 中文 severity label
      - Rule description (header)
      - summary_zh / impact_zh / next_step_zh (management-readable Chinese only)
      - Simple footer attribution

    What it DOES NOT include (unlike the deep mode payload):
      - No action buttons (Block IP / Configure Agent)
      - No tool-call traces
      - No IOC list / MITRE / raw log / technical action
      - No agent name in the body (only in footer)

    This is the "pipe" output — one-shot, no interactivity, just the verdict.
    """
    parsed = parsed or {}
    severity = str(parsed.get("severity", "info")).lower().strip()
    color, emoji = SEVERITY_STYLE.get(severity, SEVERITY_STYLE["info"])
    sev_zh = SEVERITY_TITLE_ZH.get(severity, "訊息")

    rule = alert.get("rule") or {}
    description = rule.get("description", "")
    ctx = _asset_context(alert)
    is_sample = _is_sample_alert(alert)

    summary_zh = (parsed.get("summary_zh")
                  or parsed.get("root_cause")
                  or "（LLM 未提供摘要）")
    impact_zh = parsed.get("impact_zh") or ""
    next_step_zh = (parsed.get("next_step_zh")
                    or parsed.get("action")
                    or "（請聯絡 IT 評估）")

    body_lines = []
    if is_sample:
        body_lines += ["🧪 *測試資料*", "這是 Wazuh Sample Data，用來測試通知流程，不是真實攻擊。", ""]
    body_lines += [f"*哪台電腦 / 業務背景*\n{_context_markdown(ctx)}", "", f"*發生什麼事*\n{summary_zh}"]
    if impact_zh:
        body_lines += ["", f"📛 *不處理的後果*\n{impact_zh}"]
    body_lines += ["", f"🎯 *立刻該做的事*\n{next_step_zh}"]

    return {
        "attachments": [{
            "color":     color,
            "title":     f"{'🧪 ' if is_sample else ''}{emoji} 【{sev_zh}】{ctx['name']} 需要確認",
            "pretext":   f"技術規則：{description}" if description else "",
            "text":      "\n".join(body_lines),
            "footer":    f"EdgeSec-Pi · Wazuh + {LM_MODEL} 快速分流",
            "ts":        int(time.time()),
            "mrkdwn_in": ["text", "title"],
        }]
    }


def build_quick_slack_blocks_payload(alert: dict[str, Any],
                                      parsed: Optional[dict[str, Any]]) -> dict[str, Any]:
    """Minimal Block Kit payload for quick (Stage-1 only / pipe) mode.

    Same content policy as build_quick_slack_payload — management-readable Chinese
    only, no action buttons, no tool traces, no technical fields.

    Used when posting via chat.postMessage with a bot token.
    """
    parsed = parsed or {}
    severity = str(parsed.get("severity", "info")).lower().strip()
    color, emoji = SEVERITY_STYLE.get(severity, SEVERITY_STYLE["info"])
    sev_zh = SEVERITY_TITLE_ZH.get(severity, "訊息")

    rule = alert.get("rule") or {}
    description = rule.get("description", "")
    ctx = _asset_context(alert)
    is_sample = _is_sample_alert(alert)

    summary_zh = (parsed.get("summary_zh")
                  or parsed.get("root_cause")
                  or "（LLM 未提供摘要）")
    impact_zh = parsed.get("impact_zh") or ""
    next_step_zh = (parsed.get("next_step_zh")
                    or parsed.get("action")
                    or "（請聯絡 IT 評估）")

    blocks: list[dict[str, Any]] = [
        {"type": "header",
         "text": {"type": "plain_text",
                  "text": _slack_plain(f"{'測試資料 · ' if is_sample else ''}{emoji} 【{sev_zh}】{ctx['name']} 需要確認")}},
    ]
    if is_sample:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": "🧪 *測試資料*\n這是 Wazuh Sample Data，用來測試通知流程，不是真實攻擊。"},
        })
    blocks += [
        {"type": "section",
         "text": {"type": "mrkdwn",
                  "text": f"*哪台電腦 / 業務背景*\n{_context_markdown(ctx)}"}},
        {"type": "section",
         "text": {"type": "mrkdwn", "text": f"*發生什麼事*\n{summary_zh}"}},
    ]
    if impact_zh:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn",
                     "text": f"📛 *不處理的後果*\n{impact_zh}"}
        })
    blocks.append({
        "type": "section",
        "text": {"type": "mrkdwn",
                 "text": f"🎯 *立刻該做的事*\n{next_step_zh}"}
    })
    blocks.append({
        "type": "context",
        "elements": [{"type": "mrkdwn",
                      "text": f"EdgeSec-Pi · Wazuh + {LM_MODEL} 快速分流"}]
    })

    return {"attachments": [{"color": color, "blocks": blocks}]}


async def send_to_slack(alert: dict[str, Any],
                        parsed: Optional[dict[str, Any]],
                        client: httpx.AsyncClient,


                        evidence: list[dict[str, Any]] | None = None,
                        quick_mode: bool | None = None) -> None:
    """Fire-and-forget Slack notification.





    Two message layouts depending on mode:
      • **Quick mode** (evidence is None / falsy by default):
        Minimal management-readable Chinese only — no action buttons, no tool traces,
        no technical fields (IOC/MITRE/raw log). Footer says "快速分流".
      • **Deep mode** (evidence is a non-empty list):
        Full payload with action buttons, tool-call traces, technical IT fields.
        Footer says "自動分流" with tool-call count.

    Two transport modes:
      - bot mode (SLACK_BOT_TOKEN+APP_TOKEN+CHANNEL_ID set): post via
        chat.postMessage; messages get interactive 🔒 Block buttons (deep mode only).
      - webhook mode (SLACK_WEBHOOK_URL set): post via incoming webhook;
        no buttons (incoming webhooks can't receive callbacks).

    Both modes silent-skip if neither is configured. Failures never
    block the analysis pipeline.

    `parsed` is the LLM verdict dict (already parsed by the caller — analyze()
    owns parsing so this module stays free of prompting concerns). May be None
    when Stage-1 failed to parse; renderers fall back to defaults.

    `evidence`, when supplied, is the agentic loop's tool-call trace —


    its presence (non-None non-empty) triggers deep mode; absence (None or [])
    triggers quick mode. The explicit `quick_mode` parameter, if set, overrides
    this auto-detection."""
    # ── Mode selection ──────────────────────────────────────────────
    is_deep: bool
    if quick_mode is not None:
        is_deep = not quick_mode
    else:
        # Auto-detect: deep mode iff evidence is a non-empty list
        is_deep = bool(evidence)

    if slack_actions.is_enabled():



        if is_deep:
            payload = build_slack_blocks_payload(alert, parsed, evidence=evidence)
        else:
            payload = build_quick_slack_blocks_payload(alert, parsed)
        payload = _augment_with_action_buttons(payload, alert, parsed)
        try:
            res = await slack_actions.post_alert(payload["attachments"])
            ts = (res or {}).get("ts")
            if ts:

                log.info("slack bot post ok ts=%s mode=%s",
                         ts, "deep" if is_deep else "quick")
            else:
                log.warning("slack bot post returned no ts (likely failed; see prior warning)")
        except Exception as e:
            log.warning("slack bot post failed: %s", e)
        return


    if is_deep:
        payload = build_slack_payload(alert, parsed, evidence=evidence)
    else:
        payload = build_quick_slack_payload(alert, parsed)
    if SLACK_WEBHOOK_URL:
        try:
            r = await client.post(SLACK_WEBHOOK_URL, json=payload, timeout=SLACK_TIMEOUT_S)
            if r.status_code != 200:
                log.warning("slack notify HTTP %d: %s", r.status_code, r.text[:200])
            else:

                log.info("slack notify ok mode=%s", "deep" if is_deep else "quick")
        except Exception as e:
            log.warning("slack notify failed: %s", e)
