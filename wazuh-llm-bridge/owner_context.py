"""Owner-facing endpoint context for notifications.

Keep this module free of Slack, LINE, Wazuh API, and active-response imports.
It is used by every notification channel, so importing it must not require any
external service credentials.
"""
from __future__ import annotations

import ipaddress
from typing import Any

import org_profile


CRITICALITY_TITLE_ZH: dict[str, str] = {
    "critical": "關鍵",
    "high": "高",
    "medium": "中",
    "low": "低",
}


def _agent_name(alert: dict[str, Any]) -> str:
    return str((alert.get("agent") or {}).get("name") or "未知電腦")


def _display_agent_ip(raw_ip: Any) -> str:
    ip = str(raw_ip or "").strip().strip("`")
    if not ip or ip.lower() == "any":
        return ""
    try:
        parsed = ipaddress.ip_address(ip)
        if parsed.is_loopback:
            return ""
        return str(parsed)
    except ValueError:
        return ip


def _compact_business_note(raw_note: Any) -> str:
    note = " ".join(str(raw_note or "").split())
    if not note:
        return ""
    lowered = note.lower()
    technical_noise = ("localhost", "loopback", "127.0.0.1", "::1", "0000:0000")
    if any(marker in lowered for marker in technical_noise):
        return ""
    return note if len(note) <= 70 else note[:69] + "…"


def asset_context(alert: dict[str, Any]) -> dict[str, str]:
    """Return compact endpoint context suitable for non-technical readers."""
    agent = alert.get("agent") or {}
    name = _agent_name(alert)
    asset = org_profile.find_asset(name) or {}
    role = str(asset.get("role") or "尚未設定").strip()
    owner = str(asset.get("owner") or asset.get("responsible") or "尚未指定").strip()
    criticality_raw = str(asset.get("criticality") or "").strip().lower()
    criticality = CRITICALITY_TITLE_ZH.get(criticality_raw, criticality_raw or "尚未設定")
    return {
        "name": name,
        "ip": _display_agent_ip(agent.get("ip")),
        "role": role,
        "owner": owner,
        "criticality": criticality,
        "hours": str(asset.get("business_hours") or "").strip(),
        "notes": _compact_business_note(asset.get("notes")),
        "profiled": "yes" if asset else "no",
    }


def management_context_lines(alert: dict[str, Any], *, markdown: bool = True) -> list[str]:
    ctx = asset_context(alert)

    def label(name: str, value: str) -> str:
        return f"*{name}：* {value}" if markdown else f"{name}：{value}"

    computer = ctx["name"] + (f"（IP：{ctx['ip']}）" if ctx.get("ip") else "")
    lines = [label("電腦", computer), label("用途", ctx["role"])]
    if ctx.get("owner") and ctx["owner"] != "尚未指定":
        lines.append(label("負責人", ctx["owner"]))
    lines.append(label("重要程度", ctx["criticality"]))
    if ctx.get("hours"):
        lines.append(label("使用時段", ctx["hours"]))
    if ctx.get("notes"):
        lines.append(label("說明", ctx["notes"]))
    elif ctx.get("profiled") != "yes":
        lines.append("尚未設定業務用途，建議先補上，之後告警會更準。")
    return lines


def context_markdown(ctx: dict[str, str]) -> str:
    computer = ctx["name"] + (f"（IP：{ctx['ip']}）" if ctx.get("ip") else "")
    lines = [
        f"*電腦：* {computer}",
        f"*用途：* {ctx['role']}",
        f"*重要程度：* {ctx['criticality']}",
    ]
    if ctx.get("owner") and ctx["owner"] != "尚未指定":
        lines.insert(2, f"*負責人：* {ctx['owner']}")
    if ctx.get("hours"):
        lines.append(f"*使用時段：* {ctx['hours']}")
    if ctx.get("notes"):
        lines.append(f"*說明：* {ctx['notes']}")
    elif ctx.get("profiled") != "yes":
        lines.append("尚未設定業務用途，建議先補上，之後告警會更準。")
    return "\n".join(lines)
