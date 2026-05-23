"""
/dashboard — 管理層使用的唯讀風險摘要頁。

這一層刻意不取代 Wazuh Dashboard。Wazuh 保留給 IT 深查原始事件；
EdgeSec-Pi Dashboard 只回答管理者真正需要知道的幾件事：
今天有沒有風險、哪些事件需要 IT 處理、系統本身是否還健康。
"""
from __future__ import annotations

import html
import ipaddress
import json
import os
import time
from datetime import datetime
from typing import Any
from urllib.parse import quote, urljoin

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse

import db
import admin_token
import dashboard_assets
import dashboard_model
import digest
import notify_channels
import org_profile

router = APIRouter()

SIEM_DASHBOARD_URL = os.getenv("SIEM_DASHBOARD_URL", "").rstrip("/")
DASHBOARD_V2_URL = os.getenv("DASHBOARD_V2_URL", "").rstrip("/")
WAZUH_AGENT_VERSION = os.getenv("WAZUH_VERSION", "4.14.5").lstrip("v")
MANAGER_HOST = os.getenv("MANAGER_HOST", "localhost")
PROFILE_LINK_TTL_S = int(os.getenv("PROFILE_LINK_TTL_S", "28800"))


def _esc(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _dashboard_v2_redirect_url(request: Request) -> str:
    """Translate legacy bridge dashboard links to the Next.js dashboard.

    The release UI lives in dashboard/.  The bridge keeps /dashboard as a
    compatibility entry point for old bookmarks and Slack links, but it should
    no longer render a second management UI.
    """
    view = (request.query_params.get("view") or "today").strip().lower()
    path_by_view = {
        "today": "/",
        "services": "/settings/endpoints",
        "setup": "/settings/status",
        "platform": "/settings/status",
        "advanced": "/settings/testing",
        "notifications": "/settings/notifications",
        "testing": "/settings/testing",
        "status": "/settings/status",
    }
    target_path = path_by_view.get(view, "/")
    anchor = request.url.fragment
    target = urljoin(f"{DASHBOARD_V2_URL}/", target_path.lstrip("/"))
    return f"{target}#{anchor}" if anchor else target


def _fmt_time(epoch: float | int | None) -> str:
    if not epoch:
        return "未知時間"
    return datetime.fromtimestamp(float(epoch)).strftime("%m/%d %H:%M")


def _fmt_sync_time(value: Any) -> str:
    if not value:
        return "未知"
    if isinstance(value, (int, float)):
        return _fmt_time(value)
    raw = str(value).strip()
    if not raw:
        return "未知"
    try:
        normalized = raw.replace("Z", "+00:00")
        if len(normalized) > 5 and normalized[-5] in {"+", "-"} and normalized[-3] != ":":
            normalized = f"{normalized[:-2]}:{normalized[-2:]}"
        parsed = datetime.fromisoformat(normalized)
        if parsed.year >= 2100:
            return "不適用"
        return parsed.strftime("%m/%d %H:%M")
    except Exception:
        return raw[:16]


def _fmt_agent_version(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return "未知"
    return raw if raw.lower().startswith("wazuh") else f"Wazuh {raw}"


def _fmt_os_name(platform: Any, version: Any = "") -> str:
    raw_platform = str(platform or "").strip()
    raw_version = str(version or "").strip()
    lowered = raw_platform.lower()

    names = {
        "darwin": "macOS",
        "macos": "macOS",
        "mac": "macOS",
        "ubuntu": "Ubuntu Linux",
        "debian": "Debian Linux",
        "amzn": "Amazon Linux",
        "amazon": "Amazon Linux",
        "centos": "CentOS Linux",
        "rhel": "Red Hat Enterprise Linux",
        "redhat": "Red Hat Enterprise Linux",
        "rocky": "Rocky Linux",
        "almalinux": "AlmaLinux",
        "fedora": "Fedora Linux",
        "windows": "Windows",
        "win32": "Windows",
        "linux": "Linux",
    }
    label = names.get(lowered) or (raw_platform[:1].upper() + raw_platform[1:] if raw_platform else "未知")
    return f"{label} {raw_version}" if raw_version else label


def _extract_llm_json(row: dict[str, Any]) -> dict[str, Any]:
    raw = row.get("llm_raw_reply") or ""
    if not raw:
        return {}
    try:
        data = json.loads(raw)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _srcip(row: dict[str, Any]) -> str:
    try:
        raw = json.loads(row.get("raw_alert") or "{}")
        data = raw.get("data") or {}
        return str(data.get("srcip") or "")
    except Exception:
        return ""


def _management_fallback(row: dict[str, Any]) -> dict[str, str]:
    try:
        raw = json.loads(row.get("raw_alert") or "{}")
    except Exception:
        raw = {}
    data = raw.get("data") or {}
    rule_id = str(row.get("rule_id") or "")
    agent = row.get("agent_name") or "受監控設備"
    srcip = data.get("srcip") or _srcip(row) or "不明來源"
    user = data.get("srcuser") or data.get("dstuser") or ""

    if rule_id in {"5712", "5763"}:
        target = f"帳號「{user}」" if user else "某個帳號"
        return {
            "summary": f"有人從外部 IP（{srcip}）多次嘗試登入 {agent} 的{target}。",
            "impact": "如果對方猜中密碼，可能會進入系統竊取資料、破壞服務或安裝後門程式。",
            "next_step": f"請 IT 在 Wazuh 查詢來源 IP {srcip}，確認是否有登入成功，並評估是否封鎖該 IP。",
        }

    return {
        "summary": row.get("rule_description") or "偵測到一筆需要 IT 確認的資安事件。",
        "impact": "若這不是預期行為，可能代表系統設定異常或有人嘗試未授權存取。",
        "next_step": "請 IT 到 Wazuh 查看原始告警，確認是否需要處理。",
    }



def _event_summary(row: dict[str, Any]) -> dict[str, str]:
    parsed = _extract_llm_json(row)
    fallback = _management_fallback(row)
    return {
        "summary": (
            parsed.get("summary_zh")
            or fallback["summary"]
        ),
        "impact": parsed.get("impact_zh") or fallback["impact"],
        "next_step": parsed.get("next_step_zh") or fallback["next_step"],
    }


def _management_action_text(value: str) -> str:
    text = str(value or "").strip()
    replacements = {
        "請 IT 在 Wazuh 查詢": "請負責人確認",
        "請 IT": "請負責人",
        "聯絡 IT": "聯絡負責人",
        "Wazuh": "進階系統",
        "Dashboard": "通知頁面",
        "Slack": "通知",
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    return text


def _event_account(row: dict[str, Any]) -> str:
    try:
        raw = json.loads(row.get("raw_alert") or "{}")
    except Exception:
        raw = {}
    data = raw.get("data") or {}
    return str(data.get("srcuser") or data.get("dstuser") or "").strip()


def _management_item_title(row: dict[str, Any], agent_name: str) -> str:
    rule_id = str(row.get("rule_id") or "")
    account = _event_account(row)
    subject = agent_name.strip() or "這台端點"
    if rule_id in {"5712", "5763"}:
        target = f"帳號「{account}」" if account else "帳號"
        return f"{subject} 出現多次登入嘗試，請確認{target}是否為正常操作。"
    return f"{subject} 有一項異常需要確認。"


def _management_impact(row: dict[str, Any]) -> str:
    rule_id = str(row.get("rule_id") or "")
    if rule_id in {"5712", "5763"}:
        return "若登入成功，可能影響資料安全或服務穩定。"
    text = _event_summary(row)
    return str(text["impact"])


def _management_recommendation(row: dict[str, Any]) -> str:
    rule_id = str(row.get("rule_id") or "")
    if rule_id in {"5712", "5763"}:
        return "請確認登入是否成功；若不是公司操作，封鎖來源並回報。"
    return _management_action_text(_event_summary(row)["next_step"])


def _management_steps(row: dict[str, Any], assignee: str, ip: str) -> list[str]:
    rule_id = str(row.get("rule_id") or "")
    account = _event_account(row)
    owner = str(assignee or "").strip()
    confirm_owner = f"請 {owner} 確認" if owner and owner != "尚未指派" else "請實際使用這台電腦的人確認"
    if rule_id in {"5712", "5763"}:
        target = f"帳號「{account}」" if account else "這個帳號"
        source = f"來源 IP {ip}" if ip else "來源 IP"
        return [
            f"確認：{confirm_owner}{target}是否有人成功登入。",
            f"處理：若不是公司操作，封鎖{source}。",
            "結案：在右側按「正常操作」、「已處理」或「誤報」。",
        ]
    return [
        "確認：判斷是否為公司預期操作。",
        "處理：依建議修復或排除誤報。",
        "結案：在右側更新處理結果。",
    ]


def _case_status_label(value: Any) -> tuple[str, str]:
    status = str(value or "open").strip().lower()
    labels = {
        "open": ("待確認", "case-open"),
        "in_progress": ("處理中", "case-progress"),
        "normal": ("正常操作", "case-closed"),
        "resolved": ("已處理", "case-closed"),
        "false_positive": ("誤報", "case-closed"),
    }
    return labels.get(status, ("待確認", "case-open"))


def _case_action_button(alert_id: int, status: str, label: str, group_ids: list[int] | None = None) -> str:
    group_value = ",".join(str(item) for item in (group_ids or []) if item)
    return f"""
    <form method="post" action="/dashboard/alerts/{_esc(alert_id)}/case#today-tasks" class="case-form">
      <input type="hidden" name="status" value="{_esc(status)}">
      <input type="hidden" name="group_ids" value="{_esc(group_value)}">
      <button type="submit">{_esc(label)}</button>
    </form>
    """


def _event_group_key(row: dict[str, Any]) -> tuple[str, str, str, str, str]:
    ts = float(row.get("received_at") or 0)
    day = datetime.fromtimestamp(ts).strftime("%Y-%m-%d") if ts else "unknown-day"
    agent_name = str(row.get("agent_name") or "未知設備").strip()
    rule_id = str(row.get("rule_id") or row.get("rule_description") or "unknown-rule").strip()
    srcip = _srcip(row).strip()
    account = _event_account(row).strip()
    indicator = srcip or account or str(row.get("llm_mitre") or "").strip()
    return day, agent_name, rule_id, account, indicator


def _collapse_event_groups(rows: list[dict[str, Any]], limit: int = 8) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
    ordered = sorted(rows, key=lambda r: r.get("received_at") or 0, reverse=True)
    for row in ordered:
        key = _event_group_key(row)
        row_id = int(row.get("id") or 0)
        ts = float(row.get("received_at") or 0)
        group = groups.get(key)
        if not group:
            group = dict(row)
            group["_group_count"] = 0
            group["_group_ids"] = []
            group["_group_first_at"] = ts
            group["_group_last_at"] = ts
            groups[key] = group
        group["_group_count"] = int(group.get("_group_count") or 0) + 1
        if row_id:
            group["_group_ids"].append(row_id)
        group["_group_first_at"] = min(float(group.get("_group_first_at") or ts), ts)
        group["_group_last_at"] = max(float(group.get("_group_last_at") or ts), ts)
        if str(row.get("case_status") or "").lower() == "in_progress":
            group["case_status"] = "in_progress"

    def sort_key(row: dict[str, Any]) -> tuple[int, float]:
        severity = str(row.get("llm_severity") or "").lower()
        return dashboard_model.SEVERITY_WEIGHT.get(severity, 0), float(row.get("_group_last_at") or row.get("received_at") or 0)

    return sorted(groups.values(), key=sort_key, reverse=True)[:limit]



def _render_events(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return """
        <div class="empty-state">
          <strong>今天沒有需要回報的事項。</strong>
          <span>系統仍會持續監控，低風險紀錄保留在進階查詢。</span>
        </div>
        """

    parts: list[str] = []
    for row in rows[:3]:
        sev = (row.get("llm_severity") or "unclassified").lower()
        text = _event_summary(row)
        agent_name = str(row.get("agent_name") or "未知設備")
        asset = org_profile.find_asset(agent_name) or {}
        service_label = asset.get("role") or _fallback_agent_role(agent_name, "")
        summary = _management_item_title(row, agent_name)
        impact = _management_impact(row)
        action = _management_recommendation(row)
        assignee = asset.get("owner") or asset.get("contact") or ""
        has_business_context = bool(asset)
        profile_token = admin_token.sign(agent_name, ttl_s=PROFILE_LINK_TTL_S)
        profile_url = f"/admin/quick-add?agent={quote(agent_name)}&t={quote(profile_token)}"
        due = "今天"
        ip = _srcip(row)
        steps = _management_steps(row, assignee, ip)
        account = _event_account(row)
        row_id = int(row.get("id") or 0)
        group_count = int(row.get("_group_count") or 1)
        group_ids = [int(item) for item in (row.get("_group_ids") or [row_id]) if int(item or 0) > 0]
        case_label, case_class = _case_status_label(row.get("case_status"))
        if has_business_context:
            next_title = f"確認「{account}」是否本人登入" if account else "確認是否為公司操作"
            next_note = "確認後，直接按下方按鈕更新狀態。"
        else:
            next_title = "先設定業務用途"
            next_note = "設定後，告警才知道要找誰確認。"
        iocs = row.get("llm_iocs")
        if isinstance(iocs, list) and iocs:
            ioc_text = ", ".join(str(x) for x in iocs[:4])
        else:
            ioc_text = ip or "無明確 IOC"

        event_time = _fmt_time(row.get("received_at"))
        date_part, _, time_part = event_time.partition(" ")
        severity = dashboard_model.severity_label(sev)
        severity_class = "risk-high" if sev in {"critical", "high"} else ("risk-medium" if sev == "medium" else "risk-info")
        repeated_html = (
            f'<span class="repeat-pill">同類事件 {group_count} 次</span>'
            if group_count > 1
            else ""
        )
        tech_group_html = (
            f"""
                <span>同類事件</span><code>{_esc(group_count)} 次，按右側狀態會一起更新</code>
                <span>最早時間</span><code>{_esc(_fmt_time(row.get("_group_first_at")))}</code>
                <span>最新時間</span><code>{_esc(_fmt_time(row.get("_group_last_at")))}</code>
            """
            if group_count > 1
            else ""
        )
        parts.append(f"""
        <article class="cal-task cal-task-{_esc(sev)}">
          <div class="task-time">
            <span>{_esc(date_part or event_time)}</span>
            <strong>{_esc(time_part or "")}</strong>
          </div>
          <div class="task-body">
            <div class="task-meta">
              <span class="risk-pill {severity_class}">{_esc(severity)}</span>
              <span>用途：{_esc(service_label)}</span>
              <span>期限 { _esc(due) }</span>
              {repeated_html}
            </div>
            <h3>{_esc(summary)}</h3>
            <p>{_esc(impact)}</p>
            <div class="task-action">
              <span>管理者要做</span>
              <strong>{_esc(action)}</strong>
              <ol class="task-steps">
                {"".join(f"<li>{_esc(step)}</li>" for step in steps)}
              </ol>
            </div>
            <details class="todo-tech">
              <summary>技術資料</summary>
              <div class="tech-grid">
                <span>原始說明</span><code>{_esc(text["summary"])}</code>
                <span>設備</span><code>{_esc(agent_name)}</code>
                <span>指標</span><code>{_esc(ioc_text)}</code>
                <span>rule.id</span><code>{_esc(row.get("rule_id"))}</code>
                <span>MITRE</span><code>{_esc(row.get("llm_mitre") or "未標註")}</code>
                {tech_group_html}
              </div>
            </details>
          </div>
          <div class="task-owner">
            <span>現在要做</span>
            <strong>{_esc(next_title)}</strong>
            {f'<a class="owner-link" href="{_esc(profile_url)}">設定業務用途</a>' if not has_business_context else ''}
            <div class="case-status {case_class}">{_esc(case_label)}</div>
            <div class="case-actions" aria-label="更新處理狀態">
              {_case_action_button(row_id, "normal", "正常操作", group_ids)}
              {_case_action_button(row_id, "in_progress", "交給 IT", group_ids)}
              {_case_action_button(row_id, "resolved", "已處理", group_ids)}
              {_case_action_button(row_id, "false_positive", "誤報", group_ids)}
            </div>
            <div class="reply-note">{_esc(next_note)}</div>
          </div>
        </article>
        """)
    return f'<div class="task-list">{"".join(parts)}</div>'


def _render_status(
    status: dict[str, Any],
    queue_size: int,
    queue_max: int,
    pending_items: int,
) -> str:
    wazuh = status.get("wazuh") or {}
    agents = status.get("agents") or {}
    cve = status.get("cve_feed") or {}

    version = wazuh.get("manager_version") or "未知"
    version_status = "最新" if wazuh.get("version_status") == "current" else "需確認"
    active = int(agents.get("active") or 0)
    total = int(agents.get("total") or 0)
    disconnected = int(agents.get("disconnected") or 0)
    details = agents.get("details") or []
    missing_profiles = sum(1 for agent in details if not org_profile.find_asset(str(agent.get("name") or "")))
    cve_status = cve.get("status") or "unknown"

    cve_label = "正常" if cve_status == "fresh" else "需確認"
    rows = [
        ("通知與分析", "正常" if queue_size == 0 else "需確認", "ok" if queue_size == 0 else "warn", f"待分析 {queue_size} 件"),
        ("待確認事項", f"{pending_items} 項", "ok" if pending_items == 0 else "warn", "需要確認是否為正常操作"),
        ("服務資料", f"{missing_profiles} 項待補", "ok" if missing_profiles == 0 else "warn", "補上後可顯示業務影響"),
        ("進階資料", cve_label, "ok" if cve_status == "fresh" and version_status == "最新" and disconnected == 0 else "warn", f"平台 {version}，離線 {disconnected} 台"),
    ]
    return "\n".join(
        f"""
        <div class="status-row">
          <span class="dot dot-{state}"></span>
          <span>{_esc(name)}</span>
          <strong>{_esc(value)}</strong>
          <small>{_esc(detail)}</small>
        </div>
        """
        for name, value, state, detail in rows
    )



def _criticality_label(value: Any) -> str:
    labels = {
        "critical": "關鍵",
        "high": "重要",
        "medium": "一般",
        "low": "低影響",
    }
    return labels.get(str(value or "").lower(), "未設定")


def _fmt_business_hours(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return "使用時段未設定"
    replacements = {
        "Mon-Fri": "週一至週五",
        "Mon-Thu": "週一至週四",
        "Sat-Sun": "週末",
        "Daily": "每日",
        "Asia/Taipei": "",
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    return " ".join(text.split())


def _format_ip(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return "未知"
    try:
        parsed = ipaddress.ip_address(raw)
        label = str(parsed)
        return f"本機位址 ({label})" if parsed.is_loopback else label
    except ValueError:
        return raw


def _fallback_agent_role(name: str, os_platform: str) -> str:
    lowered = f"{name} {os_platform}".lower()
    if "manager" in lowered or "wazuh.manager" in lowered:
        return "資安監控核心"
    return "尚未設定用途"



def _agent_download_url(kind: str) -> str:
    version = WAZUH_AGENT_VERSION
    urls = {
        "windows": f"https://packages.wazuh.com/4.x/windows/wazuh-agent-{version}-1.msi",
        "mac_arm": f"https://packages.wazuh.com/4.x/macos/wazuh-agent-{version}-1.arm64.pkg",
        "mac_intel": f"https://packages.wazuh.com/4.x/macos/wazuh-agent-{version}-1.intel64.pkg",
        "linux_deb": f"https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_{version}-1_amd64.deb",
        "linux_rpm": f"https://packages.wazuh.com/4.x/yum/wazuh-agent-{version}-1.x86_64.rpm",
    }
    return urls[kind]


def _notification_panel() -> str:
    slack_ready, slack_interactive, line_ready, telegram_ready, email_ready = _notification_status()
    slack_tested = bool(notify_channels.get_config("SLACK_TESTED_AT"))
    line_tested = bool(notify_channels.get_config("LINE_TESTED_AT"))
    telegram_tested = bool(notify_channels.get_config("TELEGRAM_TESTED_AT"))
    email_tested = bool(notify_channels.get_config("EMAIL_TESTED_AT"))
    notification_token = admin_token.sign("__notifications__")
    notification_url = f"/admin/notifications?t={quote(notification_token)}"
    return f"""
    <section class="cal-panel notification-card">
      <div class="cal-panel-head">
        <div>
          <h2>通知設定</h2>
          <p>先確認告警會送到哪裡；這是上線後第一件事。</p>
        </div>
        <a class="secondary-action" href="{_esc(notification_url)}">通知設定</a>
      </div>
      <div class="notification-list">
        <div><span>LINE</span><strong>{'測試成功' if line_tested else ('待測試' if line_ready else '未設定')}</strong></div>
        <div><span>Slack</span><strong>{'測試成功' if slack_tested else ('待測試' if slack_ready else '未設定')}</strong></div>
        <div><span>Telegram</span><strong>{'測試成功' if telegram_tested else ('待測試' if telegram_ready else '未設定')}</strong></div>
        <div><span>Slack 互動按鈕</span><strong>{'可用' if slack_interactive else '未完成'}</strong></div>
        <div><span>Email</span><strong>{'測試成功' if email_tested else ('待測試' if email_ready else '未設定')}</strong></div>
      </div>
    </section>
    """


def _notification_status() -> tuple[bool, bool, bool, bool, bool]:
    slack_ready = bool(
        notify_channels.get_config("SLACK_WEBHOOK_URL")
        or (
            notify_channels.get_config("SLACK_BOT_TOKEN")
            and notify_channels.get_config("SLACK_APP_TOKEN")
            and notify_channels.get_config("SLACK_CHANNEL_ID")
        )
    )
    slack_interactive = bool(
        notify_channels.get_config("SLACK_BOT_TOKEN")
        and notify_channels.get_config("SLACK_APP_TOKEN")
        and notify_channels.get_config("SLACK_CHANNEL_ID")
    )
    line_ready = bool(
        notify_channels.get_config("LINE_CHANNEL_ACCESS_TOKEN")
        and notify_channels.get_config("LINE_USER_ID")
    )
    telegram_ready = bool(
        notify_channels.get_config("TELEGRAM_BOT_TOKEN")
        and notify_channels.get_config("TELEGRAM_CHAT_ID")
    )
    email_ready = bool(
        notify_channels.get_config("SMTP_HOST")
        and notify_channels.get_config("EMAIL_FROM")
        and notify_channels.get_config("EMAIL_TO")
    )
    return slack_ready, slack_interactive, line_ready, telegram_ready, email_ready


def _notification_tested_status() -> tuple[bool, str]:
    channels = [
        ("LINE", bool(_notification_status()[2]), notify_channels.get_config("LINE_TESTED_AT")),
        ("Slack", bool(_notification_status()[0]), notify_channels.get_config("SLACK_TESTED_AT")),
        ("Telegram", bool(_notification_status()[3]), notify_channels.get_config("TELEGRAM_TESTED_AT")),
        ("Email", bool(_notification_status()[4]), notify_channels.get_config("EMAIL_TESTED_AT")),
    ]
    tested = [f"{label} {tested_at}" for label, ready, tested_at in channels if ready and tested_at]
    if tested:
        return True, "、".join(tested)
    ready_labels = [label for label, ready, _ in channels if ready]
    if ready_labels:
        return False, f"{'、'.join(ready_labels)} 已填設定，但尚未測試成功"
    return False, "建議先設定 LINE，因為手機最容易確認有沒有收到。"


def _setup_step(status: str, title: str, body: str, href: str, action: str) -> str:
    labels = {"done": "完成", "active": "現在處理", "pending": "等待"}
    return f"""
    <li class="{_esc(status)}">
      <span>{_esc(labels.get(status, status))}</span>
      <strong>{_esc(title)}</strong>
      <p>{_esc(body)}</p>
      <a href="{_esc(href)}">{_esc(action)}</a>
    </li>
    """


def _render_agent_downloads() -> str:
    buttons = [
        ("Windows", "MSI", _agent_download_url("windows")),
        ("macOS", "Apple silicon", _agent_download_url("mac_arm")),
        ("macOS", "Intel", _agent_download_url("mac_intel")),
        ("Linux", "DEB", _agent_download_url("linux_deb")),
        ("Linux", "RPM", _agent_download_url("linux_rpm")),
    ]
    button_html = "\n".join(
        f"""
        <a class="download-button" href="{_esc(url)}" target="_blank" rel="noopener noreferrer">
          <span>{_esc(os_label)}</span>
          <strong>{_esc(package_label)}</strong>
        </a>
        """
        for os_label, package_label, url in buttons
    )
    mac_setup = f"""sudo sed -i '' 's/MANAGER_IP/{MANAGER_HOST}/g' /Library/Ossec/etc/ossec.conf
sudo /Library/Ossec/bin/agent-auth -m {MANAGER_HOST} -p 1515 -A "$(scutil --get ComputerName)"
sudo /Library/Ossec/bin/wazuh-control restart"""
    linux_deb_setup = f"""sudo WAZUH_MANAGER="{MANAGER_HOST}" dpkg -i ./wazuh-agent_{WAZUH_AGENT_VERSION}-1_amd64.deb
sudo systemctl enable --now wazuh-agent"""
    linux_rpm_setup = f"""sudo WAZUH_MANAGER="{MANAGER_HOST}" rpm -ihv ./wazuh-agent-{WAZUH_AGENT_VERSION}-1.x86_64.rpm
sudo systemctl enable --now wazuh-agent"""
    return f"""
    <details class="install-menu">
      <summary>安裝 Agent</summary>
      <div class="download-grid">
        <p class="install-hint">官方安裝檔不會自動知道 Manager，安裝後請指定：{_esc(MANAGER_HOST)}</p>
        {button_html}
        <details class="install-steps">
          <summary>macOS 安裝後設定</summary>
          <p>若狀態出現 <code>MANAGER_IP</code>，請在那台 Mac 執行：</p>
          <pre>{_esc(mac_setup)}</pre>
        </details>
        <details class="install-steps">
          <summary>Linux 安裝指令</summary>
          <p>Ubuntu / Debian：</p>
          <pre>{_esc(linux_deb_setup)}</pre>
          <p>RHEL / CentOS / Rocky：</p>
          <pre>{_esc(linux_rpm_setup)}</pre>
        </details>
      </div>
    </details>
    """


def _render_agent_inventory(status: dict[str, Any], events: list[dict[str, Any]] | None = None) -> str:
    all_agents = ((status.get("agents") or {}).get("details") or [])
    agents = [agent for agent in all_agents if not dashboard_model.is_manager_agent(agent)]
    risk_by_agent = dashboard_model.endpoint_risk_map(events or [])
    total_agents = len(agents)
    active_agents = sum(
        1 for agent in agents if str(agent.get("status") or "").strip().lower() == "active"
    )
    missing_profiles = sum(
        1 for agent in agents if not org_profile.find_asset(str(agent.get("name") or ""))
    )
    item_score_values = [
        dashboard_model.endpoint_item_score(
            agent,
            org_profile.find_asset(str(agent.get("name") or "")) or {},
            risk_by_agent.get(str(agent.get("name") or "")),
        )[0]
        for agent in agents
    ]
    endpoint_score, endpoint_label, endpoint_score_class, endpoint_note = dashboard_model.endpoint_score(
        item_score_values
    )
    install_menu = _render_agent_downloads()
    if not agents:
        return f"""
        <section class="section-card service-panel">
      <div class="section-head">
        <div class="section-title">
          <h2>電腦端點 (0)</h2>
          <p>目前沒有取得端點清單，請技術窗口確認 SIEM 連線。</p>
        </div>
            {install_menu}
          </div>
          <div class="empty-state compact">
            <strong>端點清單暫時不可用。</strong>
            <span>這不代表沒有風險，只代表監控清單沒有回傳。</span>
          </div>
        </section>
        """

    first_missing_agent = next(
        (str(agent.get("name") or "") for agent in agents if not org_profile.find_asset(str(agent.get("name") or ""))),
        "",
    )
    endpoint_action_href = (
        f"/admin/quick-add?agent={quote(first_missing_agent)}&t={quote(admin_token.sign(first_missing_agent, ttl_s=PROFILE_LINK_TTL_S))}"
        if first_missing_agent
        else "/dashboard?view=platform#self-test"
    )
    endpoint_action_text = "補端點背景" if first_missing_agent else "檢查平台狀態"
    offline_count = max(total_agents - active_agents, 0)
    endpoint_summary = (
        f"{offline_count} 台離線，{missing_profiles} 台缺背景"
        if offline_count or missing_profiles
        else "全部端點正常"
    )

    rows: list[str] = []
    for agent in agents:
        name = str(agent.get("name") or "未命名 Agent")
        state, _ = dashboard_model.agent_state(str(agent.get("status") or ""))
        asset = org_profile.find_asset(name) or {}
        item_score, item_score_label, item_score_class, item_score_reason = dashboard_model.endpoint_item_score(
            agent, asset, risk_by_agent.get(name)
        )
        item_score_breakdown = dashboard_model.endpoint_score_breakdown(agent, asset, risk_by_agent.get(name))
        item_score_breakdown_html = "".join(
            f"<div><span>{_esc(label)}</span><strong>{_esc(points)}</strong></div>"
            for label, points in item_score_breakdown
        )
        ip = _format_ip(agent.get("ip"))
        os_platform = agent.get("os_platform") or ""
        os_version = agent.get("os_version") or ""
        os_display = _fmt_os_name(os_platform, os_version)
        last_sync = _fmt_sync_time(agent.get("lastKeepAlive") or agent.get("last_keep_alive"))
        agent_version = _fmt_agent_version(agent.get("version") or agent.get("agent_version"))
        display_name = name
        role_label = asset.get("role") or "已設定"
        criticality = _criticality_label(asset.get("criticality"))
        business_hours = _fmt_business_hours(asset.get("business_hours"))
        notes = asset.get("notes") or ""
        profile_token = admin_token.sign(name, ttl_s=PROFILE_LINK_TTL_S)
        profile_url = f"/admin/quick-add?agent={quote(name)}&t={quote(profile_token)}"
        unprofiled = "" if asset else " agent-unprofiled"
        impact_cell = (
            f"""
            <div class="business-context">
              <div><b>用途</b><strong>{_esc(role_label)}</strong></div>
              <div><b>影響</b><strong>{_esc(criticality)}</strong></div>
              <div><b>時段</b><strong>{_esc(business_hours)}</strong></div>
              {f'<div><b>說明</b><strong>{_esc(notes)}</strong></div>' if notes else ''}
            </div>
            <a class="profile-link icon-link" href="{_esc(profile_url)}" title="編輯端點業務背景" aria-label="編輯端點業務背景">✎</a>
            """
            if asset
            else f"""
            <div class="business-empty">
              <a class="profile-link" href="{_esc(profile_url)}" title="需使用管理者帳號登入">設定業務用途</a>
            </div>
            """
        )

        rows.append(f"""
        <article class="service-card {unprofiled.strip()}">
          <span class="dot dot-{state}" aria-hidden="true"></span>
          <div class="service-main">
            <strong>{_esc(display_name)}</strong>
            <small>作業系統：{_esc(os_display)}</small>
            <small>上次同步：{_esc(last_sync)}</small>
            <small>Agent 版本：{_esc(agent_version)}</small>
          </div>
          <div class="service-status">
            {impact_cell}
          </div>
          <details class="endpoint-row-score endpoint-score-detail {item_score_class}">
            <summary>
              <strong>{_esc(item_score)}</strong>
              <span>{_esc(item_score_label)}</span>
              <small>{_esc(item_score_reason)}</small>
            </summary>
            <div class="endpoint-score-breakdown">
              <b>分數說明</b>
              {item_score_breakdown_html}
            </div>
          </details>
          <details class="service-tech">
            <summary>技術資料</summary>
            <div class="service-tech-grid">
              <div class="tech-field"><span>代號</span><code>{_esc(name)}</code></div>
              <div class="tech-field"><span>IP</span><code>{_esc(ip)}</code></div>
              <div class="tech-field"><span>作業系統</span><code>{_esc(os_display)}</code></div>
              <div class="tech-field"><span>原始平台</span><code>{_esc(os_platform or "未知")}</code></div>
              <div class="tech-field"><span>Agent 版本</span><code>{_esc(agent_version)}</code></div>
            </div>
          </details>
        </article>
        """)

    return f"""
    <section class="section-card service-panel">
      <div class="section-head">
        <div class="section-title">
          <h2>電腦端點 ({_esc(total_agents)})</h2>
          <p>每台端點顯示監控狀態、業務影響與最近同步時間。</p>
        </div>
        {install_menu}
      </div>
      <div class="endpoint-score-card {endpoint_score_class}">
        <div class="endpoint-score-number">
          <strong>{_esc(endpoint_score)}</strong>
          <span>完整度</span>
        </div>
          <div class="endpoint-score-copy">
            <span>{_esc(endpoint_label)}</span>
            <strong>{_esc(endpoint_summary)}</strong>
            <p>{_esc(endpoint_note)}</p>
            <small>依每台電腦在線、背景、同步、版本與今日最高風險平均</small>
          </div>
        <a class="primary-action" href="{_esc(endpoint_action_href)}">{_esc(endpoint_action_text)}</a>
      </div>
      <div class="service-list-v2">
        {"".join(rows)}
      </div>
    </section>
    """



def _render_dashboard(
    stats: dict[str, Any],
    status: dict[str, Any],
    queue_size: int,
    queue_max: int,
    events: list[dict[str, Any]],
    active_view: str = "today",
) -> str:
    risk_text, risk_class, risk_desc = dashboard_model.headline_from_stats(stats)
    decision_title, decision_class, decision_desc, decision_action = dashboard_model.decision_from_stats(stats, status)
    sev = stats.get("open_by_severity_24h") or stats.get("by_severity_24h") or {}
    agents = status.get("agents") or {}
    active_agents = int(agents.get("active") or 0)
    total_agents = int(agents.get("total") or 0)
    disconnected_agents = int(agents.get("disconnected") or 0)
    agent_details = agents.get("details") or []
    endpoint_details = [agent for agent in agent_details if not dashboard_model.is_manager_agent(agent)]
    endpoint_total = len(endpoint_details)
    endpoint_active = sum(
        1 for agent in endpoint_details if str(agent.get("status") or "").strip().lower() == "active"
    )
    missing_profiles = sum(
        1 for agent in endpoint_details if not org_profile.find_asset(str(agent.get("name") or ""))
    )
    endpoint_risks = dashboard_model.endpoint_risk_map(events)
    endpoint_score_values = [
        dashboard_model.endpoint_item_score(
            agent,
            org_profile.find_asset(str(agent.get("name") or "")) or {},
            endpoint_risks.get(str(agent.get("name") or "")),
        )[0]
        for agent in endpoint_details
    ]
    owner_watch_count = len(events)
    slack_ready, slack_interactive, line_ready, telegram_ready, email_ready = _notification_status()
    notification_ready = bool(slack_ready or line_ready or telegram_ready or email_ready)
    notification_tested, notification_test_note = _notification_tested_status()
    notification_count = sum(1 for ready in (slack_ready, line_ready, telegram_ready, email_ready) if ready)
    score, score_label, score_class = dashboard_model.overall_score(
        endpoint_score_values, queue_size, int(stats.get("errors_last_24h") or 0)
    )
    system_health = (
        "正常"
        if disconnected_agents == 0 and queue_size == 0 and int(stats.get("errors_last_24h") or 0) == 0
        else "需檢查"
    )
    top_rules = stats.get("top_rules_24h") or []
    generated_at = datetime.fromtimestamp(time.time()).strftime("%Y-%m-%d %H:%M")

    top_rules_html = "\n".join(
        f"<li><strong>{_esc(r.get('c'))}</strong><span>{_esc(r.get('rule_description') or '未分類規則')}</span></li>"
        for r in top_rules[:4]
    ) or "<li><strong>0</strong><span>近 24 小時無告警</span></li>"

    if active_view == "notifications":
        active_view = "setup"

    labels = {
        "today": "今日待辦",
        "setup": "上線設定",
        "services": f"電腦端點 ({endpoint_total})",
        "platform": "平台狀態",
        "advanced": "進階查詢",
    }
    if active_view not in labels:
        active_view = "today"
    current_label = labels[active_view]
    tabs_html = "\n".join(
        f"""
        <a class="cal-tab {'active' if active_view == key else ''}" href="/dashboard{'' if key == 'today' else '?view=' + key}" {'aria-current="page"' if active_view == key else ''}>
          {_esc(label)}
        </a>
        """
        for key, label in labels.items()
    )

    summary_panel = f"""
    <section class="cal-panel summary-card" aria-label="今日摘要">
      <h2>今日摘要</h2>
      <div class="summary-metric"><span>今日風險</span><strong>{_esc(risk_text)}</strong></div>
      <div class="summary-metric"><span>待確認</span><strong>{_esc(owner_watch_count)} 項</strong></div>
      <div class="summary-metric"><span>端點在線</span><strong>{_esc(endpoint_active)}/{_esc(endpoint_total)}</strong></div>
      <div class="summary-metric"><span>資料待補</span><strong>{_esc(missing_profiles)} 項</strong></div>
      <div class="summary-metric"><span>系統健康</span><strong>{_esc(system_health)}</strong></div>
    </section>
    """
    next_step_panel = f"""
    <section class="cal-panel next-step-card">
      <h2>今天要做的事</h2>
      <p>{_esc(decision_action)}</p>
    </section>
    """
    primary_action_href = "/dashboard?view=platform#self-test" if system_health != "正常" else (
        "/dashboard?view=services" if missing_profiles else "/dashboard?view=advanced"
    )
    primary_action_text = "執行自我檢查" if system_health != "正常" else (
        "補端點背景" if missing_profiles else "查看紀錄"
    )
    primary_action_note = (
        "先確認 AI、通知與告警服務是否正常。"
        if system_health != "正常"
        else (
            f"還有 {missing_profiles} 台端點缺少業務背景。"
            if missing_profiles
            else "目前沒有待補資料，可查看事件紀錄。"
        )
    )
    endpoint_profile_done = max(endpoint_total - missing_profiles, 0)
    service_next_step = (
        f"先補齊 {_esc(missing_profiles)} 台端點的業務背景。補完後，AI 告警會直接說明可能影響的人、流程或系統。"
        if missing_profiles
        else "端點背景已完整。之後告警會直接帶出業務影響，維持定期確認即可。"
    )
    services_summary_panel = f"""
    <section class="cal-panel summary-card" aria-label="端點摘要">
      <h2>端點摘要</h2>
      <div class="summary-metric"><span>端點在線</span><strong>{_esc(endpoint_active)}/{_esc(endpoint_total)}</strong></div>
      <div class="summary-metric"><span>背景已填</span><strong>{_esc(endpoint_profile_done)}/{_esc(endpoint_total)}</strong></div>
      <div class="summary-metric"><span>待補背景</span><strong>{_esc(missing_profiles)} 台</strong></div>
      <div class="summary-metric"><span>系統健康</span><strong>{_esc(system_health)}</strong></div>
    </section>
    """
    services_next_step_panel = f"""
    <section class="cal-panel next-step-card service-next-card">
      <h2>這頁要完成的事</h2>
      <p>{service_next_step}</p>
    </section>
    """
    platform_panel = f"""
    <section class="cal-panel" id="self-test">
      <div class="cal-panel-head">
        <div>
          <h2>平台狀態</h2>
          <p>給技術窗口確認，不影響主要待辦流程。</p>
        </div>
      </div>
      {_render_status(status, queue_size, queue_max, owner_watch_count)}
      <div class="self-test">
        <div class="self-test-head">
          <h3>自我檢查</h3>
          <button class="check-button" id="self-test-button" type="button">立即檢查</button>
        </div>
        <div class="self-result" id="self-test-result">
          <strong>尚未執行</strong>
          <p>按下後會檢查通知、告警資料與分析服務。</p>
        </div>
      </div>
    </section>
    """
    agent_installed = endpoint_total > 0
    background_ready = agent_installed and missing_profiles == 0
    launch_ready = notification_tested and agent_installed and background_ready
    setup_done_count = sum(1 for ok in (notification_tested, agent_installed, background_ready) if ok)
    setup_label = "可以上班" if launch_ready else f"還差 {3 - setup_done_count} 步"
    setup_intro = (
        "通知已測試、Agent 已納管、端點背景已補齊。之後只要等通知並處理今日待辦。"
        if launch_ready
        else "通知和 Agent 可以分開做。先設定一個通知管道，同時也可以安裝 Agent。"
    )
    notify_step_status = "done" if notification_tested else "active"
    agent_step_status = "done" if agent_installed else "active"
    background_step_status = "done" if background_ready else ("active" if notification_tested and agent_installed else "pending")
    work_step_status = "active" if launch_ready else "pending"
    notification_token = admin_token.sign("__notifications__")
    line_setup_url = f"/admin/notifications?channel=line&t={quote(notification_token)}"
    slack_setup_url = f"/admin/notifications?channel=slack&t={quote(notification_token)}"
    notifications_setup_url = f"/admin/notifications?t={quote(notification_token)}"
    setup_panel = f"""
    <section class="score-panel {'score-ok' if launch_ready else 'score-warn'} setup-panel">
      <div class="score-ring">
        <strong>{_esc(setup_done_count)}/3</strong>
        <span>上線</span>
      </div>
      <div class="score-copy">
        <span class="score-label">上線檢查</span>
        <h1>{_esc(setup_label)}</h1>
        <p>{_esc(setup_intro)}</p>
        <small>通知與 Agent 可平行設定；LINE、Slack、Telegram 或 Email 至少一個要測試成功。</small>
      </div>
      <div class="score-actions">
        <a class="primary-action" href="{_esc(line_setup_url)}">設定 LINE</a>
        <a class="secondary-action" href="{_esc(slack_setup_url)}">設定 Slack</a>
        <a class="secondary-action" href="/dashboard?view=services">安裝 Agent</a>
      </div>
    </section>
    <section class="cal-panel">
      <div class="cal-panel-head">
        <div>
          <h2>上線步驟</h2>
          <p>通知和 Agent 都是上線必要項目；Agent 隨時可以先安裝。</p>
        </div>
      </div>
      <ol class="setup-checklist">
        {_setup_step(notify_step_status, "設定通知並測試成功", notification_test_note, notifications_setup_url, "設定通知")}
        {_setup_step(agent_step_status, "安裝 Agent", f"目前已看到 {endpoint_total} 台端點，{endpoint_active} 台在線。", "/dashboard?view=services", "安裝或查看端點")}
        {_setup_step(background_step_status, "設定業務用途", f"目前 {endpoint_profile_done}/{endpoint_total} 台已完成，{missing_profiles} 台待補。", "/dashboard?view=services", "設定業務用途")}
        {_setup_step(work_step_status, "開始上班，等通知", "收到告警後，在今日待辦按正常操作、交給 IT、已處理或誤報；封鎖 IP、隔離端點由技術窗口或自動回應執行。", "/dashboard", "看今日待辦")}
      </ol>
    </section>
    {_notification_panel()}
    """
    siem_link_html = (
        f'<a href="{_esc(SIEM_DASHBOARD_URL.rstrip("/") + "/app/threat-hunting")}">SIEM 深查</a>'
        if SIEM_DASHBOARD_URL
        else '<span class="disabled-link">SIEM 深查（尚未設定）</span>'
    )
    advanced_panel = f"""
    <section class="cal-panel">
      <div class="cal-panel-head">
        <div>
          <h2>進階查詢</h2>
          <p>需要細節時再進入。</p>
        </div>
      </div>
      <div class="quiet-links">
        <a href="/alerts?limit=20">原始事件</a>
        <a href="/docs">API 文件</a>
        {siem_link_html}
      </div>
    </section>
    <section class="cal-panel">
      <div class="cal-panel-head">
        <div>
          <h2>近 24 小時規則</h2>
          <p>協助技術窗口快速定位主要告警來源。</p>
        </div>
      </div>
      <ul class="top-rules">{top_rules_html}</ul>
    </section>
    """

    if active_view == "services":
        primary_content = _render_agent_inventory(status, events)
        aside_content = ""
    elif active_view == "setup":
        primary_content = setup_panel
        aside_content = summary_panel + next_step_panel
    elif active_view == "platform":
        primary_content = platform_panel
        aside_content = summary_panel + advanced_panel
    elif active_view == "advanced":
        primary_content = advanced_panel
        aside_content = summary_panel + platform_panel
    else:
        first_step_done_class = "done" if notification_tested else "active"
        second_step_class = "done" if agent_installed else ("active" if notification_tested else "")
        third_step_class = "done" if background_ready else ("active" if notification_tested and agent_installed else "")
        setup_primary_href = "/dashboard?view=setup" if not notification_tested else (
            "/dashboard?view=services" if missing_profiles else "#today-tasks"
        )
        setup_primary_text = "設定通知" if not notification_tested else (
            "補端點背景" if missing_profiles else "查看今日待辦"
        )
        setup_note = (
            "通知尚未測試成功，告警發生時不確定有沒有人會收到。"
            if not notification_tested
            else (
                f"通知已可用，還有 {missing_profiles} 台端點缺背景。"
                if missing_profiles
                else "通知已可用；今天只要看待辦事項是否需要回報。"
            )
        )
        primary_content = f"""
        <section class="score-panel {score_class}">
          <div class="score-ring">
            <strong>{_esc(score)}</strong>
            <span>健康度</span>
          </div>
          <div class="score-copy">
            <span class="score-label">{_esc(score_label)}</span>
            <h1>{_esc(decision_title)}</h1>
            <p>{_esc(setup_note)}</p>
            <small>依每台端點分數平均；同類告警合併顯示，端點只按最高風險扣一次</small>
          </div>
          <div class="score-actions">
            <a class="primary-action" href="{_esc(setup_primary_href)}">{_esc(setup_primary_text)}</a>
            <a class="secondary-action" href="/dashboard?view=services">電腦端點</a>
          </div>
        </section>

        <section class="cal-panel owner-start">
          <div class="cal-panel-head">
            <div>
              <h2>第一次進來先做這兩件事</h2>
              <p>照順序完成後，就不用一直盯儀表板，等通知即可。</p>
            </div>
          </div>
          <ol class="owner-flow compact">
            <li class="{first_step_done_class}"><strong>設定通知</strong><span>LINE 或 Slack 測試成功才算完成。</span><a href="/dashboard?view=setup">上線設定</a></li>
            <li class="{second_step_class}"><strong>安裝 Agent</strong><span>這一步隨時可做；端點出現在清單後，才算納入監控。</span><a href="/dashboard?view=services">查看端點</a></li>
            <li class="{third_step_class}"><strong>補端點背景</strong><span>讓 AI 知道每台電腦影響哪個人、流程或系統。</span><a href="/dashboard?view=services">補背景</a></li>
          </ol>
        </section>

        <section class="cal-panel events" id="today-tasks">
          <div class="cal-panel-head">
            <div>
              <h2>待辦事項</h2>
              <p>同一台電腦的同類告警會合併成一張卡；技術資料預設收起。</p>
            </div>
          </div>
          {_render_events(events)}
        </section>
        """
        aside_content = summary_panel + next_step_panel

    return f"""<!doctype html>
<html lang="zh-Hant">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>EdgeSec-Pi 安全處理中心</title>
<style>
{dashboard_assets.DASHBOARD_CSS}
</style>
</head>
<body>
<div class="cal-shell">
  <header class="cal-top">
    <div class="cal-top-inner">
      <div class="cal-brand">
        <span class="cal-mark" aria-hidden="true">E</span>
        <div>
          <strong>EdgeSec-Pi 安全處理中心</strong>
          <span>{_esc(current_label)}</span>
        </div>
      </div>
      <div class="cal-updated">更新時間：{_esc(generated_at)}</div>
    </div>
  </header>

  <main class="cal-main">
    <nav class="cal-tabs" aria-label="安全處理中心分頁">
      {tabs_html}
    </nav>
    <div class="cal-layout cal-layout-{_esc(active_view)}">
      <div class="cal-primary">
        {primary_content}
      </div>

      <aside class="cal-aside">
        {aside_content}
      </aside>
    </div>
  </main>
</div>
<div class="drawer-backdrop" id="context-drawer" aria-hidden="true">
  <aside class="drawer-panel" role="dialog" aria-modal="true" aria-label="端點業務背景">
    <div class="drawer-head">
      <strong>端點業務背景</strong>
      <button class="drawer-close" type="button" aria-label="關閉">×</button>
    </div>
    <iframe class="drawer-frame" title="端點業務背景設定"></iframe>
  </aside>
</div>
<script>
{dashboard_assets.DASHBOARD_JS}
</script>
</body>
</html>"""


@router.get("/", include_in_schema=False)
async def root() -> RedirectResponse:
    return RedirectResponse(url="/dashboard")


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    if DASHBOARD_V2_URL:
        return RedirectResponse(url=_dashboard_v2_redirect_url(request))

    stats = await db.compute_stats()

    # 管理層只看 medium 以上，Wazuh / API 保留全部細節給 IT。
    # 分 severity 抓，避免大量 info 告警把高風險事件擠出最近列表。
    event_candidates: list[dict[str, Any]] = []
    for severity in ("critical", "high", "medium"):
        event_candidates.extend(await db.list_alerts(limit=60, severity=severity, active_only=True))
    seen: set[int] = set()
    events: list[dict[str, Any]] = []
    for row in sorted(event_candidates, key=lambda r: r.get("received_at") or 0, reverse=True):
        row_id = int(row.get("id") or 0)
        if row_id in seen:
            continue
        seen.add(row_id)
        events.append(row)
        if len(events) >= 120:
            break
    events = _collapse_event_groups(events, limit=8)

    try:
        status = await digest.collect_status()
    except Exception as e:
        status = {
            "wazuh": {"manager_version": "未知", "version_status": "unknown"},
            "agents": {"total": 0, "active": 0, "disconnected": 0},
            "cve_feed": {"status": f"status check failed: {e}"},
        }

    queue = getattr(request.app.state, "queue", None)
    queue_size = queue.qsize() if queue else 0
    queue_max = getattr(queue, "maxsize", 0) or 0
    active_view = str(request.query_params.get("view") or "today").lower()

    return HTMLResponse(_render_dashboard(stats, status, queue_size, queue_max, events, active_view))


@router.post("/dashboard/alerts/{alert_id}/case", include_in_schema=False)
async def update_dashboard_alert_case(alert_id: int, request: Request) -> RedirectResponse:
    form = await request.form()
    status = str(form.get("status") or "").strip()
    note = str(form.get("note") or "").strip()
    try:
        await db.update_alert_case(alert_id, status, note, actor="dashboard")
        raw_group_ids = str(form.get("group_ids") or "").strip()
        if raw_group_ids:
            group_ids = [
                int(part)
                for part in raw_group_ids.split(",")
                if part.strip().isdigit()
            ]
            if group_ids:
                await db.update_alert_cases(group_ids, status, note, actor="dashboard")
    except ValueError:
        pass
    return RedirectResponse(url="/dashboard#today-tasks", status_code=303)
