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
from urllib.parse import quote

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse

import db
import admin_token
import dashboard_model
import digest
import notify_channels
import org_profile

router = APIRouter()

SIEM_DASHBOARD_URL = os.getenv("SIEM_DASHBOARD_URL", "").rstrip("/")
WAZUH_AGENT_VERSION = os.getenv("WAZUH_VERSION", "4.14.5").lstrip("v")
MANAGER_HOST = os.getenv("MANAGER_HOST", "localhost")
PROFILE_LINK_TTL_S = int(os.getenv("PROFILE_LINK_TTL_S", "28800"))


def _esc(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


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


def _case_action_button(alert_id: int, status: str, label: str) -> str:
    return f"""
    <form method="post" action="/dashboard/alerts/{_esc(alert_id)}/case#today-tasks" class="case-form">
      <input type="hidden" name="status" value="{_esc(status)}">
      <button type="submit">{_esc(label)}</button>
    </form>
    """



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
              </div>
            </details>
          </div>
          <div class="task-owner">
            <span>現在要做</span>
            <strong>{_esc(next_title)}</strong>
            {f'<a class="owner-link" href="{_esc(profile_url)}">設定業務用途</a>' if not has_business_context else ''}
            <div class="case-status {case_class}">{_esc(case_label)}</div>
            <div class="case-actions" aria-label="更新處理狀態">
              {_case_action_button(row_id, "normal", "正常操作")}
              {_case_action_button(row_id, "in_progress", "交給 IT")}
              {_case_action_button(row_id, "resolved", "已處理")}
              {_case_action_button(row_id, "false_positive", "誤報")}
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
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return raw


def _fallback_agent_role(name: str, os_platform: str) -> str:
    lowered = f"{name} {os_platform}".lower()
    if "manager" in lowered or "wazuh.manager" in lowered:
        return "資安監控核心"
    if "darwin" in lowered or "mac" in lowered or "studio" in lowered:
        return "管理者或員工工作站"
    if "pos" in lowered:
        return "門市 POS / 收銀端點"
    if "db" in lowered or "database" in lowered:
        return "資料庫主機"
    if "web" in lowered:
        return "網站或對外服務主機"
    return "某項受監控服務"



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
    return f"""
    <section class="cal-panel notification-card">
      <div class="cal-panel-head">
        <div>
          <h2>通知設定</h2>
          <p>先確認告警會送到哪裡；這是上線後第一件事。</p>
        </div>
        <a class="secondary-action" href="/admin/notifications">通知設定</a>
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
    owner_watch_count = int(sev.get("critical", 0) + sev.get("high", 0) + sev.get("medium", 0))
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
            <small>依每台端點分數平均；同一台重複告警只按最高風險扣一次</small>
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
              <p>只顯示今天需要確認或回報的項目；技術資料預設收起。</p>
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
  :root {{
    --bg: #f7f9fc;
    --panel: #ffffff;
    --text: #0f1f33;
    --muted: #5f6f86;
    --line: #d9e4f2;
    --blue: #2496ed;
    --blue-dark: #1d63ed;
    --blue-soft: #eaf5ff;
    --ok: #14864f;
    --warn: #b26a00;
    --high: #c24135;
    --medium: #b26a00;
    --info: #1d63ed;
    --shadow: 0 1px 2px rgba(15, 31, 51, .05), 0 8px 24px rgba(15, 31, 51, .05);
  }}
  html, body {{ height: 100%; min-height: 100%; overflow: hidden; }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; background: var(--bg); color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Noto Sans TC", "Segoe UI", sans-serif;
    line-height: 1.5;
  }}
  .app-shell {{
    min-height: 100vh; display: grid; grid-template-columns: 240px minmax(0, 1fr);
  }}
  .sidebar {{
    position: sticky; top: 0; height: 100vh; background: #ffffff;
    border-right: 1px solid var(--line); padding: 18px 14px;
    display: flex; flex-direction: column; gap: 18px;
  }}
  .brand {{ display: flex; align-items: center; gap: 10px; padding: 2px 6px 12px; }}
  .brand-mark {{
    width: 32px; height: 32px; border-radius: 7px; background: var(--blue);
    box-shadow: inset 0 -6px 0 rgba(0, 0, 0, .08);
  }}
  .brand strong {{ display: block; font-size: 16px; line-height: 1.1; }}
  .brand span {{ display: block; color: var(--muted); font-size: 12px; }}
  .nav {{ display: grid; gap: 4px; }}
  .nav a {{
    display: flex; align-items: center; gap: 10px; min-height: 38px; padding: 0 10px;
    border-radius: 7px; color: #334155; font-weight: 650; text-decoration: none;
  }}
  .nav a:hover {{ background: #f1f6fd; text-decoration: none; }}
  .nav a.active {{ background: var(--blue-soft); color: #0b5cad; }}
  .nav-icon {{
    width: 18px; height: 18px; border-radius: 5px; border: 1px solid #9ccdf7;
    background: #ffffff; flex: 0 0 auto;
  }}
  .sidebar-foot {{
    margin-top: auto; border: 1px solid var(--line); border-radius: 8px; padding: 10px;
    color: var(--muted); font-size: 13px; background: #fbfdff;
  }}
  .content-shell {{ min-width: 0; }}
  .topbar {{
    min-height: 66px; background: #ffffff; border-bottom: 1px solid var(--line);
    display: flex; align-items: center;
  }}
  .topbar-inner {{
    width: min(1220px, calc(100% - 48px)); margin: 0 auto;
    display: flex; justify-content: space-between; gap: 16px; align-items: center;
  }}
  .eyebrow {{ color: var(--muted); font-size: 12px; font-weight: 750; text-transform: uppercase; }}
  h1 {{ margin: 0; font-size: 23px; font-weight: 750; letter-spacing: 0; }}
  .updated {{
    color: var(--muted); font-size: 13px; white-space: nowrap; border: 1px solid var(--line);
    border-radius: 999px; padding: 6px 10px; background: #fbfdff;
  }}
  .wrap {{ width: min(1220px, calc(100% - 48px)); margin: 0 auto; }}
  main {{ padding: 24px 0 42px; }}
  .dashboard-grid {{
    display: grid; grid-template-columns: minmax(0, 1fr) 340px; gap: 18px; align-items: start;
  }}
  .primary-column, .side-column {{ display: grid; gap: 18px; min-width: 0; }}
  .risk-band, .panel, .event {{
    background: var(--panel); border: 1px solid var(--line); border-radius: 8px;
    box-shadow: var(--shadow);
  }}
  .risk-band {{ padding: 22px; border-top: 4px solid var(--ok); }}
  .risk-band.risk-critical, .risk-band.risk-high {{ border-top-color: var(--high); }}
  .risk-band.risk-medium {{ border-top-color: var(--medium); }}
  .risk-band.risk-ok {{ border-top-color: var(--ok); }}
  .risk-label {{ color: var(--muted); font-size: 13px; font-weight: 750; }}
  .risk-value {{ font-size: 44px; font-weight: 800; margin: 4px 0 6px; letter-spacing: 0; }}
  .risk-desc {{ max-width: 720px; font-size: 17px; }}
  .metrics {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-top: 18px; }}
  .metric {{ border: 1px solid var(--line); border-radius: 7px; padding: 10px; min-width: 0; background: #fbfdff; }}
  .metric strong {{ display: block; font-size: 24px; }}
  .metric span {{ display: block; color: var(--muted); font-size: 13px; overflow-wrap: anywhere; }}
  .panel {{ padding: 18px; }}
  .panel h2, .events h2 {{ margin: 0 0 12px; font-size: 18px; }}
  .status-row {{
    display: grid; grid-template-columns: 14px minmax(70px, .8fr) minmax(0, 1fr);
    gap: 8px; align-items: center; padding: 10px 0; border-top: 1px solid var(--line);
  }}
  .status-row:first-of-type {{ border-top: 0; }}
  .status-row strong {{ text-align: right; overflow-wrap: anywhere; }}
  .dot {{ width: 10px; height: 10px; border-radius: 50%; display: inline-block; }}
  .dot-ok {{ background: var(--ok); }}
  .dot-warn {{ background: var(--warn); }}
  .events {{ min-width: 0; }}
  .event {{ padding: 16px; margin-bottom: 12px; border-left: 4px solid var(--info); }}
  .event-critical, .event-high {{ border-left-color: var(--high); }}
  .event-medium {{ border-left-color: var(--medium); }}
  .event-info {{ border-left-color: var(--info); }}
  .event-top {{ display: flex; justify-content: space-between; gap: 12px; align-items: center; }}
  .sev {{
    display: inline-flex; align-items: center; min-height: 26px; padding: 3px 10px;
    border-radius: 999px; font-size: 13px; font-weight: 750; background: var(--blue-soft); color: #0b5cad;
  }}
  .sev-critical, .sev-high {{ background: #fee2e2; color: #991b1b; }}
  .sev-medium {{ background: #fef3c7; color: #92400e; }}
  .sev-low {{ background: #dcfce7; color: #166534; }}
  .event-time {{ color: var(--muted); font-size: 13px; white-space: nowrap; }}
  .event h3 {{ margin: 12px 0; font-size: 19px; line-height: 1.35; letter-spacing: 0; }}
  dl {{ margin: 0; display: grid; gap: 9px; }}
  dl div {{ display: grid; grid-template-columns: 70px minmax(0, 1fr); gap: 10px; }}
  dt {{ color: var(--muted); font-weight: 700; }}
  dd {{ margin: 0; overflow-wrap: anywhere; }}
  details {{ margin-top: 12px; border-top: 1px solid var(--line); padding-top: 10px; }}
  summary {{ cursor: pointer; color: #334155; font-weight: 650; }}
  .tech-grid {{ display: grid; grid-template-columns: 100px minmax(0, 1fr); gap: 8px; margin-top: 10px; }}
  code {{ background: #eef4fb; padding: 2px 6px; border-radius: 4px; overflow-wrap: anywhere; }}
  .side-list {{ list-style: none; margin: 0; padding: 0; display: grid; gap: 10px; }}
  .side-list li {{ display: grid; grid-template-columns: 42px minmax(0, 1fr); gap: 10px; align-items: start; }}
  .side-list strong {{ font-size: 22px; line-height: 1; }}
  .side-list span {{ color: var(--muted); overflow-wrap: anywhere; }}
  .agent-list {{ display: grid; gap: 0; }}
  .agent-row {{ border-top: 1px solid var(--line); padding: 14px 0; }}
  .agent-row:first-child {{ border-top: 0; padding-top: 0; }}
  .agent-row:last-child {{ padding-bottom: 0; }}
  .agent-unprofiled {{ background: #fffaf0; margin: 0 -10px; padding-left: 10px; padding-right: 10px; border-radius: 7px; }}
  .agent-head {{
    display: grid; grid-template-columns: 14px minmax(0, 1fr) auto;
    gap: 10px; align-items: start;
  }}
  .agent-title strong {{ display: block; font-size: 16px; line-height: 1.25; overflow-wrap: anywhere; }}
  .agent-title span {{ display: block; color: var(--muted); margin-top: 2px; overflow-wrap: anywhere; }}
  .status-pill {{
    border-radius: 999px; padding: 3px 9px; font-size: 12px; font-weight: 800;
    background: #ecfdf3; color: #087443; white-space: nowrap;
  }}
  .status-warn {{ background: #fff7e6; color: #9a5a00; }}
  .agent-meta {{
    display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 8px;
    margin: 10px 0 0 24px;
  }}
  .agent-meta span {{
    border: 1px solid var(--line); border-radius: 7px; padding: 8px;
    color: #334155; background: #fbfdff; min-width: 0; overflow-wrap: anywhere;
  }}
  .agent-meta b {{ display: block; color: var(--muted); font-size: 12px; margin-bottom: 2px; }}
  .agent-note {{ margin: 10px 0 0 24px; color: #475569; }}
  .profile-link {{ display: inline-block; margin: 10px 0 0 24px; font-weight: 750; }}
  .empty-state {{ background: white; border: 1px solid var(--line); border-radius: 8px; padding: 22px; box-shadow: var(--shadow); }}
  .empty-state.compact {{ box-shadow: none; padding: 14px; }}
  .empty-state strong, .empty-state span {{ display: block; }}
  .empty-state span {{ color: var(--muted); margin-top: 6px; }}
  a {{ color: var(--blue-dark); text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  .links {{ display: grid; gap: 8px; margin-top: 12px; }}
  .self-test {{ margin-top: 16px; border-top: 1px solid var(--line); padding-top: 14px; }}
  .self-test-head {{ display: flex; justify-content: space-between; gap: 10px; align-items: center; }}
  .self-test-head h3 {{ margin: 0; font-size: 16px; }}
  .check-button {{
    border: 1px solid var(--blue-dark); background: var(--blue-dark); color: white; border-radius: 6px;
    min-height: 34px; padding: 0 12px; font-weight: 700; cursor: pointer;
  }}
  .check-button:disabled {{ opacity: .65; cursor: wait; }}
  .self-result {{
    margin-top: 12px; border: 1px solid var(--line); border-radius: 8px; padding: 12px;
    background: #f8fafc; max-height: 420px; overflow: auto;
  }}
  .self-result.result-ok {{ border-color: #86efac; background: #f0fdf4; }}
  .self-result.result-warn {{ border-color: #fcd34d; background: #fffbeb; }}
  .self-result.result-fail {{ border-color: #fca5a5; background: #fef2f2; }}
  .self-result strong {{ display: block; font-size: 15px; margin-bottom: 4px; }}
  .self-result p {{ margin: 0; color: #475569; font-size: 14px; }}
  .check-list {{ list-style: none; padding: 0; margin: 12px 0 0; display: grid; gap: 8px; }}
  .check-list li {{
    display: grid; grid-template-columns: 22px minmax(0, 1fr); gap: 8px;
    border-top: 1px solid rgba(15, 23, 42, .09); padding-top: 8px;
  }}
  .check-list li:first-child {{ border-top: 0; padding-top: 0; }}
  .check-icon {{ font-weight: 800; }}
  .check-list b {{ display: block; }}
  .check-list span {{ display: block; color: #475569; font-size: 13px; }}
  .check-list details {{ grid-column: 2; margin-top: 2px; padding-top: 0; border-top: 0; }}
  .check-list summary {{ font-size: 13px; color: #475569; }}
  @media (max-width: 860px) {{
    .app-shell {{ grid-template-columns: 1fr; }}
    .sidebar {{
      position: static; height: auto; border-right: 0; border-bottom: 1px solid var(--line);
      padding: 12px; gap: 10px;
    }}
    .brand {{ padding-bottom: 6px; }}
    .nav {{ grid-template-columns: repeat(4, minmax(0, 1fr)); }}
    .nav a {{ justify-content: center; min-height: 36px; font-size: 13px; }}
    .nav-icon, .sidebar-foot {{ display: none; }}
    .topbar-inner, .event-top {{ align-items: flex-start; flex-direction: column; }}
    .dashboard-grid {{ grid-template-columns: 1fr; }}
    .self-result {{ max-height: none; }}
    .metrics, .agent-meta {{ grid-template-columns: repeat(2, 1fr); }}
    .updated, .event-time {{ white-space: normal; }}
  }}
  @media (max-width: 520px) {{
    .wrap, .topbar-inner {{ width: min(100% - 20px, 1220px); }}
    .topbar {{ padding: 12px 0; }}
    .nav {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
    main {{ padding-top: 14px; }}
    h1 {{ font-size: 21px; }}
    .risk-value {{ font-size: 36px; }}
    .metrics, .agent-meta, dl div, .tech-grid {{ grid-template-columns: 1fr; }}
    .agent-head {{ grid-template-columns: 14px minmax(0, 1fr); }}
    .status-pill {{ grid-column: 2; justify-self: start; }}
    .status-row {{ grid-template-columns: 14px minmax(0, 1fr); }}
    .status-row strong {{ grid-column: 2; text-align: left; }}
  }}
  .management-shell {{ min-height: 100vh; }}
  .management-top {{
    background: #ffffff; border-bottom: 1px solid var(--line); position: sticky; top: 0; z-index: 5;
  }}
  .management-top-inner {{
    width: min(1040px, calc(100% - 40px)); min-height: 68px; margin: 0 auto;
    display: flex; align-items: center; justify-content: space-between; gap: 16px;
  }}
  .management-brand {{ display: flex; align-items: center; gap: 10px; }}
  .management-brand strong {{ display: block; font-size: 17px; }}
  .management-brand span {{ color: var(--muted); font-size: 13px; }}
  .management-main {{ width: min(1040px, calc(100% - 40px)); margin: 0 auto; padding: 24px 0 48px; }}
  .management-updated {{ color: var(--muted); font-size: 13px; white-space: nowrap; }}
  .decision {{
    background: #ffffff; border: 1px solid var(--line); border-top: 5px solid var(--ok);
    border-radius: 8px; box-shadow: var(--shadow); padding: 26px;
  }}
  .decision-critical, .decision-high {{ border-top-color: var(--high); }}
  .decision-medium {{ border-top-color: var(--medium); }}
  .decision-label {{ color: var(--muted); font-size: 13px; font-weight: 800; }}
  .decision h1 {{ font-size: 42px; line-height: 1.05; margin: 8px 0 10px; }}
  .decision p {{ margin: 0; font-size: 18px; max-width: 760px; }}
  .owner-action {{
    margin-top: 18px; padding: 14px 16px; border-radius: 8px;
    background: #f6fafe; border: 1px solid #cfe6fb;
  }}
  .owner-action span {{ display: block; color: var(--muted); font-size: 13px; font-weight: 800; }}
  .owner-action strong {{ display: block; margin-top: 4px; font-size: 17px; }}
  .summary-grid {{
    display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; margin-top: 16px;
  }}
  .summary-card {{
    background: #ffffff; border: 1px solid var(--line); border-radius: 8px; padding: 14px; box-shadow: var(--shadow);
  }}
  .summary-card strong {{ display: block; font-size: 26px; line-height: 1.1; }}
  .summary-card span {{ display: block; margin-top: 6px; color: var(--muted); font-size: 13px; }}
  .owner-grid {{ display: grid; grid-template-columns: minmax(0, 1fr) 320px; gap: 18px; margin-top: 18px; align-items: start; }}
  .owner-main, .owner-side {{ display: grid; gap: 18px; min-width: 0; }}
  .section-card {{
    background: #ffffff; border: 1px solid var(--line); border-radius: 8px; padding: 18px; box-shadow: var(--shadow);
  }}
  .section-head {{ display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; margin-bottom: 12px; }}
  .section-head h2 {{ margin: 0; font-size: 20px; }}
  .section-head p {{ margin: 4px 0 0; color: var(--muted); }}
  .service-list {{ display: grid; gap: 10px; }}
  .service-item {{ border: 1px solid var(--line); border-radius: 8px; padding: 13px; background: #fbfdff; }}
  .service-item.agent-unprofiled {{ background: #fffaf0; }}
  .service-head {{ display: grid; grid-template-columns: 12px minmax(0, 1fr) auto; gap: 10px; align-items: start; }}
  .service-title strong {{ display: block; font-size: 16px; }}
  .service-title span {{ display: block; color: var(--muted); margin-top: 2px; overflow-wrap: anywhere; }}
  .service-meta {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; margin: 10px 0 0 22px; }}
  .service-meta span {{ border: 1px solid var(--line); border-radius: 7px; padding: 8px; background: #ffffff; }}
  .service-meta b {{ display: block; color: var(--muted); font-size: 12px; }}
  .profile-missing {{ margin: 10px 0 0 22px; border: 1px solid #f5c76b; border-radius: 7px; padding: 10px; background: #fff8e6; }}
  .profile-missing strong {{ display: block; color: #8a4b08; }}
  .profile-missing span {{ display: block; margin-top: 3px; color: #7a5a23; }}
  .service-details {{ margin-left: 22px; }}
  .profile-link {{ margin-left: 22px; }}
  .event-impact {{ margin: 0 0 12px; color: #334155; }}
  .event-action {{ border: 1px solid #cfe6fb; background: #f6fafe; border-radius: 8px; padding: 12px; }}
  .event-action span {{ display: block; color: var(--muted); font-size: 13px; font-weight: 800; }}
  .event-action strong {{ display: block; margin-top: 4px; }}
  .quiet-links {{ display: grid; gap: 8px; }}
  @media (max-width: 900px) {{
    .management-top-inner, .management-main {{ width: min(100% - 24px, 1040px); }}
    .summary-grid, .owner-grid {{ grid-template-columns: 1fr; }}
    .decision h1 {{ font-size: 34px; }}
  }}
  @media (max-width: 560px) {{
    .management-top-inner {{ align-items: flex-start; flex-direction: column; padding: 12px 0; }}
    .summary-grid {{ gap: 10px; }}
    .service-head {{ grid-template-columns: 12px minmax(0, 1fr); }}
    .status-pill {{ grid-column: 2; justify-self: start; }}
    .service-meta {{ grid-template-columns: 1fr; }}
  }}
  .management-shell {{
    --surface: #ffffff;
    --surface-muted: #f6f8fa;
    --text: #1f2328;
    --muted: #59636e;
    --line: #d0d7de;
    --line-soft: #eaeef2;
    --accent: #0969da;
    --ok: #1a7f37;
    --warn: #9a6700;
    --high: #cf222e;
    height: 100vh; min-height: 100vh; overflow-y: auto; overscroll-behavior: contain;
    background: #f6f8fa;
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Helvetica Neue", Helvetica, sans-serif;
  }}
  .management-shell * {{ box-shadow: none; letter-spacing: 0; }}
  .management-top {{
    position: sticky; top: 0; z-index: 5;
    background: rgba(255,255,255,.96); border-bottom: 1px solid var(--line);
  }}
  .management-top-inner {{
    width: min(1180px, calc(100% - 32px)); min-height: 56px; margin: 0 auto;
    display: flex; align-items: center; justify-content: space-between; gap: 16px;
  }}
  .management-brand {{ display: flex; align-items: center; gap: 10px; min-width: 0; }}
  .management-brand .brand-mark {{
    width: 24px; height: 24px; border-radius: 4px; background: #2496ed;
    box-shadow: inset 0 -4px 0 rgba(0,0,0,.12);
  }}
  .management-brand strong {{ display: block; font-size: 15px; line-height: 1.2; }}
  .management-brand span {{ display: block; margin-top: 1px; color: var(--muted); font-size: 12px; }}
  .management-updated {{ color: var(--muted); font-size: 12px; white-space: nowrap; }}
  .management-main {{ width: min(1180px, calc(100% - 32px)); margin: 0 auto; padding: 16px 0 36px; }}
  .status-strip {{
    display: grid; grid-template-columns: minmax(0, 1fr) minmax(280px, 420px); gap: 18px;
    border: 1px solid var(--line); border-left: 4px solid var(--ok);
    background: var(--surface); border-radius: 6px; padding: 16px;
  }}
  .status-strip.status-critical, .status-strip.status-high {{ border-left-color: var(--high); }}
  .status-strip.status-medium {{ border-left-color: var(--warn); }}
  .status-strip h1 {{ margin: 2px 0 4px; font-size: 22px; line-height: 1.25; }}
  .status-strip p {{ margin: 0; color: var(--muted); font-size: 14px; }}
  .status-label {{ color: var(--muted); font-size: 12px; font-weight: 700; }}
  .next-action {{ border-left: 1px solid var(--line-soft); padding-left: 18px; }}
  .next-action span {{ display: block; color: var(--muted); font-size: 12px; font-weight: 700; }}
  .next-action strong {{ display: block; margin-top: 4px; font-size: 14px; line-height: 1.45; }}
  .summary-row {{
    display: grid; grid-template-columns: repeat(4, minmax(0, 1fr));
    border: 1px solid var(--line); border-radius: 6px; background: var(--surface); margin-top: 12px;
  }}
  .summary-item {{ padding: 12px 14px; border-left: 1px solid var(--line-soft); }}
  .summary-item:first-child {{ border-left: 0; }}
  .summary-item strong {{ display: block; font-size: 18px; line-height: 1.2; }}
  .summary-item span {{ display: block; margin-top: 4px; color: var(--muted); font-size: 12px; }}
  .management-grid {{ display: grid; grid-template-columns: minmax(0, 1fr) 330px; gap: 16px; margin-top: 16px; align-items: start; }}
  .main-stack, .side-stack {{ display: grid; gap: 16px; min-width: 0; }}
  .section-card {{ background: var(--surface); border: 1px solid var(--line); border-radius: 6px; padding: 0; }}
  .section-head {{ display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 12px 14px; border-bottom: 1px solid var(--line-soft); margin: 0; }}
  .section-head h2 {{ margin: 0; font-size: 15px; }}
  .section-head p {{ display: none; }}
  .todo-list {{ display: grid; }}
  .todo-row {{ display: grid; grid-template-columns: 92px minmax(0, 1fr); gap: 14px; padding: 14px; border-top: 1px solid var(--line-soft); }}
  .todo-row:first-child {{ border-top: 0; }}
  .todo-status span {{ display: block; color: var(--muted); font-weight: 700; }}
  .todo-status strong {{
    display: inline-flex; margin-top: 6px; border: 1px solid #f0c36a; border-radius: 999px;
    padding: 2px 8px; color: #7d4e00; background: #fff8e5; font-size: 12px;
  }}
  .todo-high .todo-status span, .todo-critical .todo-status span {{ color: var(--high); }}
  .todo-medium .todo-status span {{ color: var(--warn); }}
  .todo-main h3 {{ margin: 0 0 6px; font-size: 15px; line-height: 1.45; }}
  .todo-main p {{ margin: 0; color: var(--muted); font-size: 13px; }}
  .todo-meta {{ display: flex; gap: 10px; flex-wrap: wrap; color: var(--muted); font-size: 12px; margin-bottom: 5px; }}
  .todo-action {{ margin-top: 10px; border-left: 3px solid var(--line); padding-left: 10px; font-size: 13px; }}
  .todo-tech {{ margin-top: 10px; border: 0; padding: 0; font-size: 12px; }}
  .todo-tech summary {{
    display: inline-flex; width: auto; color: var(--accent); font-weight: 650;
    cursor: pointer; outline-offset: 2px;
  }}
  .todo-tech[open] {{ border-top: 1px solid var(--line-soft); padding-top: 10px; }}
  .todo-tech[open] summary {{ margin-bottom: 8px; }}
  .asset-table-wrap {{ overflow-x: auto; }}
  .asset-table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  .asset-table th, .asset-table td {{ padding: 10px 12px; border-top: 1px solid var(--line-soft); text-align: left; vertical-align: top; }}
  .asset-table thead th {{ border-top: 0; color: var(--muted); font-size: 12px; font-weight: 700; background: var(--surface-muted); }}
  .asset-table strong, .asset-table small, .asset-table td > span {{ display: block; }}
  .asset-table small {{ color: var(--muted); margin-top: 2px; }}
  .agent-unprofiled td {{ background: #fff8e1; }}
  .profile-warning {{ color: var(--warn); font-weight: 700; }}
  .profile-link {{ display: inline-block; margin-top: 6px; font-weight: 600; }}
  .state-ok {{ color: var(--ok); font-weight: 700; }}
  .state-warn {{ color: var(--warn); font-weight: 700; }}
  .dot {{ width: 8px; height: 8px; border-radius: 50%; display: inline-block; }}
  .dot-ok {{ background: var(--ok); }}
  .dot-warn {{ background: var(--warn); }}
  .status-row {{ display: grid; grid-template-columns: 10px minmax(0, .8fr) minmax(0, 1fr); gap: 4px 8px; align-items: center; padding: 10px 14px; border-top: 1px solid var(--line-soft); }}
  .status-row:first-child {{ border-top: 0; }}
  .status-row span {{ color: var(--muted); }}
  .status-row strong {{ text-align: right; font-size: 13px; }}
  .status-row small {{ grid-column: 2 / 4; color: var(--muted); font-size: 12px; }}
  .self-test {{ margin: 0; border-top: 1px solid var(--line-soft); padding: 12px 14px; }}
  .self-test-head {{ display: flex; align-items: center; justify-content: space-between; gap: 10px; }}
  .self-test-head h3 {{ margin: 0; font-size: 14px; }}
  .check-button {{ min-height: 30px; border: 1px solid var(--line); background: var(--surface); color: var(--text); border-radius: 6px; padding: 0 10px; font-weight: 600; cursor: pointer; }}
  .check-button:hover {{ background: var(--surface-muted); }}
  .self-result {{ margin-top: 10px; border: 1px solid var(--line-soft); border-radius: 6px; padding: 10px; background: var(--surface-muted); max-height: 360px; overflow: auto; }}
  .quiet-links {{ display: grid; padding: 8px 14px 12px; }}
  .quiet-links a {{ padding: 7px 0; border-top: 1px solid var(--line-soft); }}
  .quiet-links a:first-child {{ border-top: 0; }}
  .tech-grid {{ display: grid; grid-template-columns: 70px minmax(0, 1fr); gap: 6px; margin-top: 8px; }}
  code {{ background: var(--surface-muted); border: 1px solid var(--line-soft); border-radius: 4px; padding: 1px 4px; overflow-wrap: anywhere; }}
  a {{ color: var(--accent); text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  .empty-state {{ padding: 14px; border: 0; background: var(--surface); }}
  .empty-state strong, .empty-state span {{ display: block; }}
  .empty-state span {{ color: var(--muted); margin-top: 4px; }}
  @media (max-width: 900px) {{
    .management-top-inner, .management-main {{ width: min(100% - 24px, 1180px); }}
    .status-strip, .management-grid, .summary-row {{ grid-template-columns: 1fr; }}
    .next-action, .summary-item {{ border-left: 0; border-top: 1px solid var(--line-soft); padding-left: 0; padding-top: 12px; }}
    .summary-item:first-child {{ border-top: 0; }}
    .todo-row {{ grid-template-columns: 1fr; }}
  }}
  @media (max-width: 560px) {{
    .management-top-inner {{ align-items: flex-start; flex-direction: column; padding: 10px 0; }}
  }}
  .cal-shell {{
    --surface: #ffffff;
    --surface-muted: #f7f8fa;
    --text: #111827;
    --muted: #6b7280;
    --line: #e5e7eb;
    --line-strong: #d1d5db;
    --accent: #111827;
    --accent-soft: #f3f4f6;
    --blue: #2563eb;
    --ok: #16803c;
    --warn: #b7791f;
    --high: #d92d20;
    height: 100vh; min-height: 100vh; overflow-y: auto; overscroll-behavior: contain;
    background: #f7f8fa;
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Inter", "Noto Sans TC", "Segoe UI", sans-serif;
  }}
  .cal-shell * {{ box-shadow: none; letter-spacing: 0; }}
  .cal-top {{
    position: sticky; top: 0; z-index: 10;
    background: #ffffff;
    border-bottom: 1px solid var(--line);
  }}
  .cal-top-inner {{
    width: min(1160px, calc(100% - 32px)); min-height: 64px; margin: 0 auto;
    display: flex; align-items: center; justify-content: space-between; gap: 16px;
  }}
  .cal-brand {{ display: flex; align-items: center; gap: 10px; min-width: 0; }}
  .cal-mark {{
    width: 30px; height: 30px; border-radius: 7px; background: #111827;
    display: inline-flex; align-items: center; justify-content: center; color: #ffffff; font-size: 13px; font-weight: 800;
  }}
  .cal-brand strong {{ display: block; font-size: 15px; line-height: 1.2; }}
  .cal-brand span {{ display: block; margin-top: 1px; color: var(--muted); font-size: 12px; }}
  .cal-updated {{ color: var(--muted); font-size: 12px; white-space: nowrap; }}
  .cal-main {{ width: min(1160px, calc(100% - 32px)); margin: 0 auto; padding: 22px 0 44px; }}
  .cal-tabs {{
    display: flex; align-items: center; gap: 4px; margin-bottom: 16px;
    border-bottom: 1px solid var(--line); overflow-x: auto;
  }}
  .cal-tab {{
    flex: 0 0 auto; min-height: 38px; display: inline-flex; align-items: center;
    padding: 0 12px; border-bottom: 2px solid transparent;
    color: var(--muted); font-size: 14px; font-weight: 650; text-decoration: none;
  }}
  .cal-tab:hover {{ color: var(--text); text-decoration: none; }}
  .cal-tab.active {{ color: var(--text); border-bottom-color: var(--text); }}
  .cal-layout {{
    display: grid; grid-template-columns: minmax(0, 1fr) 340px; gap: 18px; align-items: start;
  }}
  .cal-layout-services {{
    grid-template-columns: minmax(0, 1fr);
  }}
  .cal-layout-services .cal-aside {{
    display: none;
  }}
  .cal-primary, .cal-aside {{ display: grid; gap: 16px; min-width: 0; }}
  .cal-hero, .cal-panel, .section-card {{
    background: var(--surface); border: 1px solid var(--line); border-radius: 8px;
  }}
  .cal-hero {{ padding: 20px; }}
  .cal-kicker {{ color: var(--muted); font-size: 12px; font-weight: 750; }}
  .cal-hero h1 {{ margin: 6px 0 8px; font-size: 28px; line-height: 1.18; font-weight: 760; }}
  .cal-hero p {{ margin: 0; max-width: 720px; color: var(--muted); font-size: 15px; }}
  .score-panel {{
    display: grid; grid-template-columns: 132px minmax(0, 1fr) auto; gap: 18px; align-items: center;
    background: var(--surface); border: 1px solid var(--line); border-radius: 8px; padding: 20px;
  }}
  .score-ring {{
    width: 108px; height: 108px; border-radius: 50%; border: 8px solid #111827;
    display: grid; place-content: center; text-align: center; background: #ffffff;
  }}
  .score-ring strong {{ display: block; font-size: 34px; line-height: 1; }}
  .score-ring span {{ display: block; margin-top: 4px; color: var(--muted); font-size: 12px; font-weight: 700; }}
  .score-ok .score-ring {{ border-color: var(--ok); }}
  .score-warn .score-ring {{ border-color: #f59e0b; }}
  .score-high .score-ring {{ border-color: var(--high); }}
  .score-label {{ color: var(--muted); font-size: 13px; font-weight: 750; }}
  .score-copy h1 {{ margin: 4px 0 6px; font-size: 26px; line-height: 1.2; }}
  .score-copy p {{ margin: 0; color: var(--muted); font-size: 15px; }}
  .score-copy small, .endpoint-score-copy small {{ display: block; margin-top: 6px; color: var(--muted); font-size: 12px; }}
  .score-actions {{ display: flex; flex-wrap: wrap; gap: 10px; justify-content: flex-end; }}
  .primary-action, .secondary-action {{
    min-height: 38px; display: inline-flex; align-items: center; justify-content: center;
    border-radius: 8px; padding: 0 14px; font-weight: 700; text-decoration: none; white-space: nowrap;
  }}
  .primary-action {{ background: #111827; color: #ffffff; border: 1px solid #111827; }}
  .secondary-action {{ background: #ffffff; color: var(--text); border: 1px solid var(--line-strong); }}
  .primary-action:hover, .secondary-action:hover {{ text-decoration: none; }}
  .primary-action:hover {{ background: #1f2937; }}
  .secondary-action:hover {{ background: var(--surface-muted); }}
  .flow-steps {{
    list-style: none; margin: 18px 0 0; padding: 0;
    display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); border: 1px solid var(--line); border-radius: 8px; overflow: hidden;
  }}
  .flow-steps li {{
    min-width: 0; display: grid; grid-template-columns: 32px minmax(0, 1fr); gap: 10px;
    padding: 12px; border-left: 1px solid var(--line); background: #ffffff;
  }}
  .flow-steps li:first-child {{ border-left: 0; }}
  .flow-steps span {{
    width: 28px; height: 28px; border-radius: 50%; background: var(--accent-soft);
    display: inline-flex; align-items: center; justify-content: center; font-weight: 750; font-size: 13px;
  }}
  .flow-steps .active span {{ background: #111827; color: #ffffff; }}
  .flow-steps strong {{ display: block; font-size: 13px; }}
  .flow-steps small {{ display: block; margin-top: 2px; color: var(--muted); font-size: 12px; overflow-wrap: anywhere; }}
  .owner-flow {{
    list-style: none; margin: 0; padding: 8px 16px 16px; display: grid; gap: 10px;
  }}
  .owner-flow li {{
    display: grid; grid-template-columns: minmax(120px, .35fr) minmax(0, 1fr) auto;
    gap: 12px; align-items: center; min-height: 54px; padding: 12px;
    border: 1px solid var(--line); border-radius: 8px; background: #ffffff;
  }}
  .owner-flow li.active {{ border-left: 4px solid #111827; padding-left: 9px; }}
  .owner-flow li.done {{ border-left: 4px solid var(--ok); padding-left: 9px; }}
  .owner-flow strong {{ font-size: 14px; }}
  .owner-flow span {{ color: var(--muted); font-size: 13px; }}
  .owner-flow a {{
    min-height: 32px; display: inline-flex; align-items: center; justify-content: center;
    border: 1px solid var(--line-strong); border-radius: 7px; padding: 0 10px;
    color: var(--text); font-size: 13px; font-weight: 650; white-space: nowrap;
  }}
  .owner-flow a:hover {{ background: var(--surface-muted); text-decoration: none; }}
  .owner-flow.compact {{ padding-top: 0; }}
  .setup-panel {{ align-items: center; }}
  .setup-checklist {{
    list-style: none; margin: 0; padding: 8px 16px 16px; display: grid; gap: 10px;
  }}
  .setup-checklist li {{
    display: grid; grid-template-columns: 82px minmax(160px, .5fr) minmax(0, 1fr) auto;
    gap: 12px; align-items: center; min-height: 62px; padding: 12px;
    border: 1px solid var(--line); border-radius: 8px; background: #ffffff;
  }}
  .setup-checklist li.done {{ border-left: 4px solid var(--ok); padding-left: 9px; }}
  .setup-checklist li.active {{ border-left: 4px solid #111827; padding-left: 9px; }}
  .setup-checklist li.pending {{ opacity: .72; }}
  .setup-checklist span {{
    display: inline-flex; align-items: center; justify-content: center; min-height: 26px;
    border: 1px solid var(--line); border-radius: 999px; color: var(--muted); font-size: 12px; font-weight: 750;
    background: var(--surface-muted);
  }}
  .setup-checklist li.done span {{ color: var(--ok); background: #f0fdf4; }}
  .setup-checklist li.active span {{ color: var(--text); background: #ffffff; border-color: var(--line-strong); }}
  .setup-checklist strong {{ font-size: 14px; }}
  .setup-checklist p {{ margin: 0; color: var(--muted); font-size: 13px; }}
  .setup-checklist a {{
    min-height: 34px; display: inline-flex; align-items: center; justify-content: center;
    border: 1px solid var(--line-strong); border-radius: 7px; padding: 0 10px;
    color: var(--text); font-size: 13px; font-weight: 650; white-space: nowrap;
  }}
  .setup-checklist a:hover {{ background: var(--surface-muted); text-decoration: none; }}
  .cal-panel {{ overflow: hidden; }}
  .cal-panel-head, .section-head {{
    display: flex; align-items: flex-start; justify-content: flex-start; gap: 16px;
    padding: 14px 16px; border-bottom: 1px solid var(--line); margin: 0;
  }}
  .section-title {{ min-width: 0; }}
  .cal-panel-head h2, .section-head h2 {{ margin: 0; font-size: 16px; line-height: 1.3; }}
  .cal-panel-head p, .section-head p {{ margin: 4px 0 0; color: var(--muted); font-size: 13px; display: block; }}
  .task-list {{ display: grid; }}
  .cal-task {{
    display: grid; grid-template-columns: 70px minmax(0, 1fr) 150px; gap: 16px;
    padding: 16px; border-top: 1px solid var(--line); background: #ffffff;
  }}
  .cal-task:first-child {{ border-top: 0; }}
  .cal-task-high, .cal-task-critical {{ border-left: 3px solid var(--high); }}
  .cal-task-medium {{ border-left: 3px solid var(--warn); }}
  .task-time span, .task-owner span {{ display: block; color: var(--muted); font-size: 12px; }}
  .task-time strong {{ display: block; margin-top: 2px; font-size: 15px; }}
  .task-body {{ min-width: 0; }}
  .task-meta {{ display: flex; align-items: center; flex-wrap: wrap; gap: 8px; color: var(--muted); font-size: 12px; margin-bottom: 6px; }}
  .risk-pill {{
    display: inline-flex; align-items: center; min-height: 22px; padding: 0 8px; border-radius: 999px;
    background: #eef2ff; color: #3730a3; font-weight: 750;
  }}
  .risk-high {{ background: #fef3f2; color: var(--high); }}
  .risk-medium {{ background: #fffbeb; color: #92400e; }}
  .risk-info {{ background: #eff6ff; color: #1d4ed8; }}
  .task-body h3 {{ margin: 0 0 6px; font-size: 16px; line-height: 1.45; }}
  .task-body p {{ margin: 0; color: var(--muted); font-size: 14px; }}
  .task-action {{
    margin-top: 12px; border: 1px solid var(--line); border-radius: 8px; padding: 10px 12px;
    background: var(--surface-muted);
  }}
  .task-action span {{ display: block; color: var(--muted); font-size: 12px; font-weight: 750; }}
  .task-action strong {{ display: block; margin-top: 3px; font-size: 14px; line-height: 1.45; }}
  .task-steps {{ margin: 8px 0 0; padding-left: 20px; color: var(--text); }}
  .task-steps li {{ margin-top: 4px; font-size: 13px; line-height: 1.45; }}
  .task-owner {{
    min-width: 0; border-left: 1px solid var(--line); padding-left: 14px;
  }}
  .task-owner strong {{ display: block; margin-top: 2px; font-size: 14px; overflow-wrap: anywhere; }}
  .case-status {{
    display: inline-flex; align-items: center; justify-content: center; min-height: 26px;
    margin-top: 10px; border-radius: 999px; padding: 0 9px;
    font-size: 12px; font-weight: 800; border: 1px solid var(--line);
    background: #ffffff; color: var(--text);
  }}
  .case-open {{ background: #fffbeb; color: #92400e; border-color: #f6d58a; }}
  .case-progress {{ background: #eff6ff; color: #1d4ed8; border-color: #bfdbfe; }}
  .case-closed {{ background: #f0fdf4; color: var(--ok); border-color: #bbf7d0; }}
  .case-actions {{
    display: grid; grid-template-columns: 1fr; gap: 7px; margin-top: 10px;
  }}
  .case-form {{ margin: 0; }}
  .case-form button {{
    width: 100%; min-height: 32px; border: 1px solid var(--line-strong);
    border-radius: 7px; background: #ffffff; color: var(--text);
    font: inherit; font-size: 13px; font-weight: 750; cursor: pointer;
  }}
  .case-form button:hover {{ background: var(--surface-muted); }}
  .owner-link {{
    display: inline-flex; align-items: center; justify-content: center; min-height: 32px;
    margin-top: 10px; border: 1px solid var(--line-strong); border-radius: 7px;
    padding: 0 10px; background: #ffffff; color: var(--text); font-size: 13px; font-weight: 650;
  }}
  .owner-link:hover {{ background: var(--surface-muted); text-decoration: none; }}
  .reply-note {{
    margin-top: 10px; padding-left: 10px; border-left: 3px solid var(--line);
    color: var(--muted); font-size: 12px; line-height: 1.45; font-weight: 650;
  }}
  .events {{ overflow: visible; }}
  .todo-tech {{ margin-top: 12px; border: 0; padding: 0; font-size: 12px; }}
  .todo-tech summary {{
    min-height: 34px; display: flex; align-items: center; justify-content: space-between;
    width: 100%; border: 1px solid var(--line); border-radius: 7px; padding: 0 10px;
    background: #ffffff; color: var(--text); font-weight: 700; cursor: pointer; list-style: none;
  }}
  .todo-tech summary::-webkit-details-marker {{ display: none; }}
  .todo-tech summary::after {{ content: "⌄"; color: var(--muted); font-size: 13px; }}
  .todo-tech[open] summary {{ background: var(--surface-muted); }}
  .todo-tech[open] summary::after {{ content: "⌃"; }}
  .tech-grid {{ display: grid; grid-template-columns: 82px minmax(0, 1fr); gap: 7px; margin-top: 8px; }}
  code {{ background: var(--surface-muted); border: 1px solid var(--line); border-radius: 4px; padding: 1px 5px; overflow-wrap: anywhere; }}
  .summary-card {{ padding: 16px; }}
  .summary-card h2 {{ margin: 0 0 12px; font-size: 16px; }}
  .summary-metric {{ display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 8px; padding: 10px 0; border-top: 1px solid var(--line); }}
  .summary-metric:first-of-type {{ border-top: 0; padding-top: 0; }}
  .summary-metric span {{ color: var(--muted); font-size: 13px; }}
  .summary-metric strong {{ font-size: 15px; text-align: right; }}
  .next-step-card {{ padding: 16px; border-left: 3px solid var(--accent); }}
  .next-step-card h2 {{ margin: 0 0 8px; font-size: 16px; }}
  .next-step-card p {{ margin: 0; color: var(--muted); }}
  .service-next-card {{ border-left-color: #f59e0b; }}
  .status-row {{ display: grid; grid-template-columns: 10px minmax(0, .8fr) minmax(0, 1fr); gap: 4px 8px; align-items: center; padding: 10px 16px; border-top: 1px solid var(--line); }}
  .status-row:first-child {{ border-top: 0; }}
  .status-row span {{ color: var(--muted); }}
  .status-row strong {{ text-align: right; font-size: 13px; }}
  .status-row small {{ grid-column: 2 / 4; color: var(--muted); font-size: 12px; }}
  .install-menu {{ position: relative; justify-self: start; }}
  .install-menu summary {{
    display: inline-flex; align-items: center; justify-content: center; min-height: 32px;
    border: 1px solid var(--line-strong); border-radius: 7px; padding: 0 12px;
    background: #ffffff; color: var(--text); font-size: 13px; font-weight: 650;
    cursor: pointer; list-style: none; white-space: nowrap;
  }}
  .install-menu summary::-webkit-details-marker {{ display: none; }}
  .install-menu summary::after {{ content: "⌄"; margin-left: 8px; color: var(--muted); font-size: 12px; }}
  .install-menu[open] summary {{ background: var(--surface-muted); }}
  .download-grid {{
    position: absolute; top: calc(100% + 8px); right: 0; z-index: 20;
    width: min(560px, calc(100vw - 40px)); display: grid; grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 8px; padding: 10px; border: 1px solid var(--line); border-radius: 8px;
    background: #ffffff; box-shadow: 0 12px 28px rgba(31,35,40,.14);
  }}
  .install-hint {{ grid-column: 1 / -1; margin: 0 0 2px; color: var(--muted); font-size: 12px; }}
  .download-button {{
    min-width: 0; display: grid; gap: 2px; padding: 10px 12px; border: 1px solid var(--line);
    border-radius: 8px; background: #ffffff; color: var(--text); text-decoration: none;
  }}
  .download-button:hover {{ background: var(--surface-muted); text-decoration: none; }}
  .download-button span {{ color: var(--muted); font-size: 12px; }}
  .download-button strong {{ font-size: 13px; overflow-wrap: anywhere; }}
  .install-steps {{ grid-column: 1 / -1; border: 1px solid var(--line); border-radius: 8px; background: #ffffff; }}
  .install-steps summary {{
    min-height: 34px; padding: 0 10px; border: 0; border-radius: 8px; justify-content: flex-start;
    color: var(--text); background: #ffffff; font-size: 13px;
  }}
  .install-steps[open] summary {{ border-bottom: 1px solid var(--line); border-radius: 8px 8px 0 0; }}
  .install-steps p {{ margin: 10px 10px 6px; color: var(--muted); font-size: 12px; }}
  .install-steps pre {{
    margin: 8px 10px 10px; padding: 10px; border: 1px solid var(--line); border-radius: 6px;
    background: var(--surface-muted); color: var(--text); font-size: 12px; line-height: 1.5;
    white-space: pre-wrap; overflow-wrap: anywhere;
  }}
  .service-panel {{ overflow: visible; padding: 0; }}
  .endpoint-score-card {{
    display: grid; grid-template-columns: 96px minmax(0, 1fr) auto; gap: 16px; align-items: center;
    margin: 14px 16px; padding: 14px; border: 1px solid var(--line); border-radius: 8px;
    background: #ffffff;
  }}
  .endpoint-score-number {{
    width: 78px; height: 78px; border-radius: 50%; border: 6px solid #111827;
    display: grid; place-content: center; text-align: center;
  }}
  .endpoint-score-number strong {{ display: block; font-size: 25px; line-height: 1; }}
  .endpoint-score-number span {{ display: block; margin-top: 3px; color: var(--muted); font-size: 11px; font-weight: 700; }}
  .endpoint-score-card.score-ok .endpoint-score-number {{ border-color: var(--ok); }}
  .endpoint-score-card.score-warn .endpoint-score-number {{ border-color: #f59e0b; }}
  .endpoint-score-card.score-high .endpoint-score-number {{ border-color: var(--high); }}
  .endpoint-score-copy span {{ display: block; color: var(--muted); font-size: 12px; font-weight: 750; }}
  .endpoint-score-copy strong {{ display: block; margin-top: 2px; font-size: 18px; line-height: 1.3; }}
  .endpoint-score-copy p {{ margin: 4px 0 0; color: var(--muted); font-size: 13px; }}
  .service-list-v2 {{ display: grid; }}
  .service-card {{
    display: grid; grid-template-columns: 10px minmax(260px, 1fr) minmax(360px, 460px) minmax(260px, 1fr); gap: 20px;
    padding: 16px; border-top: 1px solid var(--line); align-items: start; background: #ffffff;
  }}
  .service-card:first-child {{ border-top: 0; }}
  .service-card.agent-unprofiled {{
    margin: 0; border-radius: 0; background: #ffffff;
    border-left: 3px solid #f59e0b; padding-left: 13px; padding-right: 16px;
  }}
  .service-card > .dot {{ margin-top: 8px; }}
  .service-main strong, .service-main small {{ display: block; }}
  .service-main small {{ color: var(--muted); margin-top: 2px; }}
  .business-context {{
    min-width: 0; display: grid; gap: 5px; align-content: center;
    padding: 0;
  }}
  .business-context div {{
    display: grid; grid-template-columns: 42px minmax(0, 1fr); gap: 8px; align-items: baseline;
  }}
  .business-context b {{ color: var(--muted); font-size: 12px; font-weight: 650; }}
  .business-context strong {{
    min-width: 0; color: var(--text); font-size: 14px; line-height: 1.35; font-weight: 720;
    overflow-wrap: anywhere;
  }}
  .business-empty {{
    width: 100%; min-height: 64px; display: flex; align-items: center; justify-content: center;
    padding: 0;
  }}
  .service-status {{
    grid-column: 3; align-self: center; justify-self: center; width: min(100%, 460px);
    display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 12px; align-items: center;
  }}
  .service-status:empty {{ display: none; }}
  .context-empty strong {{ color: var(--muted); font-weight: 650; }}
  .endpoint-row-score {{
    grid-column: 4; justify-self: end; align-self: center;
    min-width: 96px; border: 1px solid var(--line); border-left: 4px solid var(--ok);
    border-radius: 8px; padding: 10px 12px; background: #ffffff;
  }}
  .endpoint-row-score.score-warn {{ border-left-color: #f59e0b; }}
  .endpoint-row-score.score-high {{ border-left-color: var(--high); }}
  .endpoint-score-detail {{ cursor: pointer; }}
  .endpoint-score-detail summary {{
    display: block; list-style: none;
  }}
  .endpoint-score-detail summary::-webkit-details-marker {{ display: none; }}
  .endpoint-score-detail summary::after {{
    content: "分數說明"; display: inline-flex; margin-top: 8px; min-height: 26px; align-items: center;
    border: 1px solid var(--line-strong); border-radius: 7px; padding: 0 8px;
    color: var(--text); background: #ffffff; font-size: 12px; font-weight: 700;
  }}
  .endpoint-score-detail[open] summary::after {{ content: "收起說明"; }}
  .endpoint-row-score strong {{ display: block; font-size: 24px; line-height: 1; color: var(--text); }}
  .endpoint-row-score span {{ display: block; margin-top: 4px; font-size: 12px; font-weight: 750; color: var(--text); }}
  .endpoint-row-score small {{ display: block; margin-top: 2px; color: var(--muted); font-size: 12px; }}
  .endpoint-score-breakdown {{
    margin-top: 10px; border-top: 1px solid var(--line); padding-top: 8px;
  }}
  .endpoint-score-breakdown b {{ display: block; margin-bottom: 6px; font-size: 12px; }}
  .endpoint-score-breakdown div {{
    display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 8px; padding: 4px 0;
  }}
  .endpoint-score-breakdown div span {{ margin: 0; color: var(--muted); font-weight: 650; }}
  .endpoint-score-breakdown div strong {{ font-size: 12px; text-align: right; }}
  .profile-link {{
    display: inline-flex; align-items: center; justify-content: center; min-height: 32px;
    border: 1px solid var(--line-strong); border-radius: 7px; padding: 0 10px;
    margin: 0; background: #ffffff; color: var(--text); font-size: 13px; font-weight: 650; white-space: nowrap;
  }}
  .profile-link:hover {{ background: var(--surface-muted); text-decoration: none; }}
  .icon-link {{
    width: 32px; padding: 0; font-size: 15px; line-height: 1;
  }}
  .drawer-backdrop {{
    position: fixed; inset: 0; z-index: 40; display: none;
    background: rgba(17, 24, 39, .28);
  }}
  .drawer-backdrop.open {{ display: block; }}
  .drawer-panel {{
    position: absolute; top: 0; right: 0; width: min(520px, 100vw); height: 100%;
    background: #ffffff; border-left: 1px solid var(--line); box-shadow: -12px 0 32px rgba(15, 23, 42, .16);
    transform: translateX(100%); transition: transform .18s ease; display: grid; grid-template-rows: 52px minmax(0, 1fr);
  }}
  .drawer-backdrop.open .drawer-panel {{ transform: translateX(0); }}
  .drawer-head {{
    display: flex; align-items: center; justify-content: space-between; gap: 12px;
    padding: 0 16px; border-bottom: 1px solid var(--line);
  }}
  .drawer-head strong {{ font-size: 14px; }}
  .drawer-close {{
    width: 44px; height: 44px; border: 1px solid var(--line-strong); border-radius: 8px;
    background: #ffffff; color: var(--text); cursor: pointer; font-size: 24px; line-height: 1;
  }}
  .drawer-close:hover {{ background: var(--surface-muted); }}
  .drawer-frame {{ width: 100%; height: 100%; border: 0; }}
  .service-tech {{
    grid-column: 2 / 5; margin: 0; border-top: 1px solid var(--line); padding-top: 10px;
    min-width: 0; font-size: 13px;
  }}
  .service-tech summary {{
    display: inline-flex; color: var(--muted); font-weight: 650; cursor: pointer; outline-offset: 2px;
  }}
  .service-tech summary:focus-visible {{ outline: 2px solid var(--line-strong); border-radius: 4px; }}
  .service-tech[open] summary {{ color: var(--text); margin-bottom: 10px; }}
  .service-tech-grid {{ display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 8px; }}
  .tech-field {{
    min-width: 0; border: 1px solid var(--line); border-radius: 7px; padding: 8px 10px;
    background: var(--surface-muted);
  }}
  .tech-field span {{ display: block; margin-bottom: 3px; color: var(--muted); font-size: 12px; }}
  .tech-field code {{
    display: block; border: 0; background: transparent; padding: 0; border-radius: 0;
    color: var(--text); overflow-wrap: anywhere; word-break: break-word;
  }}
  .quiet-links {{ display: grid; padding: 8px 16px 14px; }}
  .quiet-links a, .quiet-links .disabled-link {{ padding: 8px 0; border-top: 1px solid var(--line); }}
  .quiet-links a:first-child, .quiet-links .disabled-link:first-child {{ border-top: 0; }}
  .disabled-link {{ color: var(--muted); cursor: not-allowed; }}
  .top-rules {{ list-style: none; margin: 0; padding: 8px 16px 14px; display: grid; }}
  .top-rules li {{ display: grid; grid-template-columns: 42px minmax(0, 1fr); gap: 10px; padding: 10px 0; border-top: 1px solid var(--line); }}
  .top-rules li:first-child {{ border-top: 0; }}
  .top-rules strong {{ font-size: 18px; line-height: 1.2; }}
  .top-rules span {{ color: var(--muted); overflow-wrap: anywhere; }}
  .self-test {{ margin: 0; border-top: 1px solid var(--line); padding: 14px 16px; }}
  .self-test-head {{ display: flex; align-items: center; justify-content: space-between; gap: 10px; }}
  .self-test-head h3 {{ margin: 0; font-size: 14px; }}
  .check-button {{ min-height: 32px; border: 1px solid var(--line-strong); background: #ffffff; color: var(--text); border-radius: 7px; padding: 0 12px; font-weight: 650; cursor: pointer; }}
  .check-button:hover {{ background: var(--surface-muted); }}
  .self-result {{ margin-top: 10px; border: 1px solid var(--line); border-radius: 8px; padding: 10px; background: var(--surface-muted); max-height: 360px; overflow: auto; }}
  .notification-list {{ display: grid; padding: 6px 16px 14px; }}
  .notification-list div {{ display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 10px; padding: 10px 0; border-top: 1px solid var(--line); }}
  .notification-list div:first-child {{ border-top: 0; }}
  .notification-list span {{ color: var(--muted); font-size: 13px; }}
  .notification-list strong {{ font-size: 13px; text-align: right; }}
  .empty-state {{ padding: 16px; border: 0; background: #ffffff; }}
  .empty-state strong, .empty-state span {{ display: block; }}
  .empty-state span {{ color: var(--muted); margin-top: 4px; }}
  a {{ color: var(--blue); text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  @media (max-width: 960px) {{
    .cal-layout {{ grid-template-columns: 1fr; }}
    .cal-layout-services .cal-aside {{ grid-template-columns: 1fr; }}
    .score-panel {{ grid-template-columns: 110px minmax(0, 1fr); }}
    .score-actions {{ grid-column: 1 / 3; justify-content: flex-start; }}
    .score-ring {{ width: 96px; height: 96px; }}
    .owner-flow li {{ grid-template-columns: 1fr; align-items: start; }}
    .owner-flow a {{ justify-self: start; }}
    .setup-checklist li {{ grid-template-columns: 1fr; align-items: start; }}
    .setup-checklist span, .setup-checklist a {{ justify-self: start; }}
    .endpoint-score-card {{ grid-template-columns: 86px minmax(0, 1fr); }}
    .endpoint-score-card .primary-action {{ grid-column: 1 / 3; justify-self: start; }}
    .cal-task {{ grid-template-columns: 70px minmax(0, 1fr); }}
    .task-owner {{ grid-column: 2; border-left: 0; border-top: 1px solid var(--line); padding: 10px 0 0; }}
    .service-card {{ grid-template-columns: 18px minmax(0, 1fr); align-items: start; }}
    .service-status, .endpoint-row-score, .service-tech {{ grid-column: 2; }}
    .service-status {{ margin-top: 10px; }}
    .endpoint-row-score {{ justify-self: start; min-width: 120px; }}
    .service-tech-grid {{ grid-template-columns: 1fr; }}
  }}
  @media (max-width: 640px) {{
    .cal-top-inner {{ align-items: flex-start; flex-direction: column; padding: 10px 0; }}
    .cal-main, .cal-top-inner {{ width: min(100% - 24px, 1160px); }}
    .flow-steps, .cal-task {{ grid-template-columns: 1fr; }}
    .score-panel {{ grid-template-columns: 1fr; }}
    .score-ring {{ width: 108px; height: 108px; }}
    .score-actions {{ grid-column: auto; }}
    .endpoint-score-card {{ grid-template-columns: 1fr; }}
    .endpoint-score-card .primary-action {{ grid-column: auto; justify-self: stretch; }}
    .endpoint-score-number {{ width: 84px; height: 84px; }}
    .section-head {{ align-items: flex-start; }}
    .download-grid {{ width: min(320px, calc(100vw - 32px)); grid-template-columns: 1fr; }}
    .service-status {{ grid-template-columns: 1fr; }}
    .icon-link {{ width: 100%; }}
    .flow-steps li {{ border-left: 0; border-top: 1px solid var(--line); }}
    .flow-steps li:first-child {{ border-top: 0; }}
    .task-owner {{ grid-column: auto; }}
    .tech-grid {{ grid-template-columns: 1fr; }}
  }}
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
const button = document.getElementById("self-test-button");
const result = document.getElementById("self-test-result");
const iconMap = {{ ok: "✓", warn: "!", fail: "×", skip: "·" }};
const drawer = document.getElementById("context-drawer");
const drawerFrame = drawer ? drawer.querySelector(".drawer-frame") : null;
const drawerClose = drawer ? drawer.querySelector(".drawer-close") : null;

function escapeHtml(value) {{
  return String(value ?? "").replace(/[&<>"']/g, (ch) => ({{
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }}[ch]));
}}

function renderSelfTest(data) {{
  const overall = data.overall || "warn";
  result.className = `self-result result-${{overall}}`;
  const checks = (data.checks || []).map((check) => {{
    const icon = iconMap[check.status] || "?";
    const detail = check.detail_zh
      ? `<details><summary>給 IT 的細節</summary><code>${{escapeHtml(check.detail_zh)}}</code></details>`
      : "";
    return `
      <li>
        <span class="check-icon">${{icon}}</span>
        <div>
          <b>${{escapeHtml(check.label_zh)}}</b>
          <span>${{escapeHtml(check.summary_zh)}}</span>
          ${{check.next_step_zh ? `<span>${{escapeHtml(check.next_step_zh)}}</span>` : ""}}
        </div>
        ${{detail}}
      </li>`;
  }}).join("");
  result.innerHTML = `
    <strong>${{escapeHtml(data.title_zh || "檢查完成")}}</strong>
    <p>${{escapeHtml(data.message_zh || "")}}</p>
    ${{data.next_step_zh ? `<p>${{escapeHtml(data.next_step_zh)}}</p>` : ""}}
    <ul class="check-list">${{checks}}</ul>`;
}}

if (button && result) {{
  button.addEventListener("click", async () => {{
    button.disabled = true;
    button.textContent = "檢查中";
    result.className = "self-result";
    result.innerHTML = "<strong>檢查中</strong><p>正在確認系統服務狀態，請稍候。</p>";
    try {{
      const response = await fetch("/self-test", {{ headers: {{ "Accept": "application/json" }} }});
      if (!response.ok) throw new Error(`HTTP ${{response.status}}`);
      renderSelfTest(await response.json());
    }} catch (err) {{
      result.className = "self-result result-fail";
      result.innerHTML = "<strong>自我檢查無法執行</strong><p>請 IT 檢查 EdgeSec-Pi API 是否正常。</p>";
    }} finally {{
      button.disabled = false;
      button.textContent = "重新檢查";
    }}
  }});
}}

function drawerUrl(url) {{
  const next = new URL(url, window.location.origin);
  next.searchParams.set("embed", "1");
  return next.toString();
}}

if (drawer && drawerFrame && drawerClose) {{
  document.addEventListener("click", (event) => {{
    document.querySelectorAll(".install-menu[open]").forEach((menu) => {{
      if (!menu.contains(event.target)) menu.removeAttribute("open");
    }});
  }});
  document.querySelectorAll('a[href^="/admin/quick-add"], a[href*="/admin/quick-add"]').forEach((link) => {{
    link.addEventListener("click", (event) => {{
      event.preventDefault();
      drawerFrame.src = drawerUrl(link.href);
      drawer.classList.add("open");
      drawer.setAttribute("aria-hidden", "false");
      drawerClose.focus();
    }});
  }});
  function closeDrawer() {{
    drawer.classList.remove("open");
    drawer.setAttribute("aria-hidden", "true");
    drawerFrame.removeAttribute("src");
  }}
  drawerClose.addEventListener("click", closeDrawer);
  drawer.addEventListener("click", (event) => {{
    if (event.target === drawer) closeDrawer();
  }});
  document.addEventListener("keydown", (event) => {{
    if (event.key === "Escape" && drawer.classList.contains("open")) closeDrawer();
  }});
  window.addEventListener("message", (event) => {{
    if (event.origin === window.location.origin && event.data && event.data.type === "edgesec-close-drawer") {{
      closeDrawer();
      if (event.data.refresh) window.location.reload();
    }}
  }});
}}
</script>
</body>
</html>"""


@router.get("/", include_in_schema=False)
async def root() -> RedirectResponse:
    return RedirectResponse(url="/dashboard")


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request) -> HTMLResponse:
    stats = await db.compute_stats()

    # 管理層只看 medium 以上，Wazuh / API 保留全部細節給 IT。
    # 分 severity 抓，避免大量 info 告警把高風險事件擠出最近列表。
    event_candidates: list[dict[str, Any]] = []
    for severity in ("critical", "high", "medium"):
        event_candidates.extend(await db.list_alerts(limit=12, severity=severity, active_only=True))
    seen: set[int] = set()
    events: list[dict[str, Any]] = []
    for row in sorted(event_candidates, key=lambda r: r.get("received_at") or 0, reverse=True):
        row_id = int(row.get("id") or 0)
        if row_id in seen:
            continue
        seen.add(row_id)
        events.append(row)
        if len(events) >= 8:
            break

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
    except ValueError:
        pass
    return RedirectResponse(url="/dashboard#today-tasks", status_code=303)
