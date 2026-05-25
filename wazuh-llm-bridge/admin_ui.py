"""
/admin — Org profile editor (Phase 4)

Browser-based editor for org_profile.yaml so management / IT does not need vim
and YAML knowledge. Two entry points:

  • /admin            — full editor, HTTP Basic Auth only
  • /admin/quick-add  — single-agent form, accepts either Basic Auth OR a
                        signed token (used by Slack deep-links)

Mounted from app.py via:
    import admin_ui
    app.include_router(admin_ui.router)

Extracted from app.py — purely mechanical move, no behavioural change.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from typing import Annotated, Any, Optional
from urllib.parse import quote, urljoin

import yaml
from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import HTTPBasicCredentials

import admin_auth
import admin_token
import db
import notification_settings
import org_profile

log = logging.getLogger("wazuh-bridge")

router = APIRouter()


ADMIN_USER = admin_auth.ADMIN_USER
ADMIN_PASS = admin_auth.ADMIN_PASS
# Public URL used to construct deep-links sent to Slack. Empty disables
# the "configure this agent" button entirely (gracefully degrade).
BRIDGE_PUBLIC_URL = os.getenv("BRIDGE_PUBLIC_URL", "").rstrip("/")
DASHBOARD_V2_URL = os.getenv("DASHBOARD_V2_URL", "http://127.0.0.1:3000").rstrip("/")

_basic = admin_auth.basic_auth
_check_admin = admin_auth.check_admin
_authorize_quick_add = admin_auth.authorize_quick_add
_authorize_notifications = admin_auth.authorize_notifications


def _html_escape(s: Any) -> str:
    return (str(s) if s is not None else "").replace("&", "&amp;") \
                                             .replace("<", "&lt;")  \
                                             .replace(">", "&gt;")  \
                                             .replace('"', "&quot;")


def _dashboard_url(path: str = "/") -> str:
    return urljoin(f"{DASHBOARD_V2_URL}/", path.lstrip("/"))


def _render_admin_page(profile: dict[str, Any], flash: str = "") -> str:
    """Server-side render the admin form. No JS framework, no build step.
    Each list-of-things section uses a textarea where each line is one item
    (assets/users: one YAML-ish key=value line each). Crude but ships fast.
    """
    org = profile.get("org") or {}
    assets = profile.get("assets") or []
    users = profile.get("users") or []
    risk_notes = profile.get("risk_notes") or []
    escalation_hints = profile.get("escalation_hints") or []

    # Render assets/users as YAML for editability. The user can paste/edit
    # YAML lists directly. This sidesteps building a real grid editor.
    assets_yaml = yaml.safe_dump(assets, allow_unicode=True, sort_keys=False,
                                 indent=2) if assets else ""
    users_yaml  = yaml.safe_dump(users,  allow_unicode=True, sort_keys=False,
                                 indent=2) if users  else ""
    risk_text   = "\n".join(risk_notes)
    hints_text  = "\n".join(escalation_hints)

    flash_html = ""
    if flash:
        flash_html = (f'<div class="flash">{_html_escape(flash)}</div>')

    setup_url = _dashboard_url("/settings/status")
    return f"""<!doctype html>
<html lang="zh-Hant">
<head>
<meta charset="utf-8">
<title>EdgeSec-Pi 業務脈絡設定</title>
<style>
  body {{ font-family: -apple-system, "Noto Sans TC", sans-serif;
         max-width: 880px; margin: 2em auto; padding: 0 1em;
         color: #222; background: #fafafa; line-height: 1.5; }}
  h1 {{ border-bottom: 2px solid #2563eb; padding-bottom: .3em; }}
  h2 {{ color: #2563eb; margin-top: 2em; }}
  .flash {{ background: #ecfdf5; border: 1px solid #10b981; color: #065f46;
            padding: .8em 1em; border-radius: 6px; margin: 1em 0; }}
  label {{ display: block; margin-top: .8em; font-weight: 600; }}
  input[type=text], textarea {{ width: 100%; padding: .5em;
         border: 1px solid #d1d5db; border-radius: 4px;
         font-family: ui-monospace, "SF Mono", monospace; font-size: 13px;
         box-sizing: border-box; }}
  textarea {{ resize: vertical; }}
  .hint {{ color: #6b7280; font-size: 12px; margin-top: .2em; }}
  button {{ background: #2563eb; color: white; padding: .6em 1.4em;
           border: 0; border-radius: 4px; font-size: 15px; cursor: pointer;
           margin-top: 1.5em; }}
  button:hover {{ background: #1d4ed8; }}
  .meta {{ background: white; padding: 1em 1.4em; border-radius: 6px;
           border: 1px solid #e5e7eb; margin-bottom: 1em; font-size: 13px;
           color: #6b7280; }}
  code {{ background: #f3f4f6; padding: 1px 6px; border-radius: 3px; }}
</style>
</head>
<body>
<h1>業務脈絡設定 <small style="color:#9ca3af;font-size:.6em">EdgeSec-Pi /admin</small></h1>

<div class="meta">
  這份設定會在 LLM 判斷每一筆告警時，作為 <strong>業務脈絡</strong>注入到 prompt 裡。
  改完按存檔後，下一筆告警立刻生效，不用重啟 bridge。
  資料來源：<code>{_html_escape(str(org_profile.PROFILE_PATH))}</code>
</div>

{flash_html}

<form method="POST" action="/admin/save">

<h2>公司基本資料</h2>
<label>公司名稱</label>
<input type="text" name="org_name" value="{_html_escape(org.get('name',''))}">

<label>產業</label>
<input type="text" name="org_industry"
       value="{_html_escape(org.get('industry',''))}"
       placeholder="例：餐飲連鎖 / 銀行 / 電商 / SaaS / 醫療">

<label>主要時區</label>
<input type="text" name="org_timezone"
       value="{_html_escape(org.get('primary_timezone','Asia/Taipei'))}"
       placeholder="Asia/Taipei">

<label>公司簡介（2-3 句，LLM 會作為判斷背景）</label>
<textarea name="org_description" rows="3"
          placeholder="例：30 家門市的披薩連鎖，HQ 在台北，週一到五 9-7。我們處理信用卡資料但不在海外營運。">{_html_escape(org.get('description',''))}</textarea>


<h2>資產列表（YAML 格式，一個資產一個區塊）</h2>
<label>assets:</label>
<textarea name="assets_yaml" rows="14"
          placeholder="- pattern: db-finance-*
  role: PCI 範圍內財務 DB
  criticality: critical
  business_hours: Mon-Fri 09:00-19:00 Asia/Taipei
  pci_scope: true
  notes: 處理持卡人資料">{_html_escape(assets_yaml)}</textarea>
<div class="hint">
  pattern 支援 glob (例 <code>pos-*</code>)；criticality 用 critical / high / medium / low；
  business_hours 可留空代表 24/7。
</div>


<h2>使用者列表（YAML 格式，可留空）</h2>
<label>users:</label>
<textarea name="users_yaml" rows="8"
          placeholder="- name: bob
  role: 前端工程師
  notes: 幾乎不該 sudo">{_html_escape(users_yaml)}</textarea>


<h2>風險備註（每行一條，自由格式）</h2>
<label>risk_notes:</label>
<textarea name="risk_notes" rows="5"
          placeholder="持卡人資料只應在 db-finance 與 pos 之間流動">{_html_escape(risk_text)}</textarea>
<div class="hint">這些是給 LLM 推理時的背景資訊，越具體越好。</div>


<h2>升級規則（每行一條，硬性指令）</h2>
<label>escalation_hints:</label>
<textarea name="escalation_hints" rows="5"
          placeholder="在 db-finance 上的 sudo to root → 至少 high">{_html_escape(hints_text)}</textarea>
<div class="hint">
  這些是給 LLM 的硬性規則，會在套用 Wazuh-level rubric 之前生效。
</div>


<button type="submit">儲存設定</button>
</form>

</body>
</html>
"""


def _mask_status(value: str | None) -> str:
    return notification_settings.mask_status(value)


def _notification_value(key: str, default: str = "") -> str:
    return notification_settings.get_value(key, default)


def _secret_placeholder(value: str) -> str:
    return notification_settings.secret_placeholder(value)


def _notification_css() -> str:
    return """
  html, body { min-height: 100%; overflow-y: auto; }
  body { font-family: -apple-system, "Noto Sans TC", sans-serif; max-width: 1040px; margin: 0 auto; padding: 28px 20px 48px; color: #111827; background: #f7f8fa; line-height: 1.55; }
  h1 { margin: 0 0 6px; font-size: 25px; line-height: 1.2; }
  h3 { margin: 0; font-size: 16px; }
  p { color: #6b7280; margin: 0; }
  .grid { display: grid; gap: 14px; margin-top: 18px; }
  .card { background: #ffffff; border: 1px solid #d8dee8; border-radius: 8px; padding: 18px; }
  .card.primary-card { border-color: #cfd7e3; }
  .flash { background: #f3f4f6; border: 1px solid #d1d5db; border-radius: 8px; padding: 12px 14px; margin-top: 14px; }
  .head { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
  .head h2 { margin: 0; font-size: 18px; }
  .pill { display: inline-flex; min-height: 26px; align-items: center; border-radius: 999px; padding: 0 10px; font-size: 13px; font-weight: 700; }
  .ok { background: #ecfdf3; color: #166534; }
  .warn { background: #fffbeb; color: #92400e; }
  .rows { margin-top: 14px; display: grid; gap: 8px; }
  .row { display: grid; grid-template-columns: 180px minmax(0, 1fr); gap: 12px; padding-top: 8px; border-top: 1px solid #e5e7eb; }
  .row:first-child { border-top: 0; padding-top: 0; }
  .field-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; margin-top: 14px; }
  label { display: grid; gap: 6px; font-weight: 700; color: #374151; }
  input { min-height: 40px; border: 1px solid #d1d5db; border-radius: 8px; padding: 0 10px; font: inherit; background: #ffffff; color: #111827; }
  input::placeholder { color: #6b7280; opacity: 1; }
  .check { display: flex; align-items: center; gap: 8px; margin-top: 12px; font-weight: 700; }
  .check input { min-height: 18px; width: 18px; }
  .actions { margin-top: 16px; display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }
  .form-actions { margin-top: 16px; display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }
  .channel-layout { display: grid; grid-template-columns: minmax(0, 1fr) 280px; gap: 18px; align-items: start; margin-top: 14px; }
  .status-panel { border: 1px solid #e5e7eb; border-radius: 8px; padding: 14px; background: #fbfcfe; }
  .status-panel h3 { font-size: 15px; }
  .status-panel .rows { margin-top: 10px; gap: 0; }
  .status-panel .row { grid-template-columns: 92px minmax(0, 1fr); gap: 10px; padding: 9px 0; align-items: center; }
  .status-panel .row strong { color: #6b7280; font-size: 13px; font-weight: 700; }
  .status-panel .row span { color: #111827; font-size: 14px; font-weight: 700; text-align: right; overflow-wrap: anywhere; }
  .form-panel { min-width: 0; }
  .hint { margin-top: 6px; color: #6b7280; font-size: 13px; }
  .action-note { color: #6b7280; font-size: 13px; }
  .guide { margin: 14px 0 0; padding: 0; border-radius: 8px; background: #f9fafb; border: 1px solid #e5e7eb; }
  .guide summary { cursor: pointer; padding: 10px 12px; font-weight: 800; color: #374151; }
  .guide ol { margin: 0; padding: 0 12px 12px 32px; color: #374151; }
  .guide li { margin-top: 4px; }
  .advanced-settings { margin-top: 14px; border: 1px solid #e5e7eb; border-radius: 8px; background: #fbfcfe; }
  .advanced-settings summary { cursor: pointer; padding: 12px; font-weight: 800; color: #374151; }
  .advanced-settings:not([open]) .field-grid { display: none; }
  .advanced-settings .field-grid { margin: 0; padding: 0 12px 12px; }
  .channel-tabs { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 20px; border-bottom: 1px solid #d8dee8; }
  .channel-tab { min-height: 42px; display: inline-flex; align-items: center; padding: 0 14px; border: 1px solid transparent; border-bottom: 0; border-radius: 8px 8px 0 0; color: #6b7280; text-decoration: none; font-weight: 800; }
  .channel-tab.active { color: #111827; background: #ffffff; border-color: #d8dee8; margin-bottom: -1px; }
  a.button { min-height: 38px; display: inline-flex; align-items: center; justify-content: center; border-radius: 8px; padding: 0 14px; border: 1px solid #d1d5db; color: #111827; background: #ffffff; text-decoration: none; font-weight: 700; }
  a.primary, button.primary { background: #ffffff; color: #111827; border-color: #c9d2df; }
  button { min-height: 36px; border-radius: 8px; border: 1px solid #d1d5db; background: #ffffff; color: #111827; padding: 0 12px; font-weight: 700; cursor: pointer; }
  @media (max-width: 760px) {
    .channel-layout, .field-grid { grid-template-columns: 1fr; }
    .row, .status-panel .row { grid-template-columns: 1fr; }
  }
"""


def _notification_values() -> dict[str, Any]:
    return notification_settings.values()


def _save_notification_settings(form: Any, channel: str) -> str:
    return notification_settings.save(form, channel)


async def _test_notification_channel(channel: str) -> str:
    return await notification_settings.test_channel(channel)


def _token_query(token: str) -> str:
    return f"?t={_html_escape(token)}" if token else ""


def _notification_channel_url(channel: str, token: str = "", flash: str = "") -> str:
    return notification_settings.channel_url(channel, token, flash)


def _line_card(values: dict[str, Any], primary: bool = False, token: str = "") -> str:
    line_ready = bool(values["line_channel_token"] and values["line_user_id"])
    cls = "card primary-card" if primary else "card"
    tq = _token_query(token)
    return f"""
    <section class="{cls}" id="line">
      <div class="head">
        <h2>LINE</h2>
        <span class="pill {'ok' if line_ready else 'warn'}">{'已填設定' if line_ready else '尚未啟用'}</span>
      </div>
      <details class="guide">
        <summary>設定說明</summary>
        <ol>
          <li>把 LINE Channel Access Token 貼到第一格。</li>
          <li>把接收者 ID 貼到第二格。</li>
          <li>按「儲存 LINE」。</li>
          <li>按「測試 LINE」，手機收到訊息才算完成。</li>
        </ol>
      </details>
      <div class="channel-layout">
        <div class="form-panel">
          <form method="POST" action="/admin/notifications/line{tq}">
            <div class="field-grid">
              <label>LINE 權杖
                <input type="password" name="LINE_CHANNEL_ACCESS_TOKEN" value="" placeholder="{_html_escape(_secret_placeholder(values["line_channel_token"]))}" autocomplete="off">
                <span class="hint">Channel Access Token。已設定時可留空不改。</span>
              </label>
              <label>接收 LINE 的人
                <input type="text" name="LINE_USER_ID" value="{_html_escape(values["line_user_id"])}">
                <span class="hint">LINE User ID 或群組 ID。</span>
              </label>
            </div>
            <div class="form-actions">
              <button class="primary" type="submit">儲存 LINE</button>
              <button type="submit" form="line-test-form" {'disabled' if not line_ready else ''}>測試 LINE</button>
              <span class="action-note">{'收到測試訊息才算完成。' if line_ready else '先儲存 LINE 權杖與接收者，才能測試。'}</span>
            </div>
          </form>
          <form id="line-test-form" method="POST" action="/admin/notifications/line/test{tq}"></form>
        </div>
        <aside class="status-panel">
          <h3>目前狀態</h3>
          <div class="rows">
            <div class="row"><strong>權杖</strong><span>{_mask_status(values["line_channel_token"])}</span></div>
            <div class="row"><strong>接收者</strong><span>{_mask_status(values["line_user_id"])}</span></div>
            <div class="row"><strong>最後測試</strong><span>{_html_escape(values["line_tested_at"] or "尚未測試成功")}</span></div>
          </div>
        </aside>
      </div>
    </section>
    """


def _telegram_card(values: dict[str, Any], primary: bool = False, token: str = "") -> str:
    telegram_ready = bool(values["telegram_bot_token"] and values["telegram_chat_id"])
    cls = "card primary-card" if primary else "card"
    tq = _token_query(token)
    return f"""
    <section class="{cls}" id="telegram">
      <div class="head">
        <h2>Telegram</h2>
        <span class="pill {'ok' if telegram_ready else 'warn'}">{'已填設定' if telegram_ready else '尚未啟用'}</span>
      </div>
      <details class="guide">
        <summary>設定說明</summary>
        <ol>
          <li>用 BotFather 建立 bot，貼上 Bot Token。</li>
          <li>把 bot 加到要收通知的聊天室或群組。</li>
          <li>填入 Chat ID 後按「測試 Telegram」。</li>
        </ol>
      </details>
      <div class="channel-layout">
        <div class="form-panel">
          <form method="POST" action="/admin/notifications/telegram{tq}">
            <div class="field-grid">
              <label>Bot Token
                <input type="password" name="TELEGRAM_BOT_TOKEN" value="" placeholder="{_html_escape(_secret_placeholder(values["telegram_bot_token"]))}" autocomplete="off">
                <span class="hint">已設定時可留空不改。</span>
              </label>
              <label>Chat ID
                <input type="text" name="TELEGRAM_CHAT_ID" value="{_html_escape(values["telegram_chat_id"])}">
                <span class="hint">個人、群組或頻道的 chat_id。</span>
              </label>
            </div>
            <div class="form-actions">
              <button class="primary" type="submit">儲存 Telegram</button>
              <button type="submit" form="telegram-test-form" {'disabled' if not telegram_ready else ''}>測試 Telegram</button>
              <span class="action-note">{'收到測試訊息才算完成。' if telegram_ready else '先儲存 Bot Token 與 Chat ID，才能測試。'}</span>
            </div>
          </form>
          <form id="telegram-test-form" method="POST" action="/admin/notifications/telegram/test{tq}"></form>
        </div>
        <aside class="status-panel">
          <h3>目前狀態</h3>
          <div class="rows">
            <div class="row"><strong>Bot Token</strong><span>{_mask_status(values["telegram_bot_token"])}</span></div>
            <div class="row"><strong>Chat ID</strong><span>{_mask_status(values["telegram_chat_id"])}</span></div>
            <div class="row"><strong>最後測試</strong><span>{_html_escape(values["telegram_tested_at"] or "尚未測試成功")}</span></div>
          </div>
        </aside>
      </div>
    </section>
    """


def _slack_card(values: dict[str, Any], primary: bool = False, token: str = "") -> str:
    slack_ready = bool(values["slack_webhook"] or (values["slack_bot"] and values["slack_app"] and values["slack_channel"]))
    slack_interactive = bool(values["slack_bot"] and values["slack_app"] and values["slack_channel"])
    cls = "card primary-card" if primary else "card"
    tq = _token_query(token)
    return f"""
    <section class="{cls}" id="slack">
      <div class="head">
        <h2>Slack</h2>
        <span class="pill {'ok' if slack_ready else 'warn'}">{'可通知' if slack_ready else '未完成'}</span>
      </div>
      <div class="channel-layout">
        <div class="form-panel">
          <form method="POST" action="/admin/notifications/slack{tq}">
            <h3>簡易通知</h3>
            <p class="hint">只要想把告警送進 Slack，填這一格就夠。</p>
            <div class="field-grid">
              <label>Webhook URL
                <input type="password" name="SLACK_WEBHOOK_URL" value="" placeholder="{_html_escape(_secret_placeholder(values["slack_webhook"]))}" autocomplete="off">
                <span class="hint">已設定時可留空不改。</span>
              </label>
            </div>
            <details class="advanced-settings">
              <summary>進階：Slack 互動按鈕</summary>
              <div class="field-grid">
              <label>Channel ID
                <input type="text" name="SLACK_CHANNEL_ID" value="{_html_escape(values["slack_channel"])}">
                <span class="hint">例如 C 開頭頻道或 D 開頭私訊。</span>
              </label>
              <label>Bot Token
                <input type="password" name="SLACK_BOT_TOKEN" value="" placeholder="{_html_escape(_secret_placeholder(values["slack_bot"]))}" autocomplete="off">
                <span class="hint">互動按鈕需要。已設定時可留空不改。</span>
              </label>
              <label>App Token
                <input type="password" name="SLACK_APP_TOKEN" value="" placeholder="{_html_escape(_secret_placeholder(values["slack_app"]))}" autocomplete="off">
                <span class="hint">Socket Mode 需要。已設定時可留空不改。</span>
              </label>
              <label>公開連結
                <input type="text" name="BRIDGE_PUBLIC_URL" value="{_html_escape(values["bridge_public_url"])}" placeholder="https://你的網域">
                <span class="hint">Slack 裡的設定按鈕會用到。</span>
              </label>
              </div>
            </details>
            <div class="form-actions">
              <button class="primary" type="submit">儲存 Slack</button>
              <button type="submit" form="slack-test-form" {'disabled' if not slack_ready else ''}>測試 Slack</button>
              <span class="action-note">{'收到測試訊息才算完成。' if slack_ready else '先儲存 Webhook，或完整填入 Bot Token、App Token 與 Channel ID。'}</span>
            </div>
          </form>
          <form id="slack-test-form" method="POST" action="/admin/notifications/slack/test{tq}"></form>
        </div>
        <aside class="status-panel">
          <h3>目前狀態</h3>
          <div class="rows">
            <div class="row"><strong>Webhook</strong><span>{_mask_status(values["slack_webhook"])}</span></div>
            <div class="row"><strong>互動按鈕</strong><span>{'可用' if slack_interactive else '未完成'}</span></div>
            <div class="row"><strong>公開連結</strong><span>{_mask_status(values["bridge_public_url"])}</span></div>
            <div class="row"><strong>最後測試</strong><span>{_html_escape(values["slack_tested_at"] or "尚未測試成功")}</span></div>
          </div>
        </aside>
      </div>
    </section>
    """


def _email_card(values: dict[str, Any], primary: bool = False, token: str = "") -> str:
    email_ready = bool(values["smtp_host"] and values["email_from"] and values["email_to"])
    cls = "card primary-card" if primary else "card"
    tq = _token_query(token)
    return f"""
    <section class="{cls}" id="email">
      <div class="head">
        <h2>Email</h2>
        <span class="pill {'ok' if email_ready else 'warn'}">{'可通知' if email_ready else '未完成'}</span>
      </div>
      <div class="channel-layout">
        <div class="form-panel">
          <form method="POST" action="/admin/notifications/email{tq}">
            <div class="field-grid">
              <label>SMTP 主機
                <input type="text" name="SMTP_HOST" value="{_html_escape(values["smtp_host"])}">
              </label>
              <label>SMTP Port
                <input type="text" name="SMTP_PORT" value="{_html_escape(values["smtp_port"])}">
              </label>
              <label>帳號
                <input type="text" name="SMTP_USER" value="{_html_escape(values["smtp_user"])}">
              </label>
              <label>密碼
                <input type="password" name="SMTP_PASS" value="" placeholder="{_html_escape(_secret_placeholder(_notification_value("SMTP_PASS")))}" autocomplete="off">
              </label>
              <label>寄件者
                <input type="email" name="EMAIL_FROM" value="{_html_escape(values["email_from"])}">
              </label>
              <label>收件者
                <input type="text" name="EMAIL_TO" value="{_html_escape(values["email_to"])}" placeholder="boss@example.com, it@example.com">
              </label>
            </div>
            <label class="check"><input type="checkbox" name="SMTP_SSL" value="true" {'checked' if values["smtp_ssl"] else ''}> 使用 SSL</label>
            <label class="check"><input type="checkbox" name="SMTP_STARTTLS" value="true" {'checked' if values["smtp_starttls"] else ''}> 使用 STARTTLS</label>
            <div class="form-actions">
              <button class="primary" type="submit">儲存 Email</button>
              <button type="submit" form="email-test-form" {'disabled' if not email_ready else ''}>測試 Email</button>
              <span class="action-note">{'收到測試信才算完成。' if email_ready else '先儲存 SMTP 主機、寄件者與收件者，才能測試。'}</span>
            </div>
          </form>
          <form id="email-test-form" method="POST" action="/admin/notifications/email/test{tq}"></form>
        </div>
        <aside class="status-panel">
          <h3>目前狀態</h3>
          <div class="rows">
            <div class="row"><strong>SMTP 主機</strong><span>{_mask_status(values["smtp_host"])}</span></div>
            <div class="row"><strong>寄件者</strong><span>{_mask_status(values["email_from"])}</span></div>
            <div class="row"><strong>收件者</strong><span>{_mask_status(values["email_to"])}</span></div>
            <div class="row"><strong>最後測試</strong><span>{_html_escape(values["email_tested_at"] or "尚未測試成功")}</span></div>
          </div>
        </aside>
      </div>
    </section>
    """


def _render_notification_channel_page(channel: str, flash: str = "", token: str = "") -> str:
    values = _notification_values()
    cards = {
        "line": _line_card(values, primary=True, token=token),
        "slack": _slack_card(values, primary=True, token=token),
        "telegram": _telegram_card(values, primary=True, token=token),
        "email": _email_card(values, primary=True, token=token),
    }
    titles = {"line": "LINE 通知", "slack": "Slack 通知", "telegram": "Telegram 通知", "email": "Email 通知"}
    if channel not in cards:
        raise HTTPException(status_code=404, detail="Unknown notification channel")
    tabs = _notification_tabs(channel, token)
    flash_html = f'<div class="flash">{_html_escape(flash)}</div>' if flash else ""
    setup_url = _dashboard_url("/settings/status")
    return f"""<!doctype html>
<html lang="zh-Hant">
<head>
<meta charset="utf-8">
<title>EdgeSec-Pi {titles[channel]}</title>
<style>{_notification_css()}</style>
</head>
<body>
  <div class="head">
    <div>
      <h1>通知設定</h1>
      <p>每次只設定一個管道。切換頁籤不會改到其他通知設定。</p>
    </div>
    <a class="button primary" href="{setup_url}">回上線設定</a>
  </div>
  {tabs}
  {flash_html}
  <div class="grid">{cards[channel]}</div>
  <div class="actions">
    <a class="button primary" href="{setup_url}">回上線設定</a>
  </div>
</body>
</html>"""


def _notification_tabs(active: str, token: str = "") -> str:
    channels = [("line", "LINE"), ("slack", "Slack"), ("telegram", "Telegram"), ("email", "Email")]
    token_part = f"&t={quote(token)}" if token else ""
    links = []
    for key, label in channels:
        active_class = "active" if key == active else ""
        current_attr = 'aria-current="page"' if key == active else ""
        links.append(
            f'<a class="channel-tab {active_class}" href="/admin/notifications?channel={key}{token_part}" {current_attr}>{label}</a>'
        )
    return """
  <nav class="channel-tabs" aria-label="通知管道">
    """ + "\n".join(links) + """
  </nav>
    """


def _render_notifications_page(flash: str = "", token: str = "", channel: str = "line") -> str:
    values = _notification_values()
    cards = {
        "line": _line_card(values, primary=True, token=token),
        "slack": _slack_card(values, primary=True, token=token),
        "telegram": _telegram_card(values, primary=True, token=token),
        "email": _email_card(values, primary=True, token=token),
    }
    if channel not in cards:
        channel = "line"
    tabs = _notification_tabs(channel, token)
    flash_html = f'<div class="flash">{_html_escape(flash)}</div>' if flash else ""

    setup_url = _dashboard_url("/settings/status")
    return f"""<!doctype html>
<html lang="zh-Hant">
<head>
<meta charset="utf-8">
<title>EdgeSec-Pi 通知設定</title>
<style>{_notification_css()}</style>
</head>
<body>
  <div class="head">
    <div>
      <h1>通知設定</h1>
      <p>LINE、Slack、Telegram、Email 可各自設定。至少一個管道測試成功後，就能回上線設定繼續安裝 Agent。</p>
    </div>
    <a class="button primary" href="{setup_url}">回上線設定</a>
  </div>
  {tabs}
  {flash_html}

  <div class="grid">
    {cards[channel]}
  </div>

  <div class="actions">
    <a class="button primary" href="{setup_url}">回上線設定</a>
  </div>
</body>
</html>"""


@router.get("/admin", response_class=HTMLResponse)
async def admin_page(_: str = Depends(_check_admin)) -> str:
    return _render_admin_page(org_profile.current())


@router.get("/admin/notifications", response_class=HTMLResponse)
async def admin_notifications(
    channel: str = "line",
    t: str = "",
    creds: Annotated[Optional[HTTPBasicCredentials], Depends(_basic)] = None,
) -> str:
    _authorize_notifications(t, creds)
    return _render_notifications_page(token=t, channel=channel)


@router.post("/admin/notifications", response_class=HTMLResponse)
async def admin_notifications_save(
    request: Request,
    t: str = "",
    creds: Annotated[Optional[HTTPBasicCredentials], Depends(_basic)] = None,
) -> HTMLResponse:
    _authorize_notifications(t, creds)
    form = await request.form()
    channel = str(form.get("channel") or "").strip().lower()
    flash = _save_notification_settings(form, channel)
    return HTMLResponse(_render_notifications_page(flash=flash, token=t, channel=channel or "line"))


@router.post("/admin/notifications/test", response_class=HTMLResponse)
async def admin_notifications_test(
    channel: Annotated[str, Form()],
    t: str = "",
    creds: Annotated[Optional[HTTPBasicCredentials], Depends(_basic)] = None,
) -> HTMLResponse:
    _authorize_notifications(t, creds)
    try:
        flash = await _test_notification_channel(channel)
    except Exception as exc:
        flash = f"測試失敗：{exc}"
    return HTMLResponse(_render_notifications_page(flash=flash, token=t, channel=channel))


@router.get("/admin/notifications/{channel}", response_class=HTMLResponse)
async def admin_notification_channel(
    channel: str,
    t: str = "",
    flash: str = "",
    creds: Annotated[Optional[HTTPBasicCredentials], Depends(_basic)] = None,
) -> str:
    _authorize_notifications(t, creds)
    return _render_notification_channel_page(channel, flash=flash, token=t)


@router.post("/admin/notifications/{channel}", response_class=HTMLResponse)
async def admin_notification_channel_save(
    channel: str,
    request: Request,
    t: str = "",
    creds: Annotated[Optional[HTTPBasicCredentials], Depends(_basic)] = None,
) -> HTMLResponse:
    _authorize_notifications(t, creds)
    form = await request.form()
    flash = _save_notification_settings(form, channel)
    return HTMLResponse(_render_notification_channel_page(channel, flash=flash, token=t))


@router.post("/admin/notifications/{channel}/test", response_class=HTMLResponse)
async def admin_notification_channel_test(
    channel: str,
    t: str = "",
    creds: Annotated[Optional[HTTPBasicCredentials], Depends(_basic)] = None,
) -> RedirectResponse:
    _authorize_notifications(t, creds)
    try:
        flash = await _test_notification_channel(channel)
    except Exception as exc:
        flash = f"測試失敗：{exc}"
    return RedirectResponse(_notification_channel_url(channel, t, flash), status_code=303)


@router.get("/admin/notifications/{channel}/test")
async def admin_notification_channel_test_get(
    channel: str,
    t: str = "",
    creds: Annotated[Optional[HTTPBasicCredentials], Depends(_basic)] = None,
) -> RedirectResponse:
    _authorize_notifications(t, creds)
    return RedirectResponse(
        _notification_channel_url(channel, t, "請使用頁面上的測試按鈕。"),
        status_code=303,
    )


@router.post("/admin/save")
async def admin_save(
    _: str = Depends(_check_admin),
    org_name:         str = Form(""),
    org_industry:     str = Form(""),
    org_timezone:     str = Form("Asia/Taipei"),
    org_description:  str = Form(""),
    assets_yaml:      str = Form(""),
    users_yaml:       str = Form(""),
    risk_notes:       str = Form(""),
    escalation_hints: str = Form(""),
):
    """Parse the submitted form, validate the YAML chunks, write profile back."""
    try:
        assets = yaml.safe_load(assets_yaml) if assets_yaml.strip() else []
        users  = yaml.safe_load(users_yaml)  if users_yaml.strip()  else []
    except yaml.YAMLError as e:
        return HTMLResponse(
            _render_admin_page(
                org_profile.current(),
                flash=f"❌ YAML 解析錯誤：{e!s} — 沒有儲存",
            ),
            status_code=400,
        )

    if assets and not isinstance(assets, list):
        return HTMLResponse(
            _render_admin_page(org_profile.current(),
                               flash="❌ assets 必須是 list（每筆以 '- pattern: ...' 開頭）"),
            status_code=400,
        )
    if users and not isinstance(users, list):
        return HTMLResponse(
            _render_admin_page(org_profile.current(),
                               flash="❌ users 必須是 list"),
            status_code=400,
        )

    new_profile = {
        "org": {
            "name":             org_name.strip(),
            "industry":         org_industry.strip(),
            "primary_timezone": org_timezone.strip() or "Asia/Taipei",
            "description":      org_description.strip(),
        },
        "assets":           assets or [],
        "users":            users  or [],
        "risk_notes":       [s.strip() for s in risk_notes.splitlines() if s.strip()],
        "escalation_hints": [s.strip() for s in escalation_hints.splitlines() if s.strip()],
    }

    org_profile.save(new_profile)
    log.info("admin saved org profile (%d assets, %d users, %d risk notes, %d hints)",
             len(new_profile["assets"]), len(new_profile["users"]),
             len(new_profile["risk_notes"]), len(new_profile["escalation_hints"]))
    return HTMLResponse(_render_admin_page(
        org_profile.current(),
        flash=f"✅ 已儲存。下一筆告警會立刻使用新設定。",
    ))


@router.post("/admin/reload")
async def admin_reload(_: str = Depends(_check_admin)) -> dict[str, Any]:
    """Re-read org_profile.yaml from disk (useful if someone edited it
    directly with an editor instead of through the form)."""
    org_profile.load()
    return {"ok": True, "loaded_from": str(org_profile.PROFILE_PATH)}


# ── /admin/quick-add — focused single-agent form (Slack deep-link target) ─

def _format_recent_alerts_panel(rows: list[dict[str, Any]]) -> str:
    """Render the 'Recent alerts on this agent' card for quick-add.

    Docker-style: card with a row per alert (time | severity pill | rule |
    user). Returns empty string when there's nothing to show so the page
    doesn't display an empty card.
    """
    if not rows:
        return ""
    sev_color = {"critical": "#dc2626", "high": "#ea580c",
                 "medium":   "#ca8a04", "low":  "#2563eb",
                 "info":     "#6b7280"}
    items = []
    for r in rows[:5]:
        ts = r.get("received_at") or 0
        try:
            t_str = datetime.fromtimestamp(ts).strftime("%m/%d %H:%M")
        except Exception:
            t_str = "?"

        # Username — try structured fields from raw_alert first, then full_log.
        username = None
        raw_alert = r.get("raw_alert")
        if raw_alert:
            try:
                username = org_profile._guess_user(json.loads(raw_alert))
            except Exception:
                pass

        sev   = (r.get("llm_severity") or "?").lower()
        color = sev_color.get(sev, "#6b7280")
        rid   = r.get("rule_id") or "?"
        rdesc = (r.get("rule_description") or "").strip()[:55]
        user_html = (f'<span class="recent-usr">'
                     f'使用者：<strong>{_html_escape(username)}</strong></span>'
                     if username else '<span></span>')

        items.append(f"""
    <li class="recent-row">
      <span class="recent-time">{_html_escape(t_str)}</span>
      <span class="recent-sev" style="background:{color}">{_html_escape(sev)}</span>
      <span class="recent-rule">
        <span class="rid">rule {_html_escape(str(rid))}</span>
        {_html_escape(rdesc)}
      </span>
      {user_html}
    </li>""")
    return f"""
<section class="card">
  <div class="card-label">最近活動 · {len(rows)} 筆</div>
  <ul class="recent-list">{''.join(items)}
  </ul>
</section>
"""


def _render_quick_add(agent: str,
                      existing: Optional[dict[str, Any]],
                      token: str = "",
                      flash: str = "",
                      who:   str = "",
                      recent: Optional[list[dict[str, Any]]] = None,
                      embed: bool = False) -> str:
    """Minimal 4-field form for adding/editing one asset.

    Designed so management can open a Slack deep-link and fill this in quickly.

    Two entry modes:
      1. agent provided (from Slack deep-link or /admin link): show as a
         locked label, no rename allowed.
      2. agent empty (someone typed /admin/quick-add directly): show an
         input field so IT can type the device name in.

    `existing` is the matched asset entry (if any) so we can pre-fill the
    form when the agent is already profiled.
    `who`      identifies the authenticated actor (for the header chip).
    """
    flash_html = ""
    if flash:
        flash_html = f'<div class="flash">{_html_escape(flash)}</div>'

    role         = (existing or {}).get("role", "")
    owner        = (existing or {}).get("owner", "")
    criticality  = (existing or {}).get("criticality", "medium")
    biz_hours    = (existing or {}).get("business_hours", "")
    pci_scope    = bool((existing or {}).get("pci_scope", False))
    notes        = (existing or {}).get("notes", "")

    if existing:
        title_zh = "端點業務背景"
        btn_zh   = "儲存"
    elif agent:
        title_zh = "端點業務背景"
        btn_zh   = "儲存"
    else:
        title_zh = "端點業務背景"
        btn_zh   = "儲存"

    def opt(value: str, current: str, label: str) -> str:
        sel = " selected" if value == current else ""
        return f'<option value="{_html_escape(value)}"{sel}>{_html_escape(label)}</option>'

    token_input = (f'<input type="hidden" name="t" value="{_html_escape(token)}">'
                   if token else "")
    embed_input = '<input type="hidden" name="embed" value="1">' if embed else ""

    # When the agent name comes pre-filled (from Slack / /admin link),
    # show it as a non-editable badge (above form) + hidden form field.
    # When agent is empty, show an editable text input inside the form.
    if agent:
        agent_info_box = f"""<div class="agent">
  目標 Wazuh agent：<strong>{_html_escape(agent)}</strong>
  {"（目前已在設定裡，下方為現況可直接修改）"
       if existing else "（目前未登記，新增中）"}
</div>"""
        agent_input_html = (
            f'<input type="hidden" name="agent" '
            f'value="{_html_escape(agent)}">'
        )
    else:
        agent_info_box = """<div class="agent">
  <strong>未指定 Wazuh agent</strong> —
  下方第一個欄位輸入要設定的設備名稱或 glob pattern。
</div>"""
        agent_input_html = """
  <label>設備名稱 / pattern</label>
  <input type="text" name="agent" id="agent_input" required autofocus
         placeholder="例：db-finance-01 ／ pos-* ／ web-prod-*">
  <div class="hint">
    支援 glob：<code>pos-*</code> 會 match pos-001, pos-002…；
    精確名稱：<code>db-finance-01</code> 只 match 那一台。
  </div>
"""

    # Header chip: who's logged in. Pill in the topbar (Docker-style).
    if who.startswith("token:"):
        who_html = (
            f'<span class="who-chip" title="Slack 連結 token">'
            f'<span class="dot" style="background:#f59e0b"></span>'
            f'token · <strong>{_html_escape(who[6:])}</strong>'
            f'</span>'
        )
    elif who:
        who_html = (
            f'<span class="who-chip">'
            f'<span class="dot"></span>'
            f'<strong>{_html_escape(who)}</strong>'
            f'</span>'
        )
    else:
        who_html = ""

    # ---- Docker Desktop-style layout helpers ---------------------------
    # Status pill: green when asset is already in profile, amber when new.
    if agent and existing:
        status_pill = '<span class="pill pill-ok">已設定</span>'
        status_text = "AI 會用這些背景解讀這台端點的告警。"
    elif agent:
        status_pill = '<span class="pill pill-warn">未設定</span>'
        status_text = "請補上這台端點的用途，讓 AI 判斷告警時有業務背景。"
    else:
        status_pill = '<span class="pill pill-muted">待輸入</span>'
        status_text = "先輸入要設定的設備名稱。"

    # Recent alerts list (already returns empty string when no rows).
    recent_html = _format_recent_alerts_panel(recent or [])
    recent_details = (
        f"""
        <details class="technical-reference">
          <summary>最近活動（技術參考）</summary>
          {recent_html}
        </details>
        """
        if recent_html else ""
    )
    # Agent identity row (inside the hero card).
    if agent:
        agent_display = f'<code class="hero-name">{_html_escape(agent)}</code>'
        agent_form_input = (
            f'<input type="hidden" name="agent" value="{_html_escape(agent)}">'
        )
    else:
        agent_display = ""
        agent_form_input = """
        <div class="field">
          <label for="agent_input">設備名稱 / pattern</label>
          <input type="text" name="agent" id="agent_input" required autofocus
                 placeholder="db-finance-01  或  pos-*">
          <div class="hint">
            支援 glob：<code>pos-*</code> 會 match pos-001, pos-002…；
            精確名稱：<code>db-finance-01</code> 只 match 那一台。
          </div>
        </div>
        """

    body_class = "drawer-mode" if embed else ""
    topbar_html = "" if embed else f"""
<div class="topbar">
  <div class="brand">
    EdgeSec-Pi <span class="sep">·</span><span class="page">{title_zh}</span>
  </div>
  <div>{who_html}</div>
</div>
"""

    return f"""<!doctype html>
<html lang="zh-Hant">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title_zh}{(' · ' + _html_escape(agent)) if agent else ''} — EdgeSec-Pi</title>
<style>
  :root {{
    --bg:        #f3f4f6;
    --card:      #ffffff;
    --border:    #e5e7eb;
    --text:      #111827;
    --muted:    #6b7280;
    --primary:  #2563eb;
    --primary-h:#1d4ed8;
    --ok:       #10b981;
    --warn:     #f59e0b;
    --danger:   #dc2626;
    --shadow:    0 1px 2px rgba(0,0,0,.04), 0 1px 3px rgba(0,0,0,.06);
  }}
  * {{ box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Noto Sans TC",
                 "Segoe UI", "Helvetica Neue", Arial, sans-serif;
    margin: 0; padding: 0;
    background: var(--bg); color: var(--text);
    line-height: 1.55; font-size: 14px;
    -webkit-font-smoothing: antialiased;
  }}
  body.drawer-mode {{
    background: #ffffff;
  }}
  /* ── Topbar ──────────────────────────────────────────────────────── */
  .topbar {{
    background: var(--card); border-bottom: 1px solid var(--border);
    padding: 14px 24px; display: flex; align-items: center;
    justify-content: space-between; position: sticky; top: 0; z-index: 10;
  }}
  .brand {{ font-weight: 600; font-size: 15px; }}
  .brand .sep {{ color: var(--muted); margin: 0 .5em; }}
  .brand .page {{ color: var(--muted); font-weight: 400; }}
  .who-chip {{
    display: inline-flex; align-items: center; gap: 6px;
    background: var(--bg); border: 1px solid var(--border);
    color: var(--muted); font-size: 12px;
    padding: 4px 10px; border-radius: 999px;
  }}
  .who-chip strong {{ color: var(--text); }}
  .who-chip .dot {{
    width: 7px; height: 7px; border-radius: 50%;
    background: var(--ok); display: inline-block;
  }}

  /* ── Main container ─────────────────────────────────────────────── */
  main {{ max-width: 720px; margin: 0 auto; padding: 24px; }}
  body.drawer-mode main {{ max-width: none; padding: 18px; }}

  .flash {{
    background: #ecfdf5; border: 1px solid #a7f3d0; color: #065f46;
    padding: 12px 16px; border-radius: 8px; margin-bottom: 16px;
    font-size: 13px;
  }}

  /* ── Cards ──────────────────────────────────────────────────────── */
  .card {{
    background: var(--card); border: 1px solid var(--border);
    border-radius: 10px; padding: 18px 22px; margin-bottom: 16px;
    box-shadow: var(--shadow);
  }}
  body.drawer-mode .card {{
    border-radius: 8px; box-shadow: none; padding: 14px 0; border-width: 0 0 1px 0;
    margin-bottom: 0;
  }}
  .card-label {{
    text-transform: uppercase; letter-spacing: .04em;
    font-size: 11px; font-weight: 600; color: var(--muted);
    margin-bottom: 8px;
  }}

  /* ── Hero card (agent identity) ─────────────────────────────────── */
  .hero {{ padding: 22px 24px; }}
  body.drawer-mode .hero {{ padding-top: 2px; }}
  .hero-name {{
    font-family: ui-monospace, "SF Mono", "Menlo", monospace;
    font-size: 22px; font-weight: 600;
    background: transparent; padding: 0;
    color: var(--text);
  }}
  body.drawer-mode .hero-name {{ font-size: 18px; }}
  .hero-row {{ display: flex; align-items: center; gap: 12px;
               flex-wrap: wrap; margin-top: 4px; }}
  .hero-desc {{ color: var(--muted); font-size: 13px; }}

  /* ── Status pills ───────────────────────────────────────────────── */
  .pill {{
    display: inline-block; font-size: 11px; font-weight: 600;
    padding: 2px 10px; border-radius: 999px;
    text-transform: uppercase; letter-spacing: .03em;
  }}
  .pill-ok    {{ background: #d1fae5; color: #065f46; }}
  .pill-warn  {{ background: #fef3c7; color: #92400e; }}
  .pill-muted {{ background: var(--bg); color: var(--muted);
                 border: 1px solid var(--border); }}

  /* ── Recent activity ────────────────────────────────────────────── */
  .recent-list {{ list-style: none; padding: 0; margin: 0; }}
  .recent-row {{
    display: grid;
    grid-template-columns: 96px 70px 1fr auto; gap: 10px;
    align-items: center; padding: 9px 0;
    border-top: 1px solid var(--border);
    font-size: 13px;
  }}
  .recent-row:first-child {{ border-top: 0; padding-top: 0; }}
  .recent-time {{ color: var(--muted);
                  font-family: ui-monospace, monospace; font-size: 12px; }}
  .recent-sev  {{
    display: inline-block; color: white; font-size: 10px; font-weight: 600;
    padding: 2px 8px; border-radius: 999px;
    text-transform: uppercase; text-align: center;
  }}
  .recent-rule {{ color: var(--text); }}
  .recent-rule .rid {{
    font-family: ui-monospace, monospace; font-size: 12px;
    color: var(--muted); margin-right: 8px;
  }}
  .recent-usr {{ color: #1e40af; font-size: 12px; white-space: nowrap; }}
  .recent-usr strong {{ font-weight: 600; }}
  .technical-reference {{
    margin-top: 14px; border-top: 1px solid var(--border); padding-top: 12px;
  }}
  .technical-reference summary {{
    cursor: pointer; color: var(--muted); font-size: 13px; font-weight: 600;
  }}
  .technical-reference .card {{
    margin-top: 10px; padding: 0; border: 0;
  }}
  body.drawer-mode .recent-row {{
    grid-template-columns: 74px 62px minmax(0, 1fr); gap: 8px;
  }}
  body.drawer-mode .recent-usr {{ display: none; }}

  /* ── Form ──────────────────────────────────────────────────────── */
  .field {{ margin-bottom: 16px; }}
  .field:last-child {{ margin-bottom: 0; }}
  .field label {{ display: block; font-weight: 600; font-size: 13px;
                  margin-bottom: 6px; }}
  .field input[type=text], .field select, .field textarea {{
    width: 100%; padding: 9px 12px;
    border: 1px solid var(--border); border-radius: 6px;
    font-size: 14px; color: var(--text);
    background: var(--card); font-family: inherit;
    transition: border-color .15s, box-shadow .15s;
  }}
  .field input[type=text]:focus, .field select:focus, .field textarea:focus {{
    outline: none; border-color: var(--primary);
    box-shadow: 0 0 0 3px rgba(37, 99, 235, .12);
  }}
  .field textarea {{ resize: vertical; min-height: 70px; }}
  .hint {{ color: var(--muted); font-size: 12px; margin-top: 6px; }}
  .presets {{ margin-top: 8px; }}
  .preset {{
    display: inline-block; margin-right: 6px; margin-top: 4px;
    background: var(--bg); border: 1px solid var(--border);
    padding: 3px 10px; border-radius: 999px; cursor: pointer;
    font-size: 12px; color: var(--text);
    transition: background .15s;
  }}
  .preset:hover {{ background: var(--border); }}

  .check-row {{
    display: flex; align-items: center; gap: 10px;
    padding: 10px 12px;
    background: var(--bg); border: 1px solid var(--border);
    border-radius: 6px; font-size: 13px;
  }}
  .check-row input {{ width: auto; cursor: pointer; }}
  .check-row label {{ margin: 0; font-weight: 500; cursor: pointer; }}

  /* ── Action bar ─────────────────────────────────────────────────── */
  .actionbar {{
    display: flex; justify-content: flex-end; gap: 10px;
    padding-top: 8px;
  }}
  button.primary, button.secondary {{
    min-height: 42px; padding: 0 18px; border-radius: 8px;
    font-size: 14px; font-weight: 600; cursor: pointer;
    transition: background .15s, transform .05s, border-color .15s;
  }}
  button.primary {{
    background: #111827; color: #ffffff; border: 1px solid #111827;
  }}
  button.secondary {{
    background: #ffffff; color: var(--text); border: 1px solid var(--border);
  }}
  button.primary:hover  {{ background: #1f2937; }}
  button.secondary:hover {{ background: var(--bg); border-color: #d1d5db; }}
  button.primary:active, button.secondary:active {{ transform: translateY(1px); }}

  code {{ background: var(--bg); padding: 1px 6px; border-radius: 3px;
          font-size: 12px; font-family: ui-monospace, monospace; }}
</style>
</head>
<body class="{body_class}">
{topbar_html}

<main>
{flash_html}

<section class="card hero">
  <div class="card-label">端點</div>
  {agent_display}
  <div class="hero-row">
    {status_pill}
    <span class="hero-desc">{status_text}</span>
  </div>
</section>

<form method="POST" action="/admin/quick-add">
  {token_input}
  {embed_input}

  <section class="card">
    <div class="card-label">業務背景</div>
    {agent_form_input}

    <div class="field">
      <label>這台電腦的用途</label>
      <input type="text" name="role" value="{_html_escape(role)}"
             placeholder="例：門市 POS、會計電腦、對外網站、開發者筆電" required>
    </div>

    <div class="field">
      <label>負責人</label>
      <input type="text" name="owner" value="{_html_escape(owner)}"
             placeholder="例：Peter、門市店長、資訊窗口、外包維運">
    </div>

    <div class="field">
      <label>重要程度</label>
      <select name="criticality">
        {opt("critical", criticality, "核心：停機會影響營收或客戶")}
        {opt("high",     criticality, "重要：需優先處理")}
        {opt("medium",   criticality, "一般：正常追蹤")}
        {opt("low",      criticality, "低：測試或非關鍵")}
      </select>
    </div>

    <div class="field">
      <label>主要使用時間</label>
      <input type="text" name="business_hours" id="bh"
             value="{_html_escape(biz_hours)}"
             placeholder="Mon-Fri 09:00-19:00 Asia/Taipei">
      <div class="presets">
        <span class="preset" onclick="document.getElementById('bh').value='Mon-Fri 09:00-19:00 Asia/Taipei'">辦公時間</span>
        <span class="preset" onclick="document.getElementById('bh').value='Daily 10:00-23:30 Asia/Taipei'">餐飲營業</span>
        <span class="preset" onclick="document.getElementById('bh').value='Daily 06:00-24:00 Asia/Taipei'">早到深夜</span>
        <span class="preset" onclick="document.getElementById('bh').value=''">24/7</span>
      </div>
    </div>

    <div class="field">
      <div class="check-row">
        <input type="checkbox" name="pci_scope" id="pci" value="1" {"checked" if pci_scope else ""}>
        <label for="pci">這台會處理信用卡資料</label>
      </div>
    </div>

    <div class="field">
      <label>補充背景（可留空）</label>
      <textarea name="notes" rows="3"
                placeholder="例：非營業時間登入很可疑；只有店長會使用。">{_html_escape(notes)}</textarea>
    </div>
  </section>

  <div class="actionbar">
    <button type="button" class="secondary" onclick="closeEditor()">取消</button>
    <button type="submit" class="primary">{btn_zh}</button>
  </div>
</form>
{recent_details}

</main>
<script>
function closeEditor() {{
  if (window.parent && window.parent !== window) {{
    window.parent.postMessage({{ type: "edgesec-close-drawer" }}, window.location.origin);
  }} else {{
    window.history.back();
  }}
}}
</script>
</body>
</html>
"""


def _render_quick_add_saved(agent: str, saved: dict[str, Any], embed: bool = False) -> str:
    body_class = "drawer-mode" if embed else ""
    endpoints_url = _dashboard_url("/settings/endpoints")
    return f"""<!doctype html>
<html lang="zh-Hant">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>已儲存 — EdgeSec-Pi</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; background: #f3f4f6; color: #111827;
    font-family: -apple-system, BlinkMacSystemFont, "Noto Sans TC", "Segoe UI", sans-serif;
    line-height: 1.55;
  }}
  body.drawer-mode {{ background: #ffffff; }}
  main {{ max-width: 720px; margin: 0 auto; padding: 24px; }}
  body.drawer-mode main {{ max-width: none; padding: 18px; }}
  .card {{
    background: #ffffff; border: 1px solid #e5e7eb; border-radius: 10px;
    padding: 18px 22px; margin-bottom: 14px;
  }}
  body.drawer-mode .card {{ border: 0; border-bottom: 1px solid #e5e7eb; border-radius: 0; padding: 14px 0; }}
  .label {{ color: #6b7280; font-size: 12px; font-weight: 700; }}
  h1 {{ margin: 6px 0 8px; font-size: 22px; }}
  p {{ margin: 0; color: #6b7280; }}
  .summary {{ display: grid; gap: 8px; }}
  .summary div {{ display: grid; grid-template-columns: 76px minmax(0, 1fr); gap: 10px; }}
  .summary span {{ color: #6b7280; }}
  .summary strong {{ color: #111827; overflow-wrap: anywhere; }}
  .actionbar {{ display: flex; justify-content: flex-end; gap: 10px; margin-top: 18px; }}
  button {{
    min-height: 42px; padding: 0 18px; border-radius: 8px; font-size: 14px; font-weight: 600;
    cursor: pointer; background: #ffffff; color: #111827; border: 1px solid #d1d5db;
  }}
  button:hover {{ background: #f3f4f6; }}
</style>
</head>
<body class="{body_class}">
<main>
  <section class="card">
    <div class="label">端點業務背景</div>
    <h1>已儲存</h1>
    <p>{_html_escape(agent)} 的告警會使用這份背景判斷影響。</p>
  </section>
  <section class="card summary">
    <div><span>用途</span><strong>{_html_escape(saved.get("role", ""))}</strong></div>
    <div><span>負責人</span><strong>{_html_escape(saved.get("owner", "") or "未設定")}</strong></div>
    <div><span>重要程度</span><strong>{_html_escape(saved.get("criticality", ""))}</strong></div>
    <div><span>使用時間</span><strong>{_html_escape(saved.get("business_hours", "") or "24/7")}</strong></div>
    <div><span>信用卡資料</span><strong>{"是" if saved.get("pci_scope") else "否"}</strong></div>
    {("<div><span>補充</span><strong>" + _html_escape(saved.get("notes","")) + "</strong></div>") if saved.get("notes") else ""}
  </section>
  <div class="actionbar">
    <button type="button" onclick="closeEditor()">關閉</button>
  </div>
</main>
<script>
function closeEditor() {{
  if (window.parent && window.parent !== window) {{
    window.parent.postMessage({{ type: "edgesec-close-drawer", refresh: true }}, window.location.origin);
  }} else {{
    window.location.href = "{endpoints_url}";
  }}
}}
</script>
</body>
</html>"""


def _render_quick_add_unauthorized(agent: str, embed: bool = False) -> str:
    body_class = "drawer-mode" if embed else ""
    today_url = _dashboard_url("/")
    endpoints_url = _dashboard_url("/settings/endpoints")
    return f"""<!doctype html>
<html lang="zh-Hant">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>連結已失效 — EdgeSec-Pi</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; background: #f3f4f6; color: #111827;
    font-family: -apple-system, BlinkMacSystemFont, "Noto Sans TC", "Segoe UI", sans-serif;
    line-height: 1.55;
  }}
  body.drawer-mode {{ background: #ffffff; }}
  main {{ max-width: 720px; margin: 0 auto; padding: 24px; }}
  body.drawer-mode main {{ max-width: none; padding: 18px; }}
  .card {{
    background: #ffffff; border: 1px solid #e5e7eb; border-radius: 10px;
    padding: 18px 22px;
  }}
  body.drawer-mode .card {{ border: 0; border-bottom: 1px solid #e5e7eb; border-radius: 0; padding: 14px 0; }}
  h1 {{ margin: 0 0 8px; font-size: 20px; }}
  p {{ margin: 0; color: #6b7280; }}
  .actions {{ display: flex; flex-wrap: wrap; gap: 10px; margin-top: 18px; }}
  .actionbar {{ display: flex; justify-content: flex-end; gap: 10px; margin-top: 18px; }}
  button, .button {{
    display: inline-flex; align-items: center; justify-content: center; text-decoration: none;
    min-height: 42px; padding: 0 18px; border-radius: 8px; font-size: 14px; font-weight: 600;
    cursor: pointer; background: #ffffff; color: #111827; border: 1px solid #d1d5db;
  }}
  button:hover, .button:hover {{ background: #f3f4f6; }}
</style>
</head>
<body class="{body_class}">
<main>
  <section class="card">
    <h1>此編輯連結已失效</h1>
    <p>這通常是因為儀表板開太久，安全連結已過期。請回到儀表板重新整理，再點一次「設定業務用途」。{f" 目標端點：{_html_escape(agent)}" if agent else ""}</p>
    <div class="actions">
      <a class="button" target="_top" href="{today_url}">回今日待辦</a>
      <a class="button" target="_top" href="{endpoints_url}">回電腦端點</a>
    </div>
    <div class="actionbar">
      <button type="button" onclick="closeEditor()">關閉並重新整理</button>
    </div>
  </section>
</main>
<script>
function closeEditor() {{
  if (window.parent && window.parent !== window) {{
    window.parent.postMessage({{ type: "edgesec-close-drawer", refresh: true }}, window.location.origin);
  }} else {{
    window.location.href = "{today_url}";
  }}
}}
</script>
</body>
</html>"""


@router.get("/admin/quick-add", response_class=HTMLResponse)
async def admin_quick_add_get(
    agent: Annotated[str, Query()] = "",
    t:     Annotated[Optional[str], Query()] = None,
    embed: Annotated[bool, Query()] = False,
    creds: Annotated[Optional[HTTPBasicCredentials], Depends(_basic)] = None,
) -> str:
    """Render the focused single-agent form.

    Two entry modes:
      • With ?agent=NAME (Slack deep-link, /admin link): edit/create that
        specific asset, token allowed.
      • Without ?agent= (IT types URL directly): show the form blank with
        a "device name / pattern" input. Basic Auth required (no token
        possible without a target agent).
    """
    try:
        who = _authorize_quick_add(t, agent, creds)
    except HTTPException as exc:
        if embed and exc.status_code == 401:
            return _render_quick_add_unauthorized(agent, embed=True)
        raise
    existing = org_profile.find_asset(agent) if agent else None

    # Pull last 5 alerts for this agent so the user has CONTEXT while
    # filling in role/criticality. Avoid querying for an empty agent
    # (we'd get the global tail, which is useless here).
    recent: list[dict[str, Any]] = []
    if agent:
        try:
            recent = await db.list_alerts(limit=5, agent_name=agent)
        except Exception as e:
            log.warning("quick-add: list_alerts failed for %r: %r", agent, e)

    return _render_quick_add(agent, existing, token=t or "",
                             who=who, recent=recent, embed=embed)


@router.post("/admin/quick-add", response_class=HTMLResponse)
async def admin_quick_add_post(
    agent:          Annotated[str, Form()],
    role:           Annotated[str, Form()],
    criticality:    Annotated[str, Form()],
    owner:          Annotated[str, Form()] = "",
    business_hours: Annotated[str, Form()] = "",
    pci_scope:      Annotated[Optional[str], Form()] = None,
    notes:          Annotated[str, Form()] = "",
    t:              Annotated[Optional[str], Form()] = None,
    embed:          Annotated[Optional[str], Form()] = None,
    creds:          Annotated[Optional[HTTPBasicCredentials], Depends(_basic)] = None,
) -> HTMLResponse:
    who = _authorize_quick_add(t, agent, creds)
    """Apply the quick-add. Upserts an asset entry whose pattern == the
    agent name (exact match, not glob — keeps deep-links unambiguous)."""
    try:
        org_profile.upsert_asset(
            pattern=agent,
            fields={
                "role":           role.strip(),
                "owner":          owner.strip(),
                "criticality":    criticality.strip(),
                "business_hours": business_hours.strip(),
                "pci_scope":      bool(pci_scope),
                "notes":          notes.strip(),
            },
        )
    except Exception as e:
        log.warning("quick-add failed: %r", e)
        return HTMLResponse(
            _render_quick_add(agent, org_profile.find_asset(agent),
                              token=t or "",
                              flash=f"❌ 儲存失敗：{e!s}",
                              who=who),
            status_code=400,
        )

    log.info("admin_quick_add by %s: agent=%s role=%r criticality=%s",
             who, agent, role, criticality)
    saved = org_profile.find_asset(agent) or {}
    return HTMLResponse(_render_quick_add_saved(agent, saved, embed=bool(embed)))
