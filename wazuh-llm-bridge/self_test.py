"""Management-facing self-test for EdgeSec-Pi.

The CLI tests answer "did the code break?". This module answers a different
question for non-technical users: "can I rely on the system right now?"

Checks are deliberately non-destructive. They do not inject Wazuh alerts and do
not send Slack messages; they only verify service reachability and recent data.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

import httpx

import db


Status = str


def _models_url() -> str:
    explicit = os.getenv("LM_STUDIO_MODELS_URL", "").strip()
    if explicit:
        return explicit
    lm_url = os.getenv("LM_STUDIO_URL", "http://localhost:1234/v1/chat/completions")
    return f"{lm_url.rstrip().removesuffix('/chat/completions')}/models"


def _check(
    check_id: str,
    label_zh: str,
    status: Status,
    summary_zh: str,
    next_step_zh: str = "",
    detail_zh: str = "",
    owner_zh: str = "IT",
    required: bool = True,
) -> dict[str, Any]:
    return {
        "id": check_id,
        "label_zh": label_zh,
        "status": status,
        "summary_zh": summary_zh,
        "next_step_zh": next_step_zh,
        "detail_zh": detail_zh,
        "owner_zh": owner_zh,
        "required": required,
    }


async def _check_lm_studio(client: httpx.AsyncClient) -> dict[str, Any]:
    url = _models_url()
    model = os.getenv("LM_MODEL", "local-model")
    try:
        response = await client.get(url, timeout=5)
        response.raise_for_status()
        payload = response.json()
        models = [str(item.get("id", "")) for item in payload.get("data", [])]
    except Exception as exc:
        return _check(
            "lm_studio",
            "AI 分析",
            "fail",
            "AI 分析目前沒有回應。",
            "請技術窗口確認本機 AI 服務已啟動。",
            detail_zh=f"{url} / {exc!r}",
        )

    if not models:
        return _check(
            "lm_studio",
            "AI 分析",
            "fail",
            "AI 服務有回應，但尚未載入可用模型。",
            "請技術窗口載入指定模型。",
            detail_zh=url,
        )

    if model == "local-model":
        return _check(
            "lm_studio",
            "AI 分析",
            "warn",
            "AI 服務有回應，但尚未指定正式模型名稱。",
            "請技術窗口把 bridge.env 的 LM_MODEL 改成 AI 服務中實際載入的模型名稱。",
            detail_zh=f"可用：{', '.join(models[:5])}",
        )

    if model != "local-model" and model not in models:
        return _check(
            "lm_studio",
            "AI 分析",
            "warn",
            "AI 服務有回應，但模型設定需要確認。",
            "請技術窗口確認 bridge.env 的 LM_MODEL 是否和 AI 服務顯示一致。",
            detail_zh=f"設定：{model}；可用：{', '.join(models[:5])}",
        )

    return _check(
        "lm_studio",
        "AI 分析",
        "ok",
        "AI 分析已啟動，可以把告警轉成可讀說明。",
        detail_zh=f"{len(models)} 個模型可用",
    )


async def _check_wazuh_api(client: httpx.AsyncClient) -> dict[str, Any]:
    url = os.getenv("WAZUH_API_URL", "https://localhost:55000").rstrip("/")
    try:
        response = await client.get(f"{url}/", timeout=5)
        if response.status_code in {200, 401}:
            return _check(
                "wazuh_api",
                "Wazuh",
                "ok",
                "Wazuh API 可以連線。",
                detail_zh=f"HTTP {response.status_code}",
                required=False,
            )
        return _check(
            "wazuh_api",
            "Wazuh",
            "warn",
            "Wazuh API 有回應，但狀態不如預期。",
            "請 IT 檢查 Wazuh Manager API。",
            detail_zh=f"{url}/ HTTP {response.status_code}",
            required=False,
        )
    except Exception as exc:
        return _check(
            "wazuh_api",
            "Wazuh",
            "warn",
            "目前無法確認 Wazuh API 狀態。",
            "如果仍有收到告警，代表 webhook 可能正常；請 IT 檢查 Wazuh API 或網路設定。",
            detail_zh=f"{url}/ / {exc!r}",
            required=False,
        )


async def _check_mcp(client: httpx.AsyncClient) -> dict[str, Any]:
    url = os.getenv("MCP_SERVER_URL", "").strip().rstrip("/")
    api_key = os.getenv("MCP_API_KEY", "").strip()
    if not api_key:
        return _check(
            "mcp",
            "進階查詢",
            "skip",
            "進階查詢尚未啟用。",
            "這不影響基本告警摘要；需要讓 AI 查更多 SIEM 資料時再請技術窗口啟用。",
            owner_zh="技術窗口",
            required=False,
        )
    if not url:
        return _check(
            "mcp",
            "進階查詢",
            "warn",
            "進階查詢設定不完整。",
            "請技術窗口設定 MCP_SERVER_URL，或移除 MCP_API_KEY。",
            owner_zh="技術窗口",
            required=False,
        )
    try:
        response = await client.get(f"{url}/health", timeout=5)
        if response.status_code in {200, 204}:
            return _check(
                "mcp",
                "進階查詢",
                "ok",
                "進階查詢服務可以連線。",
                "",
                detail_zh=f"HTTP {response.status_code}",
                required=False,
            )
        return _check(
            "mcp",
            "進階查詢",
            "warn",
            "進階查詢服務狀態異常。",
            "基本告警摘要仍可運作；請技術窗口檢查 MCP server。",
            detail_zh=f"{url}/health HTTP {response.status_code}",
            required=False,
        )
    except Exception as exc:
        return _check(
            "mcp",
            "進階查詢",
            "warn",
            "進階查詢服務目前無法連線。",
            "基本告警摘要仍可運作；需要進階查詢時請技術窗口處理。",
            detail_zh=f"{url}/health / {exc!r}",
            required=False,
        )


async def _check_alert_flow() -> dict[str, Any]:
    try:
        stats = await db.compute_stats()
    except Exception as exc:
        return _check(
            "alert_flow",
            "告警資料",
            "fail",
            "目前無法讀取告警資料庫。",
            "請 IT 檢查 EdgeSec-Pi 的 SQLite 資料庫設定。",
            detail_zh=repr(exc),
        )

    total = int(stats.get("total_alerts") or 0)
    last_24h = int(stats.get("alerts_last_24h") or 0)
    errors = int(stats.get("errors_last_24h") or 0)

    if total == 0:
        return _check(
            "alert_flow",
            "告警資料",
            "warn",
            "目前還沒有收到任何 Wazuh 告警。",
            "若系統剛安裝，這可能正常；否則請 IT 確認 Wazuh webhook 是否有接到 EdgeSec-Pi。",
            detail_zh="total_alerts=0",
        )
    if errors > 0:
        return _check(
            "alert_flow",
            "告警資料",
            "warn",
            "最近 24 小時有告警分析失敗。",
            "請技術窗口檢查 AI 分析、進階查詢或通知連線紀錄。",
            detail_zh=f"24h alerts={last_24h}, errors={errors}",
        )
    return _check(
        "alert_flow",
        "告警資料",
        "ok",
        "EdgeSec-Pi 已收到並保存告警資料。",
        detail_zh=f"total={total}, 24h={last_24h}",
    )


def _check_slack_config() -> dict[str, Any]:
    webhook = os.getenv("SLACK_WEBHOOK_URL", "").strip()
    bot = os.getenv("SLACK_BOT_TOKEN", "").strip()
    app = os.getenv("SLACK_APP_TOKEN", "").strip()
    channel = os.getenv("SLACK_CHANNEL_ID", "").strip()
    if webhook or (bot and app and channel):
        return _check(
            "slack",
            "Slack 通知",
            "ok",
            "Slack 通知設定已存在。",
            "若要確認實際送達，請 IT 執行 /test-slack 或手動測試。",
            required=False,
        )
    return _check(
        "slack",
        "Slack 通知",
        "warn",
        "尚未設定 Slack 通知。",
        "管理層可能看得到 Dashboard，但收不到主動通知；請 IT 設定 Slack。",
        required=False,
    )


def _summarize(checks: list[dict[str, Any]]) -> dict[str, str]:
    required_fail = [c for c in checks if c["required"] and c["status"] == "fail"]
    warnings = [c for c in checks if c["status"] == "warn"]
    if required_fail:
        return {
            "overall": "fail",
            "title_zh": "系統需要 IT 處理",
            "message_zh": "目前有必要服務沒有正常運作，告警可能無法被完整分析。",
            "next_step_zh": "請 IT 先處理紅色項目，再重新執行自我檢查。",
        }
    if warnings:
        return {
            "overall": "warn",
            "title_zh": "可以使用，但需要追蹤",
            "message_zh": "核心服務可用，但有部分設定或資料狀態需要 IT 確認。",
            "next_step_zh": "請 IT 查看黃色項目，確認是否為預期狀態。",
        }
    return {
        "overall": "ok",
        "title_zh": "系統可以正常使用",
        "message_zh": "AI 分析、告警資料與主要服務目前看起來正常。",
        "next_step_zh": "維持監控即可；若收到高風險事件再請 IT 深查。",
    }


async def run_self_test(queue_size: int = 0, queue_max: int = 0) -> dict[str, Any]:
    checks: list[dict[str, Any]] = [
        _check(
            "bridge",
            "EdgeSec-Pi",
            "ok",
            "Dashboard 與 API 服務正在執行。",
            detail_zh=f"queue={queue_size}/{queue_max}",
        )
    ]

    async with httpx.AsyncClient(verify=False) as client:
        checks.append(await _check_lm_studio(client))
        checks.append(await _check_wazuh_api(client))
        checks.append(await _check_mcp(client))

    checks.append(await _check_alert_flow())
    checks.append(_check_slack_config())

    summary = _summarize(checks)
    return {
        **summary,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
    }
