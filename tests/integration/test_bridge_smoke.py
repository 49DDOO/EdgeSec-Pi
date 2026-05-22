from __future__ import annotations

import asyncio
import json
import time
from collections import Counter
from typing import Any

import httpx
import pytest

from support import fresh_bridge_import


MOCK_TRIAGE = {
    "severity": "high",
    "summary_zh": "有人從外部 IP 不斷嘗試用錯誤密碼登入伺服器",
    "impact_zh": "若猜中密碼，攻擊者可能進入系統竊取資料",
    "next_step_zh": "請聯絡 IT 封鎖來源 IP 並確認無人成功登入",
    "root_cause": "SSH brute force from 10.0.1.45",
    "iocs": ["10.0.1.45"],
    "action": "Block 10.0.1.45 at the firewall; review auth logs.",
    "mitre": "T1110",
    "needs_investigation": False,
    "investigation_reason": "",
}


class FakeLLMClient:
    async def post(self, url: str, json: dict[str, Any], timeout: float) -> httpx.Response:
        await asyncio.sleep(0.2)
        request = httpx.Request("POST", url)
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": __import__("json").dumps(MOCK_TRIAGE, ensure_ascii=False)}}]},
            request=request,
        )


@pytest.mark.integration
def test_bridge_webhook_queue_db_and_backpressure(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.setenv("LM_STUDIO_URL", "http://lm.local/v1/chat/completions")
    monkeypatch.setenv("LM_MODEL", "test-model")
    monkeypatch.setenv("LM_TIMEOUT_S", "5")
    monkeypatch.setenv("QUEUE_MAXSIZE", "5")
    monkeypatch.setenv("WORKER_COUNT", "1")
    monkeypatch.setenv("DB_PATH", str(tmp_path / "alerts.db"))
    monkeypatch.setenv("WEBHOOK_SECRET", "")
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "")
    monkeypatch.setenv("SLACK_BOT_TOKEN", "")
    monkeypatch.setenv("SLACK_APP_TOKEN", "")
    monkeypatch.setenv("SLACK_CHANNEL_ID", "")
    monkeypatch.setenv("LINE_CHANNEL_ACCESS_TOKEN", "")
    monkeypatch.setenv("LINE_USER_ID", "")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "")
    monkeypatch.setenv("SMTP_HOST", "")
    monkeypatch.setenv("EMAIL_FROM", "")
    monkeypatch.setenv("EMAIL_TO", "")
    monkeypatch.setenv("NOTIFICATION_SETTINGS_PATH", str(tmp_path / "notification_channels.json"))
    monkeypatch.setenv("MCP_SERVER_URL", "")
    monkeypatch.setenv("MCP_API_KEY", "")
    monkeypatch.setenv("AGENTIC_FORCE_LEVEL_GTE", "99")

    modules = fresh_bridge_import(["app", "db"])
    bridge = modules["app"]
    db = modules["db"]

    async def fake_self_test(queue_size: int = 0, queue_max: int = 0) -> dict[str, Any]:
        return {
            "overall": "ok",
            "title_zh": "系統可以正常使用",
            "message_zh": "測試替身",
            "next_step_zh": "維持監控即可",
            "checked_at": "2026-05-18T00:00:00Z",
            "checks": [],
        }

    monkeypatch.setattr(bridge.self_test, "run_self_test", fake_self_test)

    async def fake_collect_status() -> dict[str, Any]:
        return {
            "wazuh": {"manager_version": "v4.14.5", "version_status": "current"},
            "agents": {
                "total": 2,
                "active": 1,
                "disconnected": 1,
                "details": [
                    {
                        "id": "001",
                        "name": "test-pos-store-01",
                        "ip": "10.0.1.10",
                        "status": "active",
                        "os_platform": "linux",
                        "os_version": "6.8",
                        "lastKeepAlive": "2026-05-18T00:00:00+0000",
                        "version": "Wazuh v4.14.5",
                    },
                    {
                        "id": "002",
                        "name": "unprofiled-agent",
                        "ip": "10.0.1.11",
                        "status": "disconnected",
                        "os_platform": "darwin",
                        "os_version": "15.5",
                        "lastKeepAlive": "2026-05-17T23:58:00+0000",
                        "version": "Wazuh v4.14.4",
                    },
                ],
            },
            "cve_feed": {"status": "fresh"},
        }

    monkeypatch.setattr(bridge.dashboard_ui.digest, "collect_status", fake_collect_status)
    monkeypatch.setattr(
        bridge.dashboard_ui.org_profile,
        "find_asset",
        lambda name: {
            "role": "門市 POS 收銀系統",
            "criticality": "critical",
            "business_hours": "Daily 09:00-22:00 Asia/Taipei",
            "notes": "負責門市交易與發票。",
        } if name == "test-pos-store-01" else None,
    )

    async def scenario() -> None:
        await db.init_db()
        queue: asyncio.Queue = asyncio.Queue(maxsize=5)
        worker = asyncio.create_task(bridge.consume(queue, FakeLLMClient(), 0))
        bridge.app.state.queue = queue

        try:
            transport = httpx.ASGITransport(app=bridge.app)
            async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
                health = (await client.get("/health")).json()
                assert health["status"] == "ok"
                assert health["queue_max"] == 5
                assert health["workers"] == 1

                self_test = (await client.get("/self-test")).json()
                assert self_test["overall"] == "ok"
                assert self_test["title_zh"] == "系統可以正常使用"

                dashboard_html = (await client.get("/dashboard")).text
                assert 'class="cal-shell"' in dashboard_html
                assert "今日待辦" in dashboard_html
                assert 'class="score-panel' in dashboard_html
                assert "健康度" in dashboard_html
                assert "同類告警合併顯示" in dashboard_html
                assert (
                    "執行自我檢查" in dashboard_html
                    or "補端點背景" in dashboard_html
                    or "查看紀錄" in dashboard_html
                )
                assert "待辦事項" in dashboard_html
                assert "?view=services" in dashboard_html

                services_html = (await client.get("/dashboard", params={"view": "services"})).text
                assert "電腦端點 (2)" in services_html
                assert "完整度" in services_html
                assert "依每台電腦在線、背景、同步、版本與今日最高風險平均" in services_html
                assert "分數說明" in services_html
                assert "端點在線" in services_html
                assert "今日中高風險" in services_html
                assert "1 台離線，1 台缺背景" in services_html
                assert ">100<" in services_html
                assert ">20<" in services_html
                assert "門市 POS 收銀系統" in services_html
                assert "端點業務背景" in services_html
                assert "編輯端點業務背景" in services_html
                assert "尚未設定" not in services_html
                assert "/admin/quick-add?agent=unprofiled-agent&amp;t=" in services_html
                assert "安裝 Agent" in services_html
                assert "上次同步：05/18 00:00" in services_html
                assert "Agent 版本：Wazuh v4.14.5" in services_html
                assert "作業系統：Linux 6.8" in services_html
                assert "作業系統：macOS 15.5" in services_html

                quick_add_html = (
                    await client.get(
                        "/admin/quick-add",
                        params={
                            "agent": "unprofiled-agent",
                            "t": bridge.admin_ui.admin_token.sign("unprofiled-agent"),
                            "embed": "1",
                        },
                    )
                ).text
                assert 'class="drawer-mode"' in quick_add_html
                assert "端點業務背景" in quick_add_html
                assert "這台電腦的用途" in quick_add_html
                assert "負責人" in quick_add_html
                assert "重要程度" in quick_add_html
                assert "EdgeSec-Pi <span" not in quick_add_html

                expired_quick_add_html = (
                    await client.get(
                        "/admin/quick-add",
                        params={
                            "agent": "wazuh-agent-01",
                            "t": "expired",
                            "embed": "1",
                        },
                    )
                ).text
                assert "此編輯連結已失效" in expired_quick_add_html
                assert "儀表板開太久" in expired_quick_add_html
                assert "回電腦端點" in expired_quick_add_html
                assert "關閉並重新整理" in expired_quick_add_html

                platform_html = (await client.get("/dashboard", params={"view": "platform"})).text
                assert "自我檢查" in platform_html
                assert "/self-test" in platform_html
                assert "上線設定" in platform_html
                assert "?view=setup" in platform_html

                setup_html = (await client.get("/dashboard", params={"view": "setup"})).text
                assert "上線檢查" in setup_html
                assert "設定通知並測試成功" in setup_html
                assert "安裝 Agent" in setup_html
                assert "設定業務用途" in setup_html
                assert "/admin/notifications?channel=line" in setup_html
                assert "/admin/notifications?channel=slack" in setup_html
                assert "/admin/notifications" in setup_html
                assert "Slack" in setup_html
                assert "LINE" in setup_html
                assert "Telegram" in setup_html
                assert "Email" in setup_html
                assert "正常操作、交給 IT、已處理或誤報" in setup_html

                notification_html = (
                    await client.get(
                        "/admin/notifications",
                        auth=(bridge.admin_ui.ADMIN_USER, bridge.admin_ui.ADMIN_PASS),
                    )
                ).text
                assert "通知設定" in notification_html
                assert "LINE、Slack、Telegram、Email 可各自設定" in notification_html
                assert "回上線設定" in notification_html
                assert "通知管道" in notification_html
                assert "設定說明" in notification_html
                assert "先儲存 LINE 權杖與接收者，才能測試。" in notification_html
                assert 'class="channel-tab active"' in notification_html
                assert "Telegram" in notification_html
                assert "手機收到訊息才算完成" in notification_html
                assert 'id="line"' in notification_html
                assert 'id="slack"' not in notification_html
                assert 'id="email"' not in notification_html
                assert '/admin/notifications?channel=line' in notification_html
                assert '/admin/notifications?channel=slack' in notification_html
                assert '/admin/notifications?channel=telegram' in notification_html
                assert '/admin/notifications?channel=email' in notification_html
                assert "LINE_CHANNEL_ACCESS_TOKEN" in notification_html
                assert "SLACK_WEBHOOK_URL" not in notification_html

                notification_slack_html = (
                    await client.get(
                        "/admin/notifications",
                        params={"channel": "slack"},
                        auth=(bridge.admin_ui.ADMIN_USER, bridge.admin_ui.ADMIN_PASS),
                    )
                ).text
                assert 'id="slack"' in notification_slack_html
                assert "SLACK_WEBHOOK_URL" in notification_slack_html
                assert "測試 Slack" in notification_slack_html
                assert "簡易通知" in notification_slack_html
                assert "進階：Slack 互動按鈕" in notification_slack_html

                notification_telegram_html = (
                    await client.get(
                        "/admin/notifications",
                        params={"channel": "telegram"},
                        auth=(bridge.admin_ui.ADMIN_USER, bridge.admin_ui.ADMIN_PASS),
                    )
                ).text
                assert 'id="telegram"' in notification_telegram_html
                assert "TELEGRAM_BOT_TOKEN" in notification_telegram_html
                assert "TELEGRAM_CHAT_ID" in notification_telegram_html
                assert "測試 Telegram" in notification_telegram_html
                assert "先儲存 Bot Token 與 Chat ID，才能測試。" in notification_telegram_html

                invalid_line_save = await client.post(
                    "/admin/notifications/line",
                    data={"LINE_CHANNEL_ACCESS_TOKEN": "", "LINE_USER_ID": ""},
                    auth=(bridge.admin_ui.ADMIN_USER, bridge.admin_ui.ADMIN_PASS),
                )
                assert invalid_line_save.status_code == 200
                assert "LINE 尚未儲存" in invalid_line_save.text

                line_html = (
                    await client.get(
                        "/admin/notifications/line",
                        auth=(bridge.admin_ui.ADMIN_USER, bridge.admin_ui.ADMIN_PASS),
                    )
                ).text
                assert "通知設定" in line_html
                assert 'id="line"' in line_html
                assert "/admin/notifications/line/test" in line_html
                assert "SLACK_WEBHOOK_URL" not in line_html

                slack_html = (
                    await client.get(
                        "/admin/notifications/slack",
                        auth=(bridge.admin_ui.ADMIN_USER, bridge.admin_ui.ADMIN_PASS),
                    )
                ).text
                assert "通知設定" in slack_html
                assert 'id="slack"' in slack_html
                assert "/admin/notifications/slack/test" in slack_html
                assert "Webhook URL" in slack_html
                assert "進階：Slack 互動按鈕" in slack_html
                assert "Channel ID" in slack_html
                assert "Bot Token" in slack_html
                assert "App Token" in slack_html
                assert "目前狀態" in slack_html
                assert "LINE_CHANNEL_ACCESS_TOKEN" not in slack_html

                slack_test_get = await client.get(
                    "/admin/notifications/slack/test",
                    auth=(bridge.admin_ui.ADMIN_USER, bridge.admin_ui.ADMIN_PASS),
                    follow_redirects=False,
                )
                assert slack_test_get.status_code == 303
                assert slack_test_get.headers["location"].startswith("/admin/notifications/slack")

                save_response = await client.post(
                    "/admin/notifications/line",
                    data={
                        "LINE_CHANNEL_ACCESS_TOKEN": "line-token",
                        "LINE_USER_ID": "line-user",
                    },
                    auth=(bridge.admin_ui.ADMIN_USER, bridge.admin_ui.ADMIN_PASS),
                )
                assert save_response.status_code == 200
                assert "LINE 設定已儲存" in save_response.text
                assert bridge.notify_channels.line_configured() is True

                await client.post(
                    "/admin/notifications/slack",
                    data={"SLACK_WEBHOOK_URL": "https://example.invalid/slack"},
                    auth=(bridge.admin_ui.ADMIN_USER, bridge.admin_ui.ADMIN_PASS),
                )
                await client.post(
                    "/admin/notifications/line",
                    data={"LINE_CHANNEL_ACCESS_TOKEN": "line-token-2", "LINE_USER_ID": "line-user-2"},
                    auth=(bridge.admin_ui.ADMIN_USER, bridge.admin_ui.ADMIN_PASS),
                )
                assert bridge.notify_channels.get_config("LINE_USER_ID") == "line-user-2"
                assert bridge.notify_channels.get_config("SLACK_WEBHOOK_URL") == "https://example.invalid/slack"

                single_alert = {
                    "rule": {"id": "5712", "level": 10, "description": "SSH brute force"},
                    "full_log": "Failed password for root from 10.0.1.45",
                    "data": {"srcip": "10.0.1.45"},
                }
                response = await client.post("/webhook", json=single_alert)
                assert response.status_code == 202
                assert response.json()["queued"] is True
                assert response.json()["siem_source"] == "wazuh"

                deadline = time.monotonic() + 8
                row = None
                while time.monotonic() < deadline:
                    rows = (await client.get("/alerts", params={"limit": 5, "rule_id": "5712"})).json()
                    if rows:
                        row = rows[0]
                        break
                    await asyncio.sleep(0.2)

                assert row is not None
                assert row["llm_status"] == "ok"
                assert row["llm_severity"] == "high"
                assert row["siem_source"] == "wazuh"
                assert row["llm_error"] in (None, "")
                assert row["llm_iocs"] == ["10.0.1.45"]

                dashboard_with_alert = (await client.get("/dashboard")).text
                assert "正常操作" in dashboard_with_alert
                assert "交給 IT" in dashboard_with_alert
                assert "已處理" in dashboard_with_alert
                assert "誤報" in dashboard_with_alert

                case_response = await client.post(
                    f"/dashboard/alerts/{row['id']}/case",
                    data={"status": "resolved"},
                    follow_redirects=False,
                )
                assert case_response.status_code == 303
                rows_after_case = (await client.get("/alerts", params={"limit": 5, "rule_id": "5712"})).json()
                assert rows_after_case[0]["case_status"] == "resolved"

                splunk_event = {
                    "sourcetype": "linux_secure",
                    "event_id": "splunk-5712",
                    "severity": "high",
                    "host": {"name": "branch-file-server", "ip": "10.0.2.10"},
                    "source_ip": "198.51.100.8",
                    "message": "Failed password for admin from 198.51.100.8",
                }
                response = await client.post("/webhook/splunk", json=splunk_event)
                assert response.status_code == 202
                assert response.json()["siem_source"] == "splunk"

                deadline = time.monotonic() + 8
                splunk_row = None
                while time.monotonic() < deadline:
                    rows = (await client.get("/alerts", params={"limit": 5, "rule_id": "splunk-5712"})).json()
                    if rows:
                        splunk_row = rows[0]
                        break
                    await asyncio.sleep(0.2)

                assert splunk_row is not None
                assert splunk_row["siem_source"] == "splunk"
                assert splunk_row["agent_name"] == "branch-file-server"

                codes: Counter[int] = Counter()
                for i in range(50):
                    burst = {
                        "rule": {"id": str(i), "level": 7, "description": f"test {i}"},
                        "full_log": f"line {i}",
                    }
                    codes[(await client.post("/webhook", json=burst)).status_code] += 1

                assert codes[202] > 0
                assert codes[503] > 0

                deadline = time.monotonic() + 20
                final_health = None
                while time.monotonic() < deadline:
                    final_health = (await client.get("/health")).json()
                    if final_health["queue_size"] == 0:
                        break
                    await asyncio.sleep(0.3)

                assert final_health is not None
                assert final_health["queue_size"] == 0
        finally:
            await queue.join()
            worker.cancel()
            await asyncio.gather(worker, return_exceptions=True)

    asyncio.run(scenario())
