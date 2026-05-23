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
    monkeypatch.setenv("DASHBOARD_V2_URL", "http://127.0.0.1:3000")

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

    monkeypatch.setattr(bridge.ops_api.self_test, "run_self_test", fake_self_test)

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

    monkeypatch.setattr(bridge.ops_api.digest, "collect_status", fake_collect_status)
    monkeypatch.setattr(
        bridge.ops_api.org_profile,
        "find_asset",
        lambda name: {
            "role": "門市 POS 收銀系統",
            "criticality": "critical",
            "business_hours": "Daily 09:00-22:00 Asia/Taipei",
            "notes": "負責門市交易與發票。",
        } if name == "test-pos-store-01" else None,
    )

    async def fake_get_agent_sca_summary(agent_id: str) -> dict[str, Any]:
        return {
            "score": 88 if agent_id == "001" else 44,
            "policy": "CIS Benchmark",
            "policy_id": "cis",
            "passed": 8,
            "failed": 2,
            "invalid": 0,
            "total": 10,
            "last_scan": "2026-05-18T00:00:00Z",
            "failed_checks": [],
            "plain_failed_checks": [],
            "available": True,
        }

    async def fake_agents_from_status() -> list[dict[str, Any]]:
        return (await fake_collect_status())["agents"]["details"]

    monkeypatch.setattr(bridge.ops_api.wazuh, "list_agents", fake_agents_from_status)
    monkeypatch.setattr(bridge.ops_api.wazuh, "get_agent_sca_summary", fake_get_agent_sca_summary)

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

                test_slack_unauth = await client.post("/test-slack")
                assert test_slack_unauth.status_code == 401
                test_digest_unauth = await client.post("/test-digest")
                assert test_digest_unauth.status_code == 401
                test_slack_auth = await client.post(
                    "/test-slack",
                    auth=(bridge.admin_ui.ADMIN_USER, bridge.admin_ui.ADMIN_PASS),
                )
                assert test_slack_auth.status_code == 400

                self_test = (await client.get("/self-test")).json()
                assert self_test["overall"] == "ok"
                assert self_test["title_zh"] == "系統可以正常使用"

                root_redirect = await client.get("/", follow_redirects=False)
                assert root_redirect.status_code == 301
                assert root_redirect.headers["location"] == "http://127.0.0.1:3000/"

                dashboard_redirect = await client.get("/dashboard", follow_redirects=False)
                assert dashboard_redirect.status_code == 301
                assert dashboard_redirect.headers["location"] == "http://127.0.0.1:3000/"

                services_redirect = await client.get(
                    "/dashboard",
                    params={"view": "services"},
                    follow_redirects=False,
                )
                assert services_redirect.status_code == 301
                assert services_redirect.headers["location"] == "http://127.0.0.1:3000/settings/endpoints"

                platform_redirect = await client.get(
                    "/dashboard",
                    params={"view": "platform"},
                    follow_redirects=False,
                )
                assert platform_redirect.status_code == 301
                assert platform_redirect.headers["location"] == "http://127.0.0.1:3000/settings/status"

                testing_redirect = await client.get(
                    "/dashboard",
                    params={"view": "advanced"},
                    follow_redirects=False,
                )
                assert testing_redirect.status_code == 301
                assert testing_redirect.headers["location"] == "http://127.0.0.1:3000/settings/testing"

                notifications_redirect = await client.get(
                    "/dashboard",
                    params={"view": "notifications"},
                    follow_redirects=False,
                )
                assert notifications_redirect.status_code == 301
                assert notifications_redirect.headers["location"] == "http://127.0.0.1:3000/settings/notifications"

                invalid_redirect = await client.get(
                    "/dashboard",
                    params={"view": "invalid"},
                    follow_redirects=False,
                )
                assert invalid_redirect.status_code == 301
                assert invalid_redirect.headers["location"] == "http://127.0.0.1:3000/"

                dashboard_summary = (await client.get("/api/dashboard/summary")).json()
                assert set(dashboard_summary) >= {
                    "alerts",
                    "riskSummary",
                    "endpoints",
                    "systemHealth",
                    "notifications",
                    "install",
                    "alertTrends",
                }
                assert dashboard_summary.get("demo") is None
                assert len(dashboard_summary["endpoints"]) == 2
                endpoint_by_name = {item["name"]: item for item in dashboard_summary["endpoints"]}
                assert endpoint_by_name["test-pos-store-01"]["purpose"] == "門市 POS 收銀系統"
                assert endpoint_by_name["test-pos-store-01"]["status"] == "online"
                assert endpoint_by_name["test-pos-store-01"]["connection_score"] == 100
                assert endpoint_by_name["test-pos-store-01"]["sca_score"] == 88
                assert endpoint_by_name["unprofiled-agent"]["status"] == "offline"
                assert endpoint_by_name["unprofiled-agent"]["purpose"] == "尚未設定"
                assert endpoint_by_name["unprofiled-agent"]["sca_score"] == 44

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

                setup_redirect = await client.get(
                    "/dashboard",
                    params={"view": "setup"},
                    follow_redirects=False,
                )
                assert setup_redirect.status_code == 301
                assert setup_redirect.headers["location"] == "http://127.0.0.1:3000/settings/status"

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

                dashboard_with_alert = (await client.get("/api/dashboard/summary")).json()
                dashboard_alerts = dashboard_with_alert["alerts"]
                assert any(alert["id"] == str(row["id"]) for alert in dashboard_alerts)
                dashboard_row = next(alert for alert in dashboard_alerts if alert["id"] == str(row["id"]))
                assert dashboard_row["status"] == "pending"
                assert dashboard_row["iocs"] == ["10.0.1.45"]
                assert dashboard_row["technical_evidence"]["indicators"]["iocs"] == ["10.0.1.45"]

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
