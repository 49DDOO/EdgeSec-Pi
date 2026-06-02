from __future__ import annotations

import pytest

from support import fresh_bridge_import


@pytest.mark.unit
def test_quick_slack_card_starts_with_endpoint_business_context(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("WAZUH_API_PASS", "test-pass")
    monkeypatch.setenv("ORG_PROFILE_PATH", str(tmp_path / "org_profile.yaml"))
    modules = fresh_bridge_import(["org_profile", "slack_render"])
    org_profile = modules["org_profile"]
    slack_render = modules["slack_render"]

    org_profile.upsert_asset(
        "boss-mac",
        {
            "role": "管理者筆電",
            "owner": "Titan",
            "criticality": "critical",
            "business_hours": "Daily 09:00-21:00 Asia/Taipei",
            "notes": "處理公司帳務與管理後台",
        },
    )
    payload = slack_render.build_quick_slack_blocks_payload(
        {
            "agent": {"name": "boss-mac", "ip": "192.168.50.80"},
            "rule": {
                "id": "19007",
                "level": 7,
                "description": "CIS_Apple_macOS_26.0_Tahoe_Benchmark_v1.0.0",
            },
        },
        {
            "severity": "medium",
            "summary_zh": "管理者筆電有一項安全設定需要確認。",
            "impact_zh": "若不處理，可能增加未授權登入風險。",
            "next_step_zh": "請 Titan 確認是否為預期設定。",
        },
    )

    blocks = payload["attachments"][0]["blocks"]
    header = blocks[0]["text"]["text"]
    context = blocks[1]["text"]["text"]
    summary = blocks[2]["text"]["text"]

    assert "boss-mac 需要確認" in header
    assert "CIS_Apple" not in header
    assert "*電腦：* boss-mac（IP：192.168.50.80）" in context
    assert "*用途：* 管理者筆電" in context
    assert "*負責人：* Titan" in context
    assert "*說明：* 處理公司帳務與管理後台" in context
    assert "*發生什麼事*" in summary


@pytest.mark.unit
def test_unprofiled_slack_card_explicitly_asks_for_business_context(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("WAZUH_API_PASS", "test-pass")
    monkeypatch.setenv("ORG_PROFILE_PATH", str(tmp_path / "org_profile.yaml"))
    slack_render = fresh_bridge_import(["slack_render"])["slack_render"]

    payload = slack_render.build_quick_slack_blocks_payload(
        {
            "agent": {"name": "unknown-pc"},
            "rule": {"description": "Some technical rule"},
        },
        {"summary_zh": "這台電腦有一項設定需要確認。"},
    )

    context = payload["attachments"][0]["blocks"][1]["text"]["text"]
    assert "*用途：* 尚未設定" in context
    assert "尚未設定業務用途" in context


@pytest.mark.unit
def test_owner_context_hides_loopback_ip_and_technical_notes(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("WAZUH_API_PASS", "test-pass")
    monkeypatch.setenv("ORG_PROFILE_PATH", str(tmp_path / "org_profile.yaml"))
    modules = fresh_bridge_import(["org_profile", "slack_render"])
    org_profile = modules["org_profile"]
    slack_render = modules["slack_render"]

    org_profile.upsert_asset(
        "titandeacStudio",
        {
            "role": "開發者",
            "criticality": "critical",
            "business_hours": "Daily 10:30 Asia/Taipei",
            "notes": "使用者提供的 IP 為 ::1 (localhost / 本機迴圈位址)，不作為實際主機位置判斷。",
        },
    )

    payload = slack_render.build_quick_slack_blocks_payload(
        {
            "agent": {
                "name": "titandeacStudio",
                "ip": "0000:0000:0000:0000:0000:0000:0000:0001",
            },
            "rule": {"description": "Network changed"},
        },
        {"summary_zh": "開發者電腦的網路狀態發生變更。"},
    )

    context = payload["attachments"][0]["blocks"][1]["text"]["text"]

    assert "titandeacStudio" in context
    assert "用途：* 開發者" in context
    assert "0000:0000" not in context
    assert "::1" not in context
    assert "localhost" not in context


@pytest.mark.unit
def test_slack_emergency_buttons_explain_actions(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("WAZUH_API_PASS", "test-pass")
    monkeypatch.setenv("DB_PATH", str(tmp_path / "alerts.db"))
    monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb-test")
    monkeypatch.setenv("SLACK_APP_TOKEN", "xapp-test")
    monkeypatch.setenv("SLACK_CHANNEL_ID", "C123")
    monkeypatch.setenv("WAZUH_ISOLATE_COMMAND", "edgesec-isolate0")
    monkeypatch.setenv("WAZUH_RELEASE_ISOLATE_COMMAND", "edgesec-release-isolate0")
    monkeypatch.setenv("ACTIVE_RESPONSE_ISOLATION_PRESERVE_CHANNELS_ACK", "1")
    monkeypatch.setenv("ACTIVE_RESPONSE_ISOLATION_VERIFIED_PLATFORMS", "macos")
    monkeypatch.setenv("BRIDGE_PUBLIC_URL", "https://edgesec.example")
    monkeypatch.setenv("ORG_PROFILE_PATH", str(tmp_path / "org_profile.yaml"))
    modules = fresh_bridge_import(["remote_action_tokens", "slack_actions", "slack_render"])
    remote_action_tokens = modules["remote_action_tokens"]
    slack_render = modules["slack_render"]

    payload = slack_render.build_quick_slack_blocks_payload(
        {
            "agent": {
                "id": "003",
                "name": "MB-TitanCheng",
                "ip": "192.168.50.106",
                "os": {"platform": "darwin"},
            },
            "data": {"srcip": "8.8.8.8"},
            "rule": {"description": "SSH brute force"},
        },
        {
            "severity": "high",
            "summary_zh": "有人多次嘗試登入這台電腦。",
            "iocs": ["8.8.8.8"],
        },
    )
    payload = slack_render._augment_with_action_buttons(
        payload,
        {
            "agent": {
                "id": "003",
                "name": "MB-TitanCheng",
                "ip": "192.168.50.106",
                "os": {"platform": "darwin"},
            },
            "data": {"srcip": "8.8.8.8"},
        },
        {
            "severity": "high",
            "iocs": ["8.8.8.8"],
            "root_cause": "successful login after brute force",
        },
    )

    blocks = payload["attachments"][0]["blocks"]
    help_text = "\n".join(
        element["text"]
        for block in blocks
        if block.get("type") == "context"
        for element in block.get("elements", [])
    )
    action_texts = [
        element["text"]["text"]
        for block in blocks
        if block.get("type") == "actions"
        for element in block.get("elements", [])
    ]

    assert "封鎖來源 IP" in action_texts
    assert "解除封鎖" not in action_texts
    assert "隔離端點" in action_texts
    assert "封鎖來源 IP*：擋住外部來源" in help_text
    assert "隔離端點*：暫停這台電腦連線" in help_text

    action_values = [
        element["value"]
        for block in blocks
        if block.get("type") == "actions"
        for element in block.get("elements", [])
        if element.get("action_id") in {"block_ip", "isolate_endpoint"}
    ]
    assert action_values
    assert all("|" not in value for value in action_values)
    claims = remote_action_tokens.consume(action_values[0], "block_ip", clicker="U-test")
    assert claims["agent_id"] == "003"
    assert claims["target"] == "8.8.8.8"
    with pytest.raises(remote_action_tokens.ActionTokenError, match="已使用過"):
        remote_action_tokens.consume(action_values[0], "block_ip", clicker="U-test")


@pytest.mark.unit
def test_slack_card_links_back_to_dashboard(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("WAZUH_API_PASS", "test-pass")
    monkeypatch.setenv("DB_PATH", str(tmp_path / "alerts.db"))
    monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb-test")
    monkeypatch.setenv("SLACK_APP_TOKEN", "xapp-test")
    monkeypatch.setenv("SLACK_CHANNEL_ID", "C123")
    monkeypatch.setenv("DASHBOARD_V2_URL", "https://dashboard.example")
    monkeypatch.setenv("ORG_PROFILE_PATH", str(tmp_path / "org_profile.yaml"))
    slack_render = fresh_bridge_import(["slack_actions", "slack_render"])["slack_render"]

    alert = {
        "agent": {"id": "003", "name": "MB-TitanCheng"},
        "rule": {"description": "Network changed"},
        "_edgesec": {"dashboard_alert_id": 123},
    }
    payload = slack_render.build_quick_slack_blocks_payload(
        alert,
        {"severity": "high", "summary_zh": "網路狀態有變動。"},
    )
    payload = slack_render._augment_with_action_buttons(payload, alert, {})

    action_buttons = [
        element
        for block in payload["attachments"][0]["blocks"]
        if block.get("type") == "actions"
        for element in block.get("elements", [])
    ]

    dashboard_button = next(
        element for element in action_buttons if element["text"]["text"] == "查看 Dashboard"
    )
    assert dashboard_button["url"] == "https://dashboard.example/?tab=alerts&alert=123"

    legacy = slack_render.build_quick_slack_payload(
        alert,
        {"severity": "high", "summary_zh": "網路狀態有變動。"},
    )
    assert legacy["attachments"][0]["title_link"] == "https://dashboard.example/?tab=alerts&alert=123"


@pytest.mark.unit
def test_slack_hides_isolation_button_when_isolation_is_not_configured(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("WAZUH_API_PASS", "test-pass")
    monkeypatch.setenv("DB_PATH", str(tmp_path / "alerts.db"))
    monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb-test")
    monkeypatch.setenv("SLACK_APP_TOKEN", "xapp-test")
    monkeypatch.setenv("SLACK_CHANNEL_ID", "C123")
    monkeypatch.setenv("WAZUH_ISOLATE_COMMAND", "")
    monkeypatch.setenv("WAZUH_RELEASE_ISOLATE_COMMAND", "")
    monkeypatch.setenv("ACTIVE_RESPONSE_ISOLATION_PRESERVE_CHANNELS_ACK", "0")
    monkeypatch.setenv("ORG_PROFILE_PATH", str(tmp_path / "org_profile.yaml"))
    slack_render = fresh_bridge_import(["slack_actions", "slack_render"])["slack_render"]

    alert = {
        "agent": {"id": "003", "name": "MB-TitanCheng", "ip": "192.168.50.106"},
        "data": {"srcip": "8.8.8.8"},
        "rule": {"description": "SSH brute force"},
    }
    payload = slack_render.build_quick_slack_blocks_payload(
        alert,
        {
            "severity": "high",
            "summary_zh": "有人多次嘗試登入這台電腦。",
            "iocs": ["8.8.8.8"],
        },
    )
    payload = slack_render._augment_with_action_buttons(payload, alert, {"iocs": ["8.8.8.8"]})

    action_texts = [
        element["text"]["text"]
        for block in payload["attachments"][0]["blocks"]
        if block.get("type") == "actions"
        for element in block.get("elements", [])
    ]

    assert "封鎖來源 IP" in action_texts
    assert "解除封鎖" not in action_texts
    assert "隔離端點" not in action_texts


@pytest.mark.unit
def test_slack_hides_isolation_button_when_platform_is_not_verified(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("WAZUH_API_PASS", "test-pass")
    monkeypatch.setenv("DB_PATH", str(tmp_path / "alerts.db"))
    monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb-test")
    monkeypatch.setenv("SLACK_APP_TOKEN", "xapp-test")
    monkeypatch.setenv("SLACK_CHANNEL_ID", "C123")
    monkeypatch.setenv("WAZUH_ISOLATE_COMMAND", "edgesec-isolate0")
    monkeypatch.setenv("WAZUH_RELEASE_ISOLATE_COMMAND", "edgesec-release-isolate0")
    monkeypatch.setenv("ACTIVE_RESPONSE_ISOLATION_PRESERVE_CHANNELS_ACK", "1")
    monkeypatch.setenv("ACTIVE_RESPONSE_ISOLATION_VERIFIED_PLATFORMS", "linux")
    monkeypatch.setenv("ORG_PROFILE_PATH", str(tmp_path / "org_profile.yaml"))
    slack_render = fresh_bridge_import(["slack_actions", "slack_render"])["slack_render"]

    alert = {
        "agent": {
            "id": "003",
            "name": "WIN-EMPLOYEE",
            "ip": "192.168.50.106",
            "os": {"platform": "windows"},
        },
        "data": {"srcip": "192.168.50.106", "dstip": "8.8.8.8"},
        "rule": {"level": 10, "description": "Suspicious outbound connection"},
    }
    parsed = {
        "severity": "high",
        "summary_zh": "這台電腦主動連到可疑外部位址。",
    }
    payload = slack_render.build_quick_slack_blocks_payload(alert, parsed)
    payload = slack_render._augment_with_action_buttons(payload, alert, parsed)

    action_texts = [
        element["text"]["text"]
        for block in payload["attachments"][0]["blocks"]
        if block.get("type") == "actions"
        for element in block.get("elements", [])
    ]

    assert "隔離端點" not in action_texts


@pytest.mark.unit
def test_slack_does_not_block_internal_source_or_llm_only_ioc(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("WAZUH_API_PASS", "test-pass")
    monkeypatch.setenv("DB_PATH", str(tmp_path / "alerts.db"))
    monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb-test")
    monkeypatch.setenv("SLACK_APP_TOKEN", "xapp-test")
    monkeypatch.setenv("SLACK_CHANNEL_ID", "C123")
    monkeypatch.setenv("WAZUH_ISOLATE_COMMAND", "edgesec-isolate0")
    monkeypatch.setenv("WAZUH_RELEASE_ISOLATE_COMMAND", "edgesec-release-isolate0")
    monkeypatch.setenv("ACTIVE_RESPONSE_ISOLATION_PRESERVE_CHANNELS_ACK", "1")
    monkeypatch.delenv("ACTIVE_RESPONSE_ISOLATION_VERIFIED_PLATFORMS", raising=False)
    monkeypatch.setenv("ORG_PROFILE_PATH", str(tmp_path / "org_profile.yaml"))
    slack_render = fresh_bridge_import(["slack_actions", "slack_render"])["slack_render"]

    alert = {
        "agent": {"id": "003", "name": "MB-TitanCheng", "ip": "192.168.50.106"},
        "data": {"srcip": "192.168.50.10"},
        "rule": {"description": "Internal SSH failures"},
    }
    parsed = {
        "severity": "high",
        "summary_zh": "內網來源多次嘗試登入。",
        "iocs": ["8.8.8.8"],
    }
    payload = slack_render.build_quick_slack_blocks_payload(alert, parsed)
    payload = slack_render._augment_with_action_buttons(payload, alert, parsed)

    blocks = payload["attachments"][0]["blocks"]
    action_texts = [
        element["text"]["text"]
        for block in blocks
        if block.get("type") == "actions"
        for element in block.get("elements", [])
    ]
    help_text = "\n".join(
        element["text"]
        for block in blocks
        if block.get("type") == "context"
        for element in block.get("elements", [])
    )

    assert "封鎖來源 IP" not in action_texts
    assert "隔離端點" not in action_texts
    assert "沒有安全可自動封鎖的外部來源" in help_text


@pytest.mark.unit
def test_slack_endpoint_outbound_alert_shows_isolation_not_block(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("WAZUH_API_PASS", "test-pass")
    monkeypatch.setenv("DB_PATH", str(tmp_path / "alerts.db"))
    monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb-test")
    monkeypatch.setenv("SLACK_APP_TOKEN", "xapp-test")
    monkeypatch.setenv("SLACK_CHANNEL_ID", "C123")
    monkeypatch.setenv("WAZUH_ISOLATE_COMMAND", "edgesec-isolate0")
    monkeypatch.setenv("WAZUH_RELEASE_ISOLATE_COMMAND", "edgesec-release-isolate0")
    monkeypatch.setenv("ACTIVE_RESPONSE_ISOLATION_PRESERVE_CHANNELS_ACK", "1")
    monkeypatch.setenv("ACTIVE_RESPONSE_ISOLATION_VERIFIED_PLATFORMS", "macos")
    monkeypatch.setenv("ORG_PROFILE_PATH", str(tmp_path / "org_profile.yaml"))
    slack_render = fresh_bridge_import(["slack_actions", "slack_render"])["slack_render"]

    alert = {
        "agent": {
            "id": "003",
            "name": "MB-TitanCheng",
            "ip": "192.168.50.106",
            "os": {"platform": "darwin"},
        },
        "data": {"srcip": "192.168.50.106", "dstip": "8.8.8.8"},
        "rule": {"level": 10, "description": "Suspicious outbound connection"},
    }
    parsed = {
        "severity": "high",
        "summary_zh": "這台電腦主動連到可疑外部位址。",
    }
    payload = slack_render.build_quick_slack_blocks_payload(alert, parsed)
    payload = slack_render._augment_with_action_buttons(payload, alert, parsed)

    action_texts = [
        element["text"]["text"]
        for block in payload["attachments"][0]["blocks"]
        if block.get("type") == "actions"
        for element in block.get("elements", [])
    ]

    assert "封鎖來源 IP" not in action_texts
    assert "隔離端點" in action_texts


@pytest.mark.unit
def test_slack_sample_alert_does_not_show_emergency_actions(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("WAZUH_API_PASS", "test-pass")
    monkeypatch.setenv("DB_PATH", str(tmp_path / "alerts.db"))
    monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb-test")
    monkeypatch.setenv("SLACK_APP_TOKEN", "xapp-test")
    monkeypatch.setenv("SLACK_CHANNEL_ID", "C123")
    monkeypatch.setenv("ORG_PROFILE_PATH", str(tmp_path / "org_profile.yaml"))
    slack_render = fresh_bridge_import(["slack_actions", "slack_render"])["slack_render"]

    alert = {
        "@sampledata": True,
        "agent": {"id": "edgesec-test", "name": "EdgeSec-Pi 測試電腦"},
        "data": {"srcip": "203.0.113.10"},
        "rule": {"description": "EdgeSec-Pi built-in notification flow test"},
    }
    payload = slack_render.build_quick_slack_blocks_payload(
        alert,
        {
            "severity": "medium",
            "summary_zh": "這是通知流程測試。",
            "iocs": ["203.0.113.10"],
        },
    )
    payload = slack_render._augment_with_action_buttons(payload, alert, {"iocs": ["203.0.113.10"]})

    action_texts = [
        element["text"]["text"]
        for block in payload["attachments"][0]["blocks"]
        if block.get("type") == "actions"
        for element in block.get("elements", [])
    ]

    assert "封鎖來源 IP" not in action_texts
    assert "解除封鎖" not in action_texts
    assert "隔離端點" not in action_texts
    assert "補端點業務背景" not in action_texts


@pytest.mark.unit
def test_slack_non_numeric_agent_id_does_not_show_emergency_actions(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("WAZUH_API_PASS", "test-pass")
    monkeypatch.setenv("DB_PATH", str(tmp_path / "alerts.db"))
    monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb-test")
    monkeypatch.setenv("SLACK_APP_TOKEN", "xapp-test")
    monkeypatch.setenv("SLACK_CHANNEL_ID", "C123")
    monkeypatch.setenv("ORG_PROFILE_PATH", str(tmp_path / "org_profile.yaml"))
    slack_render = fresh_bridge_import(["slack_actions", "slack_render"])["slack_render"]

    alert = {
        "agent": {"id": "not-a-wazuh-id", "name": "lab-host"},
        "data": {"srcip": "8.8.8.8"},
        "rule": {"description": "SSH brute force"},
    }
    payload = slack_render.build_quick_slack_blocks_payload(
        alert,
        {
            "severity": "high",
            "summary_zh": "有人多次嘗試登入這台電腦。",
            "iocs": ["8.8.8.8"],
        },
    )
    payload = slack_render._augment_with_action_buttons(payload, alert, {"iocs": ["8.8.8.8"]})

    action_texts = [
        element["text"]["text"]
        for block in payload["attachments"][0]["blocks"]
        if block.get("type") == "actions"
        for element in block.get("elements", [])
    ]

    assert "封鎖來源 IP" not in action_texts
    assert "解除封鎖" not in action_texts
    assert "隔離端點" not in action_texts
