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
    monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb-test")
    monkeypatch.setenv("SLACK_APP_TOKEN", "xapp-test")
    monkeypatch.setenv("SLACK_CHANNEL_ID", "C123")
    monkeypatch.setenv("BRIDGE_PUBLIC_URL", "https://edgesec.example")
    monkeypatch.setenv("ORG_PROFILE_PATH", str(tmp_path / "org_profile.yaml"))
    slack_render = fresh_bridge_import(["slack_actions", "slack_render"])["slack_render"]

    payload = slack_render.build_quick_slack_blocks_payload(
        {
            "agent": {"id": "003", "name": "MB-TitanCheng", "ip": "192.168.50.106"},
            "data": {"srcip": "198.51.100.42"},
            "rule": {"description": "SSH brute force"},
        },
        {
            "severity": "high",
            "summary_zh": "有人多次嘗試登入這台電腦。",
            "iocs": ["198.51.100.42"],
        },
    )
    payload = slack_render._augment_with_action_buttons(
        payload,
        {
            "agent": {"id": "003", "name": "MB-TitanCheng", "ip": "192.168.50.106"},
            "data": {"srcip": "198.51.100.42"},
        },
        {"iocs": ["198.51.100.42"]},
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
    assert "解除封鎖" in action_texts
    assert "隔離端點" in action_texts
    assert "封鎖來源 IP*：擋住外部來源" in help_text
    assert "隔離端點*：暫停這台電腦連線" in help_text
