from __future__ import annotations

import pytest

from support import fresh_bridge_import


@pytest.mark.unit
def test_line_text_uses_llm_result_and_clean_endpoint_context(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("WAZUH_API_PASS", "test-pass")
    monkeypatch.setenv("ORG_PROFILE_PATH", str(tmp_path / "org_profile.yaml"))
    modules = fresh_bridge_import(["org_profile", "notify_channels"])
    org_profile = modules["org_profile"]
    notify_channels = modules["notify_channels"]

    org_profile.upsert_asset(
        "titandeacStudio",
        {
            "role": "開發者",
            "criticality": "critical",
            "business_hours": "Daily 10:30 Asia/Taipei",
            "notes": "使用者提供的 IP 為 ::1 (localhost / 本機迴圈位址)，不作為實際主機位置判斷。",
        },
    )

    text = notify_channels._alert_text(
        {
            "agent": {
                "name": "titandeacStudio",
                "ip": "0000:0000:0000:0000:0000:0000:0000:0001",
            }
        },
        {
            "severity": "medium",
            "summary_zh": "開發者電腦的網路狀態發生變更。",
            "impact_zh": "若不是本人操作，可能代表有人嘗試建立未授權連線。",
            "next_step_zh": "請開發者確認是否正在測試網路；若不是，請通知 IT 檢查。",
        },
    )

    assert "哪台電腦" in text
    assert "電腦：titandeacStudio" in text
    assert "用途：開發者" in text
    assert "發生什麼事" in text
    assert "開發者電腦的網路狀態發生變更" in text
    assert "立刻該做的事" in text
    assert "0000:0000" not in text
    assert "::1" not in text
    assert "localhost" not in text
