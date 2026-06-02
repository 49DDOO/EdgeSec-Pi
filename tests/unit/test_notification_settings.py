from __future__ import annotations

import pytest

from support import fresh_bridge_import


@pytest.mark.unit
def test_notification_settings_require_useful_slack_configuration(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("NOTIFICATION_SETTINGS_PATH", str(tmp_path / "notifications.json"))
    notification_settings = fresh_bridge_import(["notification_settings"])["notification_settings"]

    message = notification_settings.save({}, "slack")

    assert message == "Slack 尚未儲存：請填 Webhook URL，或填 Bot Token + App Token + Channel ID。"


@pytest.mark.unit
def test_notification_settings_preserve_existing_secret_when_blank(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("NOTIFICATION_SETTINGS_PATH", str(tmp_path / "notifications.json"))
    modules = fresh_bridge_import(["notify_channels", "notification_settings"])
    notify_channels = modules["notify_channels"]
    notification_settings = modules["notification_settings"]
    notify_channels.save_settings({"LINE_CHANNEL_ACCESS_TOKEN": "old-token"})

    message = notification_settings.save(
        {
            "LINE_CHANNEL_ACCESS_TOKEN": "",
            "LINE_USER_ID": "U123",
        },
        "line",
    )
    settings = notify_channels.load_settings()

    assert message == "LINE 設定已儲存。請按測試確認通知能送達。"
    assert settings["LINE_CHANNEL_ACCESS_TOKEN"] == "old-token"
    assert settings["LINE_USER_ID"] == "U123"
