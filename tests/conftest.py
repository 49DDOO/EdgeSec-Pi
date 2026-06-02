from __future__ import annotations

import os
from typing import Any

import pytest

from support import ensure_bridge_on_path


def pytest_configure(config: Any) -> None:
    ensure_bridge_on_path()


@pytest.fixture(autouse=True)
def _isolated_wazuh_settings(tmp_path, monkeypatch):
    """將 wazuh_settings 的持久化檔導向臨時路徑，避免讀到本機真實設定
    （例如已設定的 WEBHOOK_SECRET）而污染測試。"""
    monkeypatch.setenv("WAZUH_SETTINGS_PATH", str(tmp_path / "wazuh_settings.json"))
    yield
