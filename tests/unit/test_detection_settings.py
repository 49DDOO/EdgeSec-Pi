import sys
from pathlib import Path

import pytest

BRIDGE_DIR = Path(__file__).resolve().parents[2] / "wazuh-llm-bridge"
sys.path.insert(0, str(BRIDGE_DIR))

import detection_settings  # noqa: E402


@pytest.mark.unit
def test_network_category_can_skip_llm_without_dropping_raw_alert(tmp_path, monkeypatch):
    settings_path = tmp_path / "detection_categories.json"
    monkeypatch.setattr(detection_settings, "SETTINGS_PATH", settings_path)
    detection_settings.save({
        **detection_settings.DEFAULT_ENABLED,
        "network": False,
    })
    alert = {
        "rule": {"id": "533", "level": 7, "description": "Listened ports status changed"},
        "agent": {"id": "004", "name": "dev-mac", "ip": "127.0.0.1"},
        "full_log": "netstat: new listening port 8080/tcp detected",
    }

    enabled, category = detection_settings.is_enabled_for_alert(alert)
    verdict = detection_settings.lightweight_verdict(alert, category)

    assert enabled is False
    assert category == "network"
    assert verdict["llm_skipped"] is True
    assert verdict["detection_category"] == "network"
    assert "未送 LLM" in verdict["impact_zh"]


@pytest.mark.unit
def test_rejects_disabling_every_detection_category(tmp_path, monkeypatch):
    settings_path = tmp_path / "detection_categories.json"
    monkeypatch.setattr(detection_settings, "SETTINGS_PATH", settings_path)

    with pytest.raises(ValueError, match="至少需要啟用一個"):
        detection_settings.save({key: False for key in detection_settings.DEFAULT_ENABLED})


@pytest.mark.unit
def test_detection_preset_persists_enabled_categories(tmp_path, monkeypatch):
    settings_path = tmp_path / "detection_categories.json"
    monkeypatch.setattr(detection_settings, "SETTINGS_PATH", settings_path)

    saved = detection_settings.save(preset="recommended")
    loaded = detection_settings.load()

    assert saved["active_preset"] == "recommended"
    assert loaded["active_preset"] == "recommended"
    assert loaded["enabled"]["authentication"] is True
    assert loaded["enabled"]["network"] is True
    assert loaded["enabled"]["other"] is False
    assert any(item["key"] == "recommended" for item in loaded["presets"])
    assert loaded["noise"]["noisy_categories"] == ["sca", "network"]


@pytest.mark.unit
def test_custom_detection_settings_report_noise_and_core_warnings(tmp_path, monkeypatch):
    settings_path = tmp_path / "detection_categories.json"
    monkeypatch.setattr(detection_settings, "SETTINGS_PATH", settings_path)
    monkeypatch.setenv("FP_SUPPRESSION_ENABLED", "0")

    enabled = {
        **detection_settings.DEFAULT_ENABLED,
        "fim": False,
        "malware": False,
        "system": True,
        "compliance": True,
        "other": True,
    }
    saved = detection_settings.save(enabled)

    assert saved["active_preset"] == "custom"
    assert saved["noise"]["false_positive_suppression"] is False
    assert "fim" in saved["noise"]["core_disabled"]
    assert "malware" in saved["noise"]["core_disabled"]
    assert saved["noise"]["warnings"]


@pytest.mark.unit
def test_rejects_noise_only_detection_settings(tmp_path, monkeypatch):
    settings_path = tmp_path / "detection_categories.json"
    monkeypatch.setattr(detection_settings, "SETTINGS_PATH", settings_path)
    enabled = {key: False for key in detection_settings.DEFAULT_ENABLED}
    enabled["network"] = True

    with pytest.raises(ValueError, match="核心資安偵測"):
        detection_settings.save(enabled)
