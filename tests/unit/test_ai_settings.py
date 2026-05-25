import sys
from pathlib import Path

import pytest

BRIDGE_DIR = Path(__file__).resolve().parents[2] / "wazuh-llm-bridge"
sys.path.insert(0, str(BRIDGE_DIR))

import ai_settings  # noqa: E402


@pytest.mark.unit
def test_ai_settings_preserves_secret_when_form_leaves_api_key_blank(tmp_path, monkeypatch):
    settings_path = tmp_path / "ai_settings.json"
    monkeypatch.setattr(ai_settings, "SETTINGS_PATH", settings_path)

    first = ai_settings.save({
        "provider": "openai",
        "base_url": "https://api.openai.com/v1",
        "model": "gpt-4.1-mini",
        "api_key": "sk-test",
    })
    second = ai_settings.save({
        "provider": "openai",
        "base_url": "https://api.openai.com/v1",
        "model": "gpt-4.1",
        "api_key": "",
    })
    activated = ai_settings.use_provider("openai")
    secret = ai_settings.load(include_secret=True)
    openai = next(provider for provider in second["providers"] if provider["key"] == "openai")

    assert openai["api_key_configured"] is True
    assert openai["api_key_preview"].startswith("sk")
    assert "*" in openai["api_key_preview"]
    assert second["provider"] == "lm_studio"
    assert activated["provider"] == "openai"
    assert activated["model"] == "gpt-4.1"
    assert secret["api_key"] == "sk-test"


@pytest.mark.unit
def test_ai_settings_normalizes_chat_completion_base_url(tmp_path, monkeypatch):
    settings_path = tmp_path / "ai_settings.json"
    monkeypatch.setattr(ai_settings, "SETTINGS_PATH", settings_path)

    result = ai_settings.save({
        "provider": "openai_compatible",
        "base_url": "http://localhost:1234/v1/chat/completions",
        "model": "local-model",
    })
    provider = next(item for item in result["providers"] if item["key"] == "openai_compatible")

    assert provider["base_url"] == "http://localhost:1234/v1"
    assert provider["chat_completions_url"] == "http://localhost:1234/v1/chat/completions"


@pytest.mark.unit
def test_saving_provider_config_does_not_change_active_provider(tmp_path, monkeypatch):
    settings_path = tmp_path / "ai_settings.json"
    monkeypatch.setattr(ai_settings, "SETTINGS_PATH", settings_path)

    saved = ai_settings.save({
        "provider": "openai",
        "base_url": "https://api.openai.com/v1",
        "model": "gpt-4.1-mini",
    })
    active = ai_settings.load()

    assert saved["provider"] == "lm_studio"
    assert active["provider"] == "lm_studio"
    assert next(item for item in saved["providers"] if item["key"] == "openai")["model"] == "gpt-4.1-mini"
