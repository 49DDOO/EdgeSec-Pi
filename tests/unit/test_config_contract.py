from __future__ import annotations

from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.unit
def test_bridge_env_example_is_the_service_location_map() -> None:
    text = (ROOT / "bridge.env.example").read_text()

    required_keys = {
        "BRIDGE_PORT",
        "BRIDGE_PUBLIC_URL",
        "LM_STUDIO_URL",
        "WAZUH_API_URL",
        "WAZUH_INDEXER_URL",
        "MANAGER_HOST",
        "WAZUH_AGENT_PORT",
        "WAZUH_AUTHD_PORT",
        "MCP_HOST_PORT",
        "MCP_SERVER_URL",
        "LOBECHAT_URL",
    }

    missing = [key for key in sorted(required_keys) if f"{key}=" not in text]
    assert missing == []


@pytest.mark.unit
def test_bridge_env_example_does_not_contain_runtime_secrets() -> None:
    text = (ROOT / "bridge.env.example").read_text()

    secret_keys = {
        "SLACK_WEBHOOK_URL",
        "SLACK_BOT_TOKEN",
        "SLACK_APP_TOKEN",
        "MCP_API_KEY",
        "WAZUH_API_PASS",
        "ACTIVE_RESPONSE_TOKEN",
        "WEBHOOK_SECRET",
    }

    leaked = [key for key in sorted(secret_keys) if f"{key}=" in text]
    assert leaked == []


@pytest.mark.unit
def test_bridge_secret_template_does_not_redeclare_service_locations() -> None:
    text = (ROOT / "wazuh-llm-bridge" / ".env.example").read_text()

    service_location_keys = {
        "BRIDGE_PORT",
        "BRIDGE_PUBLIC_URL",
        "LM_STUDIO_URL",
        "WAZUH_API_URL",
        "WAZUH_INDEXER_URL",
        "MCP_SERVER_URL",
    }

    duplicates = [key for key in sorted(service_location_keys) if f"{key}=" in text]
    assert duplicates == []
