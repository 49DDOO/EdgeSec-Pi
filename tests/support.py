from __future__ import annotations

import importlib
import socket
import sys
import threading
import time
from collections.abc import Iterable
from pathlib import Path
from types import ModuleType
from typing import Any

import uvicorn


ROOT = Path(__file__).resolve().parents[1]
BRIDGE_DIR = ROOT / "wazuh-llm-bridge"


def ensure_bridge_on_path() -> None:
    bridge_path = str(BRIDGE_DIR)
    if bridge_path not in sys.path:
        sys.path.insert(0, bridge_path)


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_for_port(port: int, timeout_s: float = 10.0) -> None:
    deadline = time.monotonic() + timeout_s
    last_error: OSError | None = None
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError as exc:
            last_error = exc
            time.sleep(0.05)
    raise RuntimeError(f"port {port} did not open within {timeout_s}s: {last_error}")


def run_uvicorn_in_thread(app: Any, port: int) -> threading.Thread:
    thread = threading.Thread(
        target=lambda: uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning"),
        daemon=True,
    )
    thread.start()
    wait_for_port(port)
    return thread


def fresh_bridge_import(module_names: Iterable[str]) -> dict[str, ModuleType]:
    """Import bridge modules after env setup, clearing old import-time config."""
    ensure_bridge_on_path()
    bridge_modules = {
        "active_response_api",
        "active_response_lifecycle",
        "active_response_safety",
        "active_response_state",
        "agent_loop",
        "alert_queue",
        "app",
        "canonical_signal",
        "canonical_context",
        "dashboard_notifications_api",
        "dashboard_sample_data_api",
        "dashboard_sources_api",
        "dashboard_wazuh_settings_api",
        "dashboard_ui",
        "db",
        "digest",
        "investigation_context",
        "investigation_evidence",
        "investigation_playbooks",
        "investigation_rules",
        "investigation_suggestions",
        "investigation_tools",
        "mcp_client",
        "notify_channels",
        "notification_settings",
        "ops_api",
        "org_profile",
        "owner_context",
        "prompting",
        "prompt_safety",
        "remote_action_tokens",
        "response_router",
        "self_test",
        "siem",
        "source_settings",
        "slack_action_tokens",
        "slack_actions",
        "slack_render",
        "tool_loop",
        "triage_router",
        "wazuh",
        "wazuh_hardening",
        "wazuh_settings",
        "webhook_api",
    }
    for name in bridge_modules:
        sys.modules.pop(name, None)
    return {name: importlib.import_module(name) for name in module_names}
