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
        "admin_token",
        "admin_ui",
        "active_response_api",
        "admin_auth",
        "agent_loop",
        "app",
        "dashboard_ui",
        "db",
        "digest",
        "mcp_client",
        "notify_channels",
        "notification_settings",
        "ops_api",
        "org_profile",
        "owner_context",
        "prompting",
        "remote_action_tokens",
        "slack_action_tokens",
        "slack_actions",
        "slack_render",
        "triage_router",
        "wazuh",
        "webhook_api",
    }
    for name in bridge_modules:
        sys.modules.pop(name, None)
    return {name: importlib.import_module(name) for name in module_names}
