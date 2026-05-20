from __future__ import annotations

from typing import Any

from support import ensure_bridge_on_path


def pytest_configure(config: Any) -> None:
    ensure_bridge_on_path()
