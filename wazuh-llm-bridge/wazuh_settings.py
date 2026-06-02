"""Wazuh connection settings for split EdgeSec-Pi deployments."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

try:
    from dotenv import load_dotenv

    _root = Path(__file__).resolve().parent.parent
    for _env_path in (
        _root / "bridge.env",
        Path(__file__).resolve().parent / ".env",
        _root / "wazuh-stack" / "wazuh-mcp" / ".env",
    ):
        if _env_path.exists():
            load_dotenv(_env_path, override=False)
except ImportError:
    pass


# 預設使用套件內 data/ 路徑；WAZUH_SETTINGS_PATH 可覆寫（測試隔離 / 自訂部署）
SETTINGS_PATH = Path(
    os.getenv("WAZUH_SETTINGS_PATH")
    or (Path(__file__).resolve().parent / "data" / "wazuh_settings.json")
)

SECRET_KEYS = {"WAZUH_API_PASS", "WAZUH_INDEXER_PASS", "WEBHOOK_SECRET"}
DEPLOYMENT_MODES = {"managed", "existing", "local_lab"}
DEPLOYMENT_MODE_LABELS = {
    "managed": "EdgeSec 代管 Wazuh",
    "existing": "連接現有 Wazuh",
    "local_lab": "本機快速體驗",
}


def _read_saved() -> dict[str, Any]:
    if not SETTINGS_PATH.exists():
        return {}
    try:
        raw = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
        return raw if isinstance(raw, dict) else {}
    except Exception:
        return {}


def _write_saved(settings: dict[str, Any]) -> None:
    SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    SETTINGS_PATH.write_text(json.dumps(settings, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    try:
        SETTINGS_PATH.chmod(0o600)
    except OSError:
        pass


def _bool(value: Any, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() not in {"0", "false", "no", "off"}


def _mask_secret(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if len(text) <= 10:
        return f"{text[:2]}{'*' * max(len(text) - 4, 2)}{text[-2:]}"
    return f"{text[:5]}{'*' * 10}{text[-4:]}"


def _env_default(key: str) -> Any:
    defaults: dict[str, Any] = {
        "WAZUH_DEPLOYMENT_MODE": "existing",
        "WAZUH_API_URL": "https://localhost:55000",
        "WAZUH_API_USER": "wazuh-wui",
        "WAZUH_API_PASS": "",
        "WAZUH_VERIFY_SSL": False,
        "WAZUH_INDEXER_URL": "https://localhost:9200",
        "WAZUH_INDEXER_USER": "admin",
        "WAZUH_INDEXER_PASS": "",
        "WAZUH_INDEXER_VERIFY_SSL": False,
        "BRIDGE_PUBLIC_URL": "",
        "WEBHOOK_SECRET": "",
    }
    if key in {"WAZUH_VERIFY_SSL", "WAZUH_INDEXER_VERIFY_SSL"}:
        return _bool(os.getenv(key), bool(defaults[key]))
    return os.getenv(key, defaults.get(key, ""))


def _coerce(raw: dict[str, Any]) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for key in (
        "WAZUH_DEPLOYMENT_MODE",
        "WAZUH_API_URL",
        "WAZUH_API_USER",
        "WAZUH_API_PASS",
        "WAZUH_VERIFY_SSL",
        "WAZUH_INDEXER_URL",
        "WAZUH_INDEXER_USER",
        "WAZUH_INDEXER_PASS",
        "WAZUH_INDEXER_VERIFY_SSL",
        "BRIDGE_PUBLIC_URL",
        "WEBHOOK_SECRET",
    ):
        value = raw.get(key, _env_default(key))
        if key == "WAZUH_DEPLOYMENT_MODE":
            normalized = str(value or "").strip().lower()
            values[key] = normalized if normalized in DEPLOYMENT_MODES else "existing"
        elif key in {"WAZUH_VERIFY_SSL", "WAZUH_INDEXER_VERIFY_SSL"}:
            values[key] = _bool(value, bool(_env_default(key)))
        elif key.endswith("_URL"):
            values[key] = str(value or "").strip().rstrip("/")
        else:
            values[key] = str(value or "").strip()
    return values


def values(include_secret: bool = False) -> dict[str, Any]:
    merged = _coerce(_read_saved())
    public: dict[str, Any] = {}
    for key, value in merged.items():
        if key in SECRET_KEYS and not include_secret:
            public[key] = ""
            public[f"{key}_configured"] = bool(value)
            public[f"{key}_preview"] = _mask_secret(str(value))
        else:
            public[key] = value
    public["WAZUH_DEPLOYMENT_LABEL_ZH"] = DEPLOYMENT_MODE_LABELS.get(
        str(merged.get("WAZUH_DEPLOYMENT_MODE") or "existing"),
        DEPLOYMENT_MODE_LABELS["existing"],
    )
    public["webhook_url"] = webhook_url(merged)
    return public


def save(update: dict[str, Any]) -> dict[str, Any]:
    current = _coerce(_read_saved())
    for key, value in update.items():
        if key not in current:
            continue
        if key in SECRET_KEYS and not str(value or "").strip():
            continue
        current[key] = value
    for key in SECRET_KEYS:
        if update.get(f"clear_{key}") is True:
            current[key] = ""
    current = _coerce(current)
    _write_saved(current)
    result = values()
    result["message"] = "Wazuh 連線設定已儲存；新查詢會立即使用，不需重新啟動。"
    return result


def get(key: str, default: Any = "") -> Any:
    return _coerce(_read_saved()).get(key, default)


def api_config() -> dict[str, Any]:
    current = _coerce(_read_saved())
    return {
        "url": current["WAZUH_API_URL"],
        "user": current["WAZUH_API_USER"],
        "password": current["WAZUH_API_PASS"],
        "verify_ssl": bool(current["WAZUH_VERIFY_SSL"]),
    }


def indexer_config() -> dict[str, Any]:
    current = _coerce(_read_saved())
    return {
        "url": current["WAZUH_INDEXER_URL"],
        "user": current["WAZUH_INDEXER_USER"],
        "password": current["WAZUH_INDEXER_PASS"],
        "verify_ssl": bool(current["WAZUH_INDEXER_VERIFY_SSL"]),
    }


def webhook_url(current: dict[str, Any] | None = None) -> str:
    cfg = current or _coerce(_read_saved())
    public_url = str(cfg.get("BRIDGE_PUBLIC_URL") or "").strip().rstrip("/")
    return f"{public_url}/webhook" if public_url else "/webhook"
