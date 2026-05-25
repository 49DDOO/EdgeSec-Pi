"""AI model provider settings for EdgeSec-Pi.

Settings are split into two concepts:
- provider configs: saved Base URL / model / API key per provider
- active provider: the provider currently used by new LLM requests
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


SETTINGS_PATH = Path(__file__).resolve().parent / "data" / "ai_settings.json"

PROVIDERS: dict[str, dict[str, str]] = {
    "lm_studio": {
        "label_zh": "LM Studio",
        "default_base_url": "http://localhost:1234/v1",
        "default_model": "local-model",
        "help_zh": "本機模型，不出網；適合資料敏感但會吃本機資源。",
    },
    "ollama": {
        "label_zh": "Ollama",
        "default_base_url": "http://localhost:11434/v1",
        "default_model": "llama3.1",
        "help_zh": "本機 Ollama OpenAI-compatible API；負載仍在本機。",
    },
    "openai": {
        "label_zh": "OpenAI",
        "default_base_url": "https://api.openai.com/v1",
        "default_model": "gpt-4.1-mini",
        "help_zh": "雲端模型，可降低本機負擔；告警內容會送出到 OpenAI API。",
    },
    "openai_compatible": {
        "label_zh": "OpenAI-compatible",
        "default_base_url": "http://localhost:8000/v1",
        "default_model": "local-model",
        "help_zh": "可接 vLLM、OpenRouter、Groq、Together 或企業內部模型閘道。",
    },
}


def _env_provider() -> str:
    provider = os.getenv("AI_PROVIDER", "lm_studio").strip() or "lm_studio"
    return provider if provider in PROVIDERS else "openai_compatible"


def _env_base_url() -> str:
    url = os.getenv("AI_BASE_URL") or os.getenv("LM_STUDIO_URL") or ""
    return _normalize_base_url(url) or PROVIDERS["lm_studio"]["default_base_url"]


def _env_enabled() -> bool:
    return os.getenv("AI_ENABLED", "true").strip().lower() not in {"0", "false", "no", "off"}


def _env_timeout() -> float:
    try:
        return max(5.0, min(float(os.getenv("AI_TIMEOUT_S") or os.getenv("LM_TIMEOUT_S") or "60"), 300.0))
    except Exception:
        return 60.0


def _env_concurrency() -> int:
    try:
        return max(1, min(int(os.getenv("AI_MAX_CONCURRENT_REQUESTS", "2")), 16))
    except Exception:
        return 2


def _normalize_base_url(value: Any) -> str:
    url = str(value or "").strip().rstrip("/")
    if url.endswith("/chat/completions"):
        url = url.removesuffix("/chat/completions").rstrip("/")
    return url


def _mask_secret(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if len(text) <= 10:
        return f"{text[:2]}{'*' * max(len(text) - 4, 2)}{text[-2:]}"
    return f"{text[:5]}{'*' * 10}{text[-4:]}"


def _read_saved() -> dict[str, Any]:
    if not SETTINGS_PATH.exists():
        return {}
    try:
        raw = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
        return raw if isinstance(raw, dict) else {}
    except Exception:
        return {}


def _default_provider_config(provider: str) -> dict[str, Any]:
    meta = PROVIDERS[provider]
    return {
        "base_url": meta["default_base_url"],
        "model": meta["default_model"],
        "api_key": "",
        "timeout_s": _env_timeout(),
        "max_concurrent_requests": _env_concurrency(),
    }


def _coerce_provider_config(provider: str, raw: Any) -> dict[str, Any]:
    values = _default_provider_config(provider)
    if isinstance(raw, dict):
        values.update(raw)
    base_url = _normalize_base_url(values.get("base_url")) or PROVIDERS[provider]["default_base_url"]
    model = str(values.get("model") or PROVIDERS[provider]["default_model"]).strip()
    try:
        timeout_s = max(5.0, min(float(values.get("timeout_s") or 60), 300.0))
    except Exception:
        timeout_s = _env_timeout()
    try:
        max_concurrent = max(1, min(int(values.get("max_concurrent_requests") or 2), 16))
    except Exception:
        max_concurrent = _env_concurrency()
    return {
        "base_url": base_url,
        "model": model,
        "api_key": str(values.get("api_key") or ""),
        "timeout_s": timeout_s,
        "max_concurrent_requests": max_concurrent,
    }


def _coerce_store(raw: dict[str, Any]) -> dict[str, Any]:
    env_provider = _env_provider()
    active_provider = str(raw.get("active_provider") or raw.get("provider") or env_provider).strip()
    if active_provider not in PROVIDERS:
        active_provider = env_provider

    provider_configs: dict[str, dict[str, Any]] = {}
    raw_configs = raw.get("provider_configs") if isinstance(raw.get("provider_configs"), dict) else {}
    for key in PROVIDERS:
        provider_configs[key] = _coerce_provider_config(key, raw_configs.get(key))

    env_active = provider_configs[env_provider].copy()
    env_active.update({
        "base_url": _env_base_url(),
        "model": os.getenv("AI_MODEL") or os.getenv("LM_MODEL") or PROVIDERS[env_provider]["default_model"],
        "api_key": os.getenv("AI_API_KEY") or os.getenv("OPENAI_API_KEY") or env_active.get("api_key", ""),
        "timeout_s": _env_timeout(),
        "max_concurrent_requests": _env_concurrency(),
    })
    provider_configs[env_provider] = _coerce_provider_config(env_provider, env_active)

    # Migrate the earlier flat format into the chosen provider config.
    if raw.get("provider") in PROVIDERS and not raw_configs:
        flat_provider = str(raw.get("provider"))
        flat = {
            "base_url": raw.get("base_url"),
            "model": raw.get("model"),
            "api_key": raw.get("api_key"),
            "timeout_s": raw.get("timeout_s"),
            "max_concurrent_requests": raw.get("max_concurrent_requests"),
        }
        provider_configs[flat_provider] = _coerce_provider_config(flat_provider, flat)

    return {
        "enabled": bool(raw.get("enabled", _env_enabled())),
        "active_provider": active_provider,
        "provider_configs": provider_configs,
    }


def _write_store(store: dict[str, Any]) -> None:
    SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    SETTINGS_PATH.write_text(json.dumps(store, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _public_provider(provider: str, config: dict[str, Any], active_provider: str, include_secret: bool) -> dict[str, Any]:
    item = {
        "key": provider,
        **PROVIDERS[provider],
        "base_url": config["base_url"],
        "chat_completions_url": f"{config['base_url']}/chat/completions",
        "model": config["model"],
        "timeout_s": config["timeout_s"],
        "max_concurrent_requests": config["max_concurrent_requests"],
        "api_key_configured": bool(config["api_key"]),
        "api_key_preview": _mask_secret(config["api_key"]),
        "is_active": provider == active_provider,
    }
    if include_secret:
        item["api_key"] = config["api_key"]
    return item


def load(include_secret: bool = False) -> dict[str, Any]:
    store = _coerce_store(_read_saved())
    active_provider = store["active_provider"]
    active_config = store["provider_configs"][active_provider]
    providers = [
        _public_provider(key, store["provider_configs"][key], active_provider, include_secret)
        for key in PROVIDERS
    ]
    public = {
        "enabled": store["enabled"],
        "provider": active_provider,
        "active_provider": active_provider,
        "base_url": active_config["base_url"],
        "chat_completions_url": f"{active_config['base_url']}/chat/completions",
        "model": active_config["model"],
        "timeout_s": active_config["timeout_s"],
        "max_concurrent_requests": active_config["max_concurrent_requests"],
        "api_key_configured": bool(active_config["api_key"]),
        "api_key_preview": _mask_secret(active_config["api_key"]),
        "providers": providers,
    }
    if include_secret:
        public["api_key"] = active_config["api_key"]
    return public


def save(values: dict[str, Any]) -> dict[str, Any]:
    store = _coerce_store(_read_saved())
    provider = str(values.get("provider") or store["active_provider"]).strip()
    if provider not in PROVIDERS:
        raise ValueError("unknown AI provider")

    config = store["provider_configs"][provider].copy()
    for key in ("base_url", "model", "timeout_s", "max_concurrent_requests"):
        if key in values:
            config[key] = values[key]
    if str(values.get("api_key") or "").strip():
        config["api_key"] = str(values.get("api_key") or "").strip()
    if values.get("clear_api_key") is True:
        config["api_key"] = ""
    store["provider_configs"][provider] = _coerce_provider_config(provider, config)
    if "enabled" in values:
        store["enabled"] = bool(values.get("enabled"))
    _write_store(store)
    result = load()
    result["message"] = "模型設定已儲存，尚未切換使用" if provider != store["active_provider"] else "目前使用模型設定已儲存"
    return result


def use_provider(provider: str) -> dict[str, Any]:
    provider = str(provider or "").strip()
    if provider not in PROVIDERS:
        raise ValueError("unknown AI provider")
    store = _coerce_store(_read_saved())
    store["active_provider"] = provider
    _write_store(store)
    result = load()
    result["message"] = f"已切換使用 {PROVIDERS[provider]['label_zh']}"
    return result
