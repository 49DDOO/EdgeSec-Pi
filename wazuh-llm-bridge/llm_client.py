"""Shared chat-completion client for all EdgeSec-Pi LLM calls."""
from __future__ import annotations

import asyncio
from typing import Any, Optional

import httpx

import ai_settings

_semaphore: Optional[asyncio.Semaphore] = None
_semaphore_limit = 0


def current_config(include_secret: bool = False) -> dict[str, Any]:
    return ai_settings.load(include_secret=include_secret)


def _headers(api_key: str) -> dict[str, str]:
    api_key = str(api_key or "").strip()
    return {"Authorization": f"Bearer {api_key}"} if api_key else {}


def _request_semaphore(limit: int) -> asyncio.Semaphore:
    global _semaphore, _semaphore_limit
    limit = max(1, min(int(limit or 1), 16))
    if _semaphore is None or _semaphore_limit != limit:
        _semaphore = asyncio.Semaphore(limit)
        _semaphore_limit = limit
    return _semaphore


async def chat_completion(
    client: httpx.AsyncClient,
    payload: dict[str, Any],
    timeout: Optional[float] = None,
) -> dict[str, Any]:
    settings = ai_settings.load(include_secret=True)
    if not settings.get("enabled", True):
        raise RuntimeError("AI model analysis is disabled")
    request = dict(payload)
    request["model"] = settings["model"]
    headers = _headers(str(settings.get("api_key") or ""))
    semaphore = _request_semaphore(int(settings.get("max_concurrent_requests") or 2))
    async with semaphore:
        response = await client.post(
            settings["chat_completions_url"],
            json=request,
            headers=headers,
            timeout=timeout or float(settings["timeout_s"]),
        )
    response.raise_for_status()
    return response.json()


async def list_models(
    client: httpx.AsyncClient,
    base_url: str,
    api_key: str = "",
    timeout: float = 12.0,
) -> list[str]:
    url = str(base_url or "").strip().rstrip("/")
    if url.endswith("/chat/completions"):
        url = url.removesuffix("/chat/completions").rstrip("/")
    if not url:
        raise ValueError("base_url is required")
    response = await client.get(f"{url}/models", headers=_headers(api_key), timeout=timeout)
    response.raise_for_status()
    body = response.json()
    items = body.get("data") if isinstance(body, dict) else body
    if not isinstance(items, list):
        return []
    models: list[str] = []
    for item in items:
        if isinstance(item, dict):
            model_id = str(item.get("id") or item.get("name") or "").strip()
        else:
            model_id = str(item or "").strip()
        if model_id:
            models.append(model_id)
    return sorted(set(models), key=str.lower)


async def test_connection(client: httpx.AsyncClient) -> dict[str, Any]:
    settings = ai_settings.load(include_secret=True)
    payload = {
        "messages": [
            {"role": "system", "content": "Reply with JSON only."},
            {"role": "user", "content": "{\"ok\": true}"},
        ],
        "temperature": 0,
        "stream": False,
    }
    data = await chat_completion(client, payload, timeout=min(float(settings["timeout_s"]), 30.0))
    content = data["choices"][0]["message"].get("content", "")
    return {
        "ok": True,
        "provider": settings["provider"],
        "model": settings["model"],
        "base_url": settings["base_url"],
        "reply_preview": str(content)[:200],
    }
