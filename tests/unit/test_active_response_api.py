from __future__ import annotations

import asyncio
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

from support import fresh_bridge_import


def _test_app(router) -> FastAPI:
    app = FastAPI()
    app.include_router(router)
    return app


@pytest.mark.unit
def test_active_response_requires_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WAZUH_API_PASS", "test-pass")
    monkeypatch.setenv("ACTIVE_RESPONSE_TOKEN", "")
    active_response_api = fresh_bridge_import(["active_response_api"])["active_response_api"]

    async def scenario() -> None:
        transport = httpx.ASGITransport(app=_test_app(active_response_api.router))
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.post(
                "/active-response/block-ip",
                json={"agent_id": "002", "ip": "198.51.100.42"},
            )

        assert response.status_code == 503
        assert "ACTIVE_RESPONSE_TOKEN is not set" in response.text

    asyncio.run(scenario())


@pytest.mark.unit
def test_active_response_blocks_ip_with_authorized_request(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WAZUH_API_PASS", "test-pass")
    monkeypatch.setenv("ACTIVE_RESPONSE_TOKEN", "secret")
    active_response_api = fresh_bridge_import(["active_response_api"])["active_response_api"]
    calls: list[tuple[str, str]] = []

    async def fake_block_ip(agent_id: str, ip: str) -> dict[str, Any]:
        calls.append((agent_id, ip))
        return {"data": {"total_failed_items": 0}}

    monkeypatch.setattr(active_response_api.wazuh, "block_ip", fake_block_ip)

    async def scenario() -> None:
        transport = httpx.ASGITransport(app=_test_app(active_response_api.router))
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.post(
                "/active-response/block-ip",
                headers={"Authorization": "Bearer secret"},
                json={"agent_id": "002", "ip": "198.51.100.42"},
            )

        assert response.status_code == 200
        assert response.json()["ok"] is True

    asyncio.run(scenario())
    assert calls == [("002", "198.51.100.42")]


@pytest.mark.unit
def test_active_response_reports_disabled_isolation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WAZUH_API_PASS", "test-pass")
    monkeypatch.setenv("ACTIVE_RESPONSE_TOKEN", "secret")
    active_response_api = fresh_bridge_import(["active_response_api"])["active_response_api"]

    async def fake_isolate_agent(agent_id: str, reason: str = "") -> dict[str, Any]:
        return {"ok": False, "error": "endpoint isolation is not enabled"}

    monkeypatch.setattr(active_response_api.wazuh, "isolate_agent", fake_isolate_agent)

    async def scenario() -> None:
        transport = httpx.ASGITransport(app=_test_app(active_response_api.router))
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.post(
                "/active-response/isolate-endpoint",
                headers={"Authorization": "Bearer secret"},
                json={"agent_id": "003", "reason": "suspected compromise"},
            )

        assert response.status_code == 501
        assert response.json()["detail"] == "endpoint isolation is not enabled"

    asyncio.run(scenario())
