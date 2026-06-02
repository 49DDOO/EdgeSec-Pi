from __future__ import annotations

import asyncio

import httpx
import pytest
from fastapi import FastAPI

from support import fresh_bridge_import


def _test_app(router, queue: asyncio.Queue | None = None) -> FastAPI:
    app = FastAPI()
    app.include_router(router)
    if queue is not None:
        app.state.queue = queue
    return app


@pytest.mark.unit
def test_webhook_rejects_invalid_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEBHOOK_SECRET", "secret")
    webhook_api = fresh_bridge_import(["webhook_api"])["webhook_api"]

    async def scenario() -> None:
        transport = httpx.ASGITransport(app=_test_app(webhook_api.router, asyncio.Queue()))
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.post("/webhook", json={"rule": {"id": "1"}})

        assert response.status_code == 401
        assert response.json()["detail"] == "invalid webhook secret"

    asyncio.run(scenario())


@pytest.mark.unit
def test_webhook_normalizes_and_enqueues_alert(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEBHOOK_SECRET", "secret")
    webhook_api = fresh_bridge_import(["webhook_api"])["webhook_api"]

    async def scenario() -> None:
        queue: asyncio.Queue = asyncio.Queue(maxsize=2)
        transport = httpx.ASGITransport(app=_test_app(webhook_api.router, queue))
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.post(
                "/webhook/splunk",
                headers={"Authorization": "Bearer secret"},
                json={
                    "rule": {"id": "5712", "level": 10, "description": "SSH brute force"},
                    "agent": {"name": "PC001"},
                },
            )

        assert response.status_code == 202
        assert response.json()["queued"] is True
        assert response.json()["queue_size"] == 1
        queued = queue.get_nowait()
        assert queued["rule"]["id"] == "5712"
        assert queued["_edgesec"]["siem_source"] == "splunk"

    asyncio.run(scenario())


@pytest.mark.unit
def test_webhook_returns_backpressure_when_queue_is_full(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEBHOOK_SECRET", "")
    webhook_api = fresh_bridge_import(["webhook_api"])["webhook_api"]

    async def scenario() -> None:
        queue: asyncio.Queue = asyncio.Queue(maxsize=1)
        queue.put_nowait({"already": "queued"})
        transport = httpx.ASGITransport(app=_test_app(webhook_api.router, queue))
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.post(
                "/webhook",
                json={"rule": {"id": "5712", "level": 10, "description": "SSH brute force"}},
            )

        assert response.status_code == 503
        assert response.json()["detail"] == "queue full, retry later"

    asyncio.run(scenario())


@pytest.mark.unit
def test_webhook_rejects_unknown_explicit_source(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEBHOOK_SECRET", "")
    webhook_api = fresh_bridge_import(["webhook_api"])["webhook_api"]

    async def scenario() -> None:
        queue: asyncio.Queue = asyncio.Queue(maxsize=2)
        transport = httpx.ASGITransport(app=_test_app(webhook_api.router, queue))
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.post("/webhook/not-a-real-source", json={"message": "hello"})

        assert response.status_code == 400
        assert "unsupported SIEM source" in response.json()["detail"]
        assert queue.empty()

    asyncio.run(scenario())
