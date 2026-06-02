"""FastAPI routes for SIEM alert intake.

The webhook must stay small and predictable: authenticate the caller,
normalize the alert, enqueue it, and return quickly. LLM work remains in
the background workers owned by app.py.
"""
from __future__ import annotations

import asyncio
import logging
import os
import secrets
from typing import Any

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import JSONResponse

import siem
import wazuh_settings

log = logging.getLogger("webhook-api")

router = APIRouter(tags=["webhook"])


def _webhook_secret() -> str | None:
    return str(wazuh_settings.get("WEBHOOK_SECRET") or os.getenv("WEBHOOK_SECRET", "")).strip() or None


def _check_webhook_secret(request: Request) -> None:
    """Enforce WEBHOOK_SECRET if set. No-op when unset."""
    secret = _webhook_secret()
    if not secret:
        return
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer ") or not secrets.compare_digest(auth[7:], secret):
        raise HTTPException(status_code=401, detail="invalid webhook secret")


def _queue_from_request(request: Request) -> asyncio.Queue:
    queue = getattr(request.app.state, "queue", None)
    if queue is None:
        raise HTTPException(status_code=503, detail="queue not initialized")
    return queue


async def _enqueue_webhook(request: Request, source_hint: str = "auto") -> JSONResponse:
    _check_webhook_secret(request)
    try:
        payload: dict[str, Any] = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid JSON")
    try:
        alert = siem.normalize_alert(payload, source_hint=source_hint)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    queue = _queue_from_request(request)
    try:
        queue.put_nowait(alert)
    except asyncio.QueueFull:
        log.warning("queue full (%d) — rejecting alert", queue.qsize())
        raise HTTPException(status_code=503, detail="queue full, retry later")

    return JSONResponse(
        {
            "queued": True,
            "queue_size": queue.qsize(),
            "siem_source": (alert.get("_edgesec") or {}).get("siem_source", "unknown"),
        },
        status_code=status.HTTP_202_ACCEPTED,
    )


@router.post("/webhook", status_code=status.HTTP_202_ACCEPTED)
async def webhook(request: Request) -> JSONResponse:
    """Default alert intake for existing Wazuh integrations."""
    return await _enqueue_webhook(request, source_hint="auto")


@router.post("/webhook/{source}", status_code=status.HTTP_202_ACCEPTED)
async def webhook_source(source: str, request: Request) -> JSONResponse:
    """Explicit SIEM intake, e.g. /webhook/splunk or /webhook/sentinel."""
    return await _enqueue_webhook(request, source_hint=source)
