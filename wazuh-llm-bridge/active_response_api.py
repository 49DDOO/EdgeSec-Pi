"""FastAPI routes for Wazuh Active Response actions.

The main bridge pipeline receives alerts and runs LLM analysis. Active
Response is a separate, higher-risk control surface, so its auth and error
mapping live here instead of in app.py.
"""
from __future__ import annotations

import logging
import os
import secrets
from typing import Any

import httpx
from fastapi import APIRouter, HTTPException, Request

import wazuh

log = logging.getLogger("active-response-api")

router = APIRouter(prefix="/active-response", tags=["active-response"])


def active_response_enabled() -> bool:
    return bool(_active_response_token())


def _active_response_token() -> str | None:
    return os.getenv("ACTIVE_RESPONSE_TOKEN", "").strip() or None


def _require_ar_token(request: Request) -> None:
    """Require the shared secret before allowing any disruptive action."""
    token = _active_response_token()
    if not token:
        raise HTTPException(
            status_code=503,
            detail=(
                "ACTIVE_RESPONSE_TOKEN is not set in env — refusing to enable "
                "active response without an auth secret. Set one in .env "
                "(any random string) and restart."
            ),
        )
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer ") or not secrets.compare_digest(auth[7:], token):
        raise HTTPException(status_code=401, detail="invalid bearer token")


def _wazuh_error(exc: httpx.HTTPStatusError) -> HTTPException:
    return HTTPException(
        status_code=502,
        detail=f"Wazuh API rejected: {exc.response.status_code} {exc.response.text[:200]}",
    )


@router.post("/block-ip")
async def block_ip_endpoint(request: Request) -> dict[str, Any]:
    """Block an IP at a specific agent's host firewall.

    Body:  {"agent_id": "002", "ip": "203.0.113.45"}
    Header: Authorization: Bearer <ACTIVE_RESPONSE_TOKEN>
    """
    _require_ar_token(request)
    body = await request.json()
    agent_id = str(body.get("agent_id", "")).strip()
    ip = str(body.get("ip", "")).strip()
    if not agent_id or not ip:
        raise HTTPException(400, detail="need both agent_id and ip in body")

    log.warning("manual block-ip request: agent=%s ip=%s", agent_id, ip)
    try:
        result = await wazuh.block_ip(agent_id, ip)
    except httpx.HTTPStatusError as exc:
        raise _wazuh_error(exc)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"block_ip failed: {exc}")
    return {"ok": True, "agent_id": agent_id, "ip": ip, "wazuh_response": result}


@router.post("/isolate-endpoint")
async def isolate_endpoint(request: Request) -> dict[str, Any]:
    """Run the configured endpoint-isolation Active Response command.

    Body:  {"agent_id": "003", "reason": "suspected compromise"}
    Header: Authorization: Bearer <ACTIVE_RESPONSE_TOKEN>
    """
    _require_ar_token(request)
    body = await request.json()
    agent_id = str(body.get("agent_id", "")).strip()
    reason = str(body.get("reason", "")).strip()
    if not agent_id:
        raise HTTPException(400, detail="need agent_id in body")

    log.warning("manual isolate-endpoint request: agent=%s", agent_id)
    try:
        result = await wazuh.isolate_agent(agent_id, reason=reason)
    except httpx.HTTPStatusError as exc:
        raise _wazuh_error(exc)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"isolate_endpoint failed: {exc}")
    if not result.get("ok"):
        raise HTTPException(status_code=501, detail=result.get("error", "isolate not enabled"))
    return result


@router.get("/agents")
async def list_agents_endpoint(request: Request) -> dict[str, Any]:
    """List active agents for manual Active Response targeting."""
    _require_ar_token(request)
    try:
        agents = await wazuh.list_agents()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"list_agents failed: {exc}")
    return {"agents": agents}
