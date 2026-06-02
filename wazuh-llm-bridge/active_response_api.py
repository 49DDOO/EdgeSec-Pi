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

import active_response_safety
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


def _denied_error(exc: active_response_safety.ActiveResponseDenied) -> HTTPException:
    return HTTPException(status_code=exc.status_code, detail=exc.message)


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
    try:
        guard = active_response_safety.validate_block_request(agent_id, ip)
    except active_response_safety.ActiveResponseDenied as exc:
        raise _denied_error(exc)
    agent_id = guard["agent_id"]
    ip = guard["ip"]

    log.warning("manual block-ip request: agent=%s ip=%s", agent_id, ip)
    try:
        result = await wazuh.block_ip(agent_id, ip)
    except httpx.HTTPStatusError as exc:
        raise _wazuh_error(exc)
    except active_response_safety.ActiveResponseDenied as exc:
        raise _denied_error(exc)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"block_ip failed: {exc}")
    failed = (result.get("data", {}) or {}).get("total_failed_items", 0)
    if failed:
        err = (
            result.get("data", {})
            .get("failed_items", [{}])[0]
            .get("error", {})
            .get("message", "unknown")
        )
        raise HTTPException(status_code=502, detail=f"Wazuh API: {err}")
    guardrails = (result.get("_edgesec") or {}).get("guardrails") or guard
    return {
        "ok": True,
        "agent_id": agent_id,
        "ip": ip,
        "ttl_s": guardrails.get("ttl_s"),
        "expires_at": guardrails.get("expires_at"),
        "wazuh_response": result,
    }


@router.post("/unblock-ip")
async def unblock_ip_endpoint(request: Request) -> dict[str, Any]:
    """Remove a tracked IP block from the local host firewall.

    Body:  {"agent_id": "002", "ip": "203.0.113.45"}
    Header: Authorization: Bearer <ACTIVE_RESPONSE_TOKEN>
    """
    _require_ar_token(request)
    body = await request.json()
    agent_id = str(body.get("agent_id", "")).strip()
    ip = str(body.get("ip", "")).strip()
    if not agent_id or not ip:
        raise HTTPException(400, detail="need both agent_id and ip in body")

    log.warning("manual unblock-ip request: agent=%s ip=%s", agent_id, ip)
    try:
        result = await wazuh.unblock_ip(agent_id, ip)
    except httpx.HTTPStatusError as exc:
        raise _wazuh_error(exc)
    except active_response_safety.ActiveResponseDenied as exc:
        raise _denied_error(exc)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"unblock_ip failed: {exc}")
    if not result.get("ok"):
        raise HTTPException(status_code=409, detail=result.get("error", "unblock not completed"))
    return result


@router.get("/blocks")
async def list_active_blocks_endpoint(request: Request) -> dict[str, Any]:
    """List tracked IP blocks.

    By default this returns only currently active, unexpired blocks. Pass
    ?include_inactive=1 to inspect rows that reached TTL expiry but still need
    manual cleanup or failed automatic unblock.
    """
    _require_ar_token(request)
    include_inactive = request.query_params.get("include_inactive", "").lower() in {
        "1",
        "true",
        "yes",
    }
    return {"blocks": active_response_safety.list_blocks(include_inactive=include_inactive)}


@router.post("/isolate-endpoint")
async def isolate_endpoint(request: Request) -> dict[str, Any]:
    """Run the configured endpoint-isolation Active Response command.

    Body:  {"agent_id": "003", "reason": "suspected compromise"}
    Header: Authorization: Bearer <ACTIVE_RESPONSE_TOKEN>
    """
    _require_ar_token(request)
    body = await request.json()
    agent_id = str(body.get("agent_id", "")).strip()
    agent_name = str(body.get("agent_name", "")).strip()
    platform = str(body.get("agent_platform") or body.get("platform") or "").strip()
    reason = str(body.get("reason", "")).strip()
    if not agent_id:
        raise HTTPException(400, detail="need agent_id in body")

    log.warning("manual isolate-endpoint request: agent=%s", agent_id)
    try:
        result = await wazuh.isolate_agent(
            agent_id,
            agent_name=agent_name,
            platform=platform,
            reason=reason,
        )
    except httpx.HTTPStatusError as exc:
        raise _wazuh_error(exc)
    except active_response_safety.ActiveResponseDenied as exc:
        raise _denied_error(exc)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"isolate_endpoint failed: {exc}")
    if not result.get("ok"):
        raise HTTPException(status_code=501, detail=result.get("error", "isolate not enabled"))
    return result


@router.get("/isolation-capability")
async def isolation_capability_endpoint(request: Request) -> dict[str, Any]:
    """Report whether endpoint isolation is safe to expose for a target OS."""
    _require_ar_token(request)
    return active_response_safety.isolation_capability(
        str(request.query_params.get("platform") or "").strip(),
        agent_id=str(request.query_params.get("agent_id") or "").strip(),
        agent_name=str(request.query_params.get("agent_name") or "").strip(),
    )


@router.post("/release-isolation")
async def release_isolation_endpoint(request: Request) -> dict[str, Any]:
    """Release a tracked endpoint isolation.

    Body:  {"agent_id": "003", "reason": "incident handled"}
    Header: Authorization: Bearer <ACTIVE_RESPONSE_TOKEN>
    """
    _require_ar_token(request)
    body = await request.json()
    agent_id = str(body.get("agent_id", "")).strip()
    agent_name = str(body.get("agent_name", "")).strip()
    reason = str(body.get("reason", "")).strip()
    if not agent_id:
        raise HTTPException(400, detail="need agent_id in body")

    log.warning("manual release-isolation request: agent=%s", agent_id)
    try:
        result = await wazuh.release_isolation(
            agent_id,
            agent_name=agent_name,
            reason=reason,
        )
    except httpx.HTTPStatusError as exc:
        raise _wazuh_error(exc)
    except active_response_safety.ActiveResponseDenied as exc:
        raise _denied_error(exc)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"release_isolation failed: {exc}")
    if not result.get("ok"):
        raise HTTPException(status_code=409, detail=result.get("error", "release not completed"))
    return result


@router.get("/isolations")
async def list_active_isolations_endpoint(request: Request) -> dict[str, Any]:
    """List tracked endpoint isolations."""
    _require_ar_token(request)
    include_inactive = request.query_params.get("include_inactive", "").lower() in {
        "1",
        "true",
        "yes",
    }
    return {"isolations": active_response_safety.list_isolations(include_inactive=include_inactive)}


@router.get("/agents")
async def list_agents_endpoint(request: Request) -> dict[str, Any]:
    """List active agents for manual Active Response targeting."""
    _require_ar_token(request)
    try:
        agents = await wazuh.list_agents()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"list_agents failed: {exc}")
    return {"agents": agents}
