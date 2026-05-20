"""Wazuh Manager REST API client — Active Response edition.

Talks to https://localhost:55000 (the manager's API) to:
  1. authenticate (POST /security/user/authenticate → JWT)
  2. trigger active response on a specific agent
       (PUT /active-response  with command + agents_list)

The classic SOC use is "block this IP at the host firewall". Wazuh ships
a built-in agent script `/var/ossec/active-response/bin/firewall-drop`
that handles iptables (Linux) / pfctl (macOS) / netsh (Windows)
automatically based on the agent's OS.

JWT cache: tokens last ~15 min by default; we cache and reuse until they
fail with 401, then re-auth. Saves a round-trip on every action.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Any, Optional

import httpx

log = logging.getLogger("wazuh-api")

WAZUH_API_URL  = os.getenv("WAZUH_API_URL", "https://localhost:55000")
WAZUH_API_USER = os.getenv("WAZUH_API_USER", "wazuh-wui")
WAZUH_API_PASS = os.getenv("WAZUH_API_PASS", "")
# SECURITY: no default password. Forgetting to set this should fail closed,
# not silently authenticate against a lab deployment with vendor defaults.
if not WAZUH_API_PASS:
    raise RuntimeError(
        "WAZUH_API_PASS must be set (env var or .env). "
        "Refusing to start with default/empty credentials — active response "
        "would otherwise work against any out-of-the-box Wazuh deployment."
    )

# TLS verification on Wazuh API calls. Default ON (production-safe).
# Set WAZUH_VERIFY_SSL=false ONLY for self-signed lab certs; doing so disables
# MITM protection — any LAN attacker can then forge active-response replies
# and intercept the API JWT. Logged at startup as a WARNING when disabled.
WAZUH_VERIFY_SSL = os.getenv("WAZUH_VERIFY_SSL", "true").strip().lower() != "false"
if not WAZUH_VERIFY_SSL:
    log.warning(
        "  ⚠  WAZUH_VERIFY_SSL is FALSE — TLS verification disabled on Wazuh "
        "API calls. Accept this for self-signed lab only; production MUST "
        "use a proper certificate and remove this override."
    )

# How long we trust a cached JWT before refreshing (seconds).
# Wazuh tokens are valid 900s; 720s gives a 3-minute safety margin.
JWT_TTL_S = float(os.getenv("WAZUH_JWT_TTL_S", "720"))
WAZUH_ISOLATE_COMMAND = os.getenv("WAZUH_ISOLATE_COMMAND", "").strip()

_jwt_lock: Optional[asyncio.Lock] = None
_jwt_cache: dict[str, Any] = {"token": None, "expires_at": 0.0}


def _get_lock() -> asyncio.Lock:
    global _jwt_lock
    if _jwt_lock is None:
        _jwt_lock = asyncio.Lock()
    return _jwt_lock


# ── Auth ────────────────────────────────────────────────────────────────
async def _fetch_jwt(client: httpx.AsyncClient) -> str:
    log.info("authenticating to Wazuh API at %s", WAZUH_API_URL)
    r = await client.post(
        f"{WAZUH_API_URL}/security/user/authenticate",
        auth=(WAZUH_API_USER, WAZUH_API_PASS),
        timeout=10,
    )
    r.raise_for_status()
    token = r.json()["data"]["token"]
    return token


async def _get_jwt(client: httpx.AsyncClient, force_refresh: bool = False) -> str:
    async with _get_lock():
        now = time.time()
        if (not force_refresh
            and _jwt_cache["token"]
            and _jwt_cache["expires_at"] > now):
            return _jwt_cache["token"]
        token = await _fetch_jwt(client)
        _jwt_cache["token"] = token
        _jwt_cache["expires_at"] = now + JWT_TTL_S
        return token


# ── Active response ─────────────────────────────────────────────────────
async def trigger_active_response(
    *,
    command: str,
    agents_list: list[str],
    arguments: Optional[list[str]] = None,
    alert: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Send an active-response command to one or more agents.

    Args:
      command:     indexed command name from manager's ossec.conf
                   (e.g. 'firewall-drop0' for the 0th <active-response> block).
      agents_list: agent IDs (strings, zero-padded — e.g. ['001', '002'])
      arguments:   passed to the script as `extra_args`. Some scripts use
                   this; firewall-drop ignores it and reads `alert.data.srcip`.
      alert:       passed to the script as `parameters.alert`. firewall-drop
                   needs `alert.data.srcip` to know what IP to block.

    Returns the API response. Raises on HTTP error.
    """
    # Wazuh v4.14+ schema accepts: command, arguments, alert.
    # `custom` (used in older versions) is rejected with 400.
    body: dict[str, Any] = {
        "command": command,
        "arguments": arguments or [],
    }
    if alert is not None:
        body["alert"] = alert
    params = {"agents_list": ",".join(agents_list)}

    async with httpx.AsyncClient(verify=WAZUH_VERIFY_SSL) as client:
        # Try with cached JWT first; on 401, refresh and retry once.
        for force_refresh in (False, True):
            token = await _get_jwt(client, force_refresh=force_refresh)
            r = await client.put(
                f"{WAZUH_API_URL}/active-response",
                params=params,
                headers={"Authorization": f"Bearer {token}"},
                json=body,
                timeout=15,
            )
            if r.status_code != 401:
                break
            log.info("JWT expired, refreshing and retrying…")

        r.raise_for_status()
        return r.json()


async def block_ip(agent_id: str, ip: str) -> dict[str, Any]:
    """Block an IP at the host firewall on a specific agent.

    Two non-obvious things about this call:

    1. The command name has a '0' suffix ('firewall-drop0', not
       'firewall-drop'). This is Wazuh 4.x's internal active-response
       position index — see agent's ar.conf for the actual registered
       names. NOT a deprecated OSSEC 3.x convention as I first thought.

    2. firewall-drop reads the target IP from `alert.data.srcip`, NOT
       from `arguments`. Passing only arguments yields:
           Cannot read 'srcip' from data
       in the agent's active-responses.log. We pass both for safety
       (some scripts use arguments; firewall-drop uses alert).
    """
    log.warning("ACTIVE RESPONSE: block_ip agent=%s ip=%s", agent_id, ip)
    return await trigger_active_response(
        command="firewall-drop0",
        agents_list=[agent_id],
        arguments=[ip],
        alert={"data": {"srcip": ip}},
    )


async def unblock_ip(agent_id: str, ip: str) -> dict[str, Any]:
    """Remove an IP from the Wazuh firewall block list.

    The Wazuh API can only dispatch the 'add' action of firewall-drop —
    the 'delete' action is reserved for internal timeout cleanup. So we
    bypass Wazuh's AR machinery and run pfctl directly on the Mac host
    via a tightly-scoped NOPASSWD sudoers entry (see
    `wazuh-stack/enable-unblock.sh`).

    Limitation: this only works for agents running on the SAME host as
    the bridge (i.e. agent 002 = the Mac host in our demo). For multi-
    host deployments, replace this with a custom Wazuh AR script
    deployed to each agent.
    """
    log.warning("ACTIVE RESPONSE: unblock_ip agent=%s ip=%s", agent_id, ip)

    if agent_id != "002":
        return {
            "ok": False,
            "error": (
                f"unblock currently only supported for the local Mac agent (002). "
                f"For agent {agent_id}, run on that host: "
                f"sudo pfctl -t wazuh_fwtable -T delete {ip}"
            ),
        }

    proc = await asyncio.create_subprocess_exec(
        "sudo", "-n", "/sbin/pfctl", "-t", "wazuh_fwtable", "-T", "delete", ip,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    out = (stdout.decode() + stderr.decode()).strip()
    if proc.returncode != 0:
        return {"ok": False, "error": f"pfctl unblock rc={proc.returncode}: {out}"}
    return {"ok": True, "output": out, "ip": ip, "agent_id": agent_id}


async def isolate_agent(agent_id: str, reason: str = "") -> dict[str, Any]:
    """Run a custom endpoint-isolation Active Response command.

    There is no universal built-in Wazuh command that safely isolates every
    OS in every network. Production deployments should install a vetted
    local active-response script on agents, then set WAZUH_ISOLATE_COMMAND
    to its Wazuh command name, for example `edgesec-isolate0`.
    """
    if not WAZUH_ISOLATE_COMMAND:
        return {
            "ok": False,
            "error": (
                "endpoint isolation is not enabled. Set WAZUH_ISOLATE_COMMAND "
                "after installing a tested isolation active-response script."
            ),
        }

    log.warning(
        "ACTIVE RESPONSE: isolate_agent agent=%s command=%s",
        agent_id,
        WAZUH_ISOLATE_COMMAND,
    )
    result = await trigger_active_response(
        command=WAZUH_ISOLATE_COMMAND,
        agents_list=[agent_id],
        arguments=[reason or "manual isolation from Slack"],
        alert={"data": {"reason": reason or "manual isolation from Slack"}},
    )
    failed = (result.get("data", {}) or {}).get("total_failed_items", 0)
    if failed:
        err = (
            result.get("data", {})
            .get("failed_items", [{}])[0]
            .get("error", {})
            .get("message", "unknown")
        )
        return {"ok": False, "error": f"Wazuh API: {err}", "wazuh_response": result}
    return {"ok": True, "agent_id": agent_id, "wazuh_response": result}


# ── Inventory helpers ───────────────────────────────────────────────────
async def list_agents() -> list[dict[str, Any]]:
    """Return active agents (id, name, ip, os, status). Useful for picking
    an agent to send active response to from a Slack/UI dropdown."""
    async with httpx.AsyncClient(verify=WAZUH_VERIFY_SSL) as client:
        token = await _get_jwt(client)
        r = await client.get(
            f"{WAZUH_API_URL}/agents",
            params={"limit": 100, "select": "id,name,ip,status,os.platform,os.version,lastKeepAlive,version"},
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        )
        r.raise_for_status()
        return r.json().get("data", {}).get("affected_items", [])
