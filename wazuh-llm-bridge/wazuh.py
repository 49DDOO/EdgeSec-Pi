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
import re
import time
from typing import Any, Optional
from urllib.parse import quote

import httpx

import active_response_safety
import sca_explainer
import wazuh_settings

log = logging.getLogger("wazuh-api")

WAZUH_API_URL = str(wazuh_settings.get("WAZUH_API_URL", "https://localhost:55000"))
WAZUH_API_USER = str(wazuh_settings.get("WAZUH_API_USER", "wazuh-wui"))
WAZUH_API_PASS = str(wazuh_settings.get("WAZUH_API_PASS", ""))
WAZUH_VERIFY_SSL = bool(wazuh_settings.get("WAZUH_VERIFY_SSL", True))

# How long we trust a cached JWT before refreshing (seconds).
# Wazuh tokens are valid 900s; 720s gives a 3-minute safety margin.
JWT_TTL_S = float(os.getenv("WAZUH_JWT_TTL_S", "720"))
WAZUH_ISOLATE_COMMAND = os.getenv("WAZUH_ISOLATE_COMMAND", "").strip()
WAZUH_RELEASE_ISOLATE_COMMAND = os.getenv("WAZUH_RELEASE_ISOLATE_COMMAND", "").strip()
WAZUH_UNBLOCK_COMMAND = os.getenv("WAZUH_UNBLOCK_COMMAND", "").strip()

_jwt_lock: Optional[asyncio.Lock] = None
_jwt_cache: dict[str, Any] = {"token": None, "expires_at": 0.0, "cache_key": ""}


def _api_config() -> dict[str, Any]:
    cfg = wazuh_settings.api_config()
    cfg["url"] = str(cfg["url"] or "https://localhost:55000").rstrip("/")
    cfg["user"] = str(cfg["user"] or "wazuh-wui")
    cfg["password"] = str(cfg["password"] or "")
    cfg["verify_ssl"] = bool(cfg["verify_ssl"])
    return cfg


def _cache_key(cfg: dict[str, Any]) -> str:
    return f"{cfg['url']}|{cfg['user']}"


def _require_password(cfg: dict[str, Any]) -> None:
    if not cfg["password"]:
        raise RuntimeError("WAZUH_API_PASS 尚未設定，無法連線 Wazuh Manager API。")


def _get_lock() -> asyncio.Lock:
    global _jwt_lock
    if _jwt_lock is None:
        _jwt_lock = asyncio.Lock()
    return _jwt_lock


# ── Auth ────────────────────────────────────────────────────────────────
async def _fetch_jwt(client: httpx.AsyncClient) -> str:
    cfg = _api_config()
    _require_password(cfg)
    log.info("authenticating to Wazuh API at %s", cfg["url"])
    r = await client.post(
        f"{cfg['url']}/security/user/authenticate",
        auth=(cfg["user"], cfg["password"]),
        timeout=10,
    )
    r.raise_for_status()
    token = r.json()["data"]["token"]
    return token


async def _get_jwt(client: httpx.AsyncClient, force_refresh: bool = False) -> str:
    async with _get_lock():
        cfg = _api_config()
        key = _cache_key(cfg)
        now = time.time()
        if (not force_refresh
            and _jwt_cache["token"]
            and _jwt_cache["expires_at"] > now
            and _jwt_cache.get("cache_key") == key):
            return _jwt_cache["token"]
        token = await _fetch_jwt(client)
        _jwt_cache["token"] = token
        _jwt_cache["expires_at"] = now + JWT_TTL_S
        _jwt_cache["cache_key"] = key
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

    cfg = _api_config()
    async with httpx.AsyncClient(verify=cfg["verify_ssl"]) as client:
        # Try with cached JWT first; on 401, refresh and retry once.
        for force_refresh in (False, True):
            token = await _get_jwt(client, force_refresh=force_refresh)
            r = await client.put(
                f"{cfg['url']}/active-response",
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
    guard = active_response_safety.validate_block_request(agent_id, ip)
    agent_id = guard["agent_id"]
    ip = guard["ip"]

    log.warning(
        "ACTIVE RESPONSE: block_ip agent=%s ip=%s ttl_s=%s",
        agent_id,
        ip,
        guard["ttl_s"],
    )
    result = await trigger_active_response(
        command="firewall-drop0",
        agents_list=[agent_id],
        arguments=[ip],
        alert={"data": {"srcip": ip}},
    )
    failed = (result.get("data", {}) or {}).get("total_failed_items", 0)
    if not failed:
        result["_edgesec"] = {
            "guardrails": {
                "ttl_s": guard["ttl_s"],
                "expires_at": guard["expires_at"],
                "ip": ip,
                "agent_id": agent_id,
            }
        }
        try:
            active_response_safety.record_block(
                agent_id,
                ip,
                ttl_s=guard["ttl_s"],
                expires_at=guard["expires_at"],
                details={"wazuh_response": result},
            )
        except Exception as exc:
            log.exception("failed to record active response block state")
            result["_edgesec"]["guardrails"]["tracking_error"] = str(exc)
    return result


async def unblock_ip(
    agent_id: str,
    ip: str,
    *,
    require_tracked: bool = True,
    record_state: bool = True,
) -> dict[str, Any]:
    """Remove an IP from the Wazuh firewall block list.

    The Wazuh API can only dispatch the 'add' action of firewall-drop —
    the 'delete' action is reserved for internal timeout cleanup. For
    cross-platform deployments, install a custom agent-side unblock script
    and set WAZUH_UNBLOCK_COMMAND to its Wazuh command name. Without that,
    this falls back to pfctl on the local Mac demo host via a tightly-scoped
    NOPASSWD sudoers entry (see `wazuh-stack/enable-unblock.sh`).

    The TTL sweeper calls this with require_tracked=False because expired
    block rows are no longer "active" for dashboard purposes but still need
    firewall cleanup.
    """
    agent_id = str(agent_id or "").strip()
    ip = active_response_safety.normalize_ip(ip)

    if require_tracked and not active_response_safety.find_open_block(agent_id, ip):
        return {
            "ok": False,
            "error": (
                "找不到 EdgeSec-Pi 尚未解除的封鎖紀錄，已拒絕自動解除封鎖。"
                "若這是人工封鎖，請 IT 在該主機上手動解除。"
            ),
        }

    log.warning("ACTIVE RESPONSE: unblock_ip agent=%s ip=%s", agent_id, ip)

    if WAZUH_UNBLOCK_COMMAND:
        result = await trigger_active_response(
            command=WAZUH_UNBLOCK_COMMAND,
            agents_list=[agent_id],
            arguments=[ip],
            alert={"data": {"srcip": ip, "action": "delete"}},
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
        if record_state:
            try:
                active_response_safety.record_unblock(
                    agent_id,
                    ip,
                    details={"method": "custom_wazuh_ar", "wazuh_response": result},
                )
            except Exception as exc:
                log.exception("failed to record active response unblock state")
                return {
                    "ok": True,
                    "ip": ip,
                    "agent_id": agent_id,
                    "method": "custom_wazuh_ar",
                    "wazuh_response": result,
                    "tracking_error": str(exc),
                }
        return {
            "ok": True,
            "ip": ip,
            "agent_id": agent_id,
            "method": "custom_wazuh_ar",
            "wazuh_response": result,
        }

    if agent_id != "002":
        return {
            "ok": False,
            "manual_required": True,
            "error": (
                f"unblock currently needs WAZUH_UNBLOCK_COMMAND for non-local agent {agent_id}. "
                "Install a tested agent-side unblock active-response script, or ask IT to remove "
                f"{ip} from that endpoint firewall manually."
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
    if record_state:
        try:
            active_response_safety.record_unblock(
                agent_id,
                ip,
                details={"method": "local_pfctl", "output": out},
            )
        except Exception as exc:
            log.exception("failed to record active response unblock state")
            return {
                "ok": True,
                "output": out,
                "ip": ip,
                "agent_id": agent_id,
                "method": "local_pfctl",
                "tracking_error": str(exc),
            }
    return {"ok": True, "output": out, "ip": ip, "agent_id": agent_id, "method": "local_pfctl"}


async def isolate_agent(
    agent_id: str,
    reason: str = "",
    *,
    agent_name: str = "",
    platform: str = "",
    actor: str = "",
    record_state: bool = True,
) -> dict[str, Any]:
    """Run a custom endpoint-isolation Active Response command.

    There is no universal built-in Wazuh command that safely isolates every
    OS in every network. Production deployments should install a vetted
    local active-response script on agents, then set both
    WAZUH_ISOLATE_COMMAND and WAZUH_RELEASE_ISOLATE_COMMAND.
    """
    guard = active_response_safety.validate_isolate_request(
        agent_id,
        agent_name=agent_name,
        platform=platform,
    )
    agent_id = guard["agent_id"]

    log.warning(
        "ACTIVE RESPONSE: isolate_agent agent=%s command=%s ttl_s=%s",
        agent_id,
        WAZUH_ISOLATE_COMMAND,
        guard["ttl_s"],
    )
    result = await trigger_active_response(
        command=WAZUH_ISOLATE_COMMAND,
        agents_list=[agent_id],
        arguments=[reason or "manual isolation", str(guard["ttl_s"])],
        alert={
            "data": {
                "action": "isolate",
                "reason": reason or "manual isolation",
                "ttl_s": guard["ttl_s"],
            }
        },
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
    result["_edgesec"] = {
        "guardrails": {
            "ttl_s": guard["ttl_s"],
            "expires_at": guard["expires_at"],
            "agent_id": agent_id,
            "agent_name": guard["agent_name"],
            "agent_platform": guard["agent_platform"],
        }
    }
    if record_state:
        try:
            active_response_safety.record_isolation(
                agent_id,
                agent_name=guard["agent_name"],
                ttl_s=guard["ttl_s"],
                expires_at=guard["expires_at"],
                actor=actor,
                reason=reason,
                details={
                    "agent_platform": guard["agent_platform"],
                    "wazuh_response": result,
                },
            )
        except Exception as exc:
            log.exception("failed to record endpoint isolation state")
            result["_edgesec"]["guardrails"]["tracking_error"] = str(exc)
    return {
        "ok": True,
        "agent_id": agent_id,
        "agent_platform": guard["agent_platform"],
        "ttl_s": guard["ttl_s"],
        "expires_at": guard["expires_at"],
        "wazuh_response": result,
    }


async def release_isolation(
    agent_id: str,
    *,
    agent_name: str = "",
    reason: str = "",
    require_tracked: bool = True,
    record_state: bool = True,
    actor: str = "",
) -> dict[str, Any]:
    """Release a tracked endpoint isolation through a custom AR command."""
    agent_id = active_response_safety.validate_agent_id(agent_id)
    if not WAZUH_RELEASE_ISOLATE_COMMAND:
        return {
            "ok": False,
            "manual_required": True,
            "error": (
                "release isolation currently needs WAZUH_RELEASE_ISOLATE_COMMAND. "
                "Ask IT to restore the endpoint manually or deploy a tested release script."
            ),
        }

    if require_tracked and not active_response_safety.find_open_isolation(agent_id):
        return {
            "ok": False,
            "error": (
                "找不到 EdgeSec-Pi 尚未解除的隔離紀錄，已拒絕自動解除隔離。"
                "若這是人工隔離，請 IT 在該主機上手動恢復。"
            ),
        }

    log.warning(
        "ACTIVE RESPONSE: release_isolation agent=%s command=%s",
        agent_id,
        WAZUH_RELEASE_ISOLATE_COMMAND,
    )
    result = await trigger_active_response(
        command=WAZUH_RELEASE_ISOLATE_COMMAND,
        agents_list=[agent_id],
        arguments=[reason or "manual isolation release"],
        alert={
            "data": {
                "action": "release_isolation",
                "reason": reason or "manual isolation release",
            }
        },
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
    if record_state:
        try:
            active_response_safety.record_release_isolation(
                agent_id,
                actor=actor,
                reason=reason,
                details={
                    "agent_name": agent_name,
                    "method": "custom_wazuh_ar",
                    "wazuh_response": result,
                },
            )
        except Exception as exc:
            log.exception("failed to record endpoint isolation release state")
            return {
                "ok": True,
                "agent_id": agent_id,
                "method": "custom_wazuh_ar",
                "wazuh_response": result,
                "tracking_error": str(exc),
            }
    return {
        "ok": True,
        "agent_id": agent_id,
        "method": "custom_wazuh_ar",
        "wazuh_response": result,
    }


# ── Inventory helpers ───────────────────────────────────────────────────
async def list_agents() -> list[dict[str, Any]]:
    """Return active agents (id, name, ip, os, status). Useful for picking
    an agent to send active response to from a Slack/UI dropdown."""
    cfg = _api_config()
    async with httpx.AsyncClient(verify=cfg["verify_ssl"]) as client:
        token = await _get_jwt(client)
        r = await client.get(
            f"{cfg['url']}/agents",
            params={"limit": 100, "select": "id,name,ip,status,os.platform,os.version,lastKeepAlive,version"},
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        )
        r.raise_for_status()
        return r.json().get("data", {}).get("affected_items", [])


async def _get_affected_items(path: str, params: dict[str, Any] | None = None) -> list[Any]:
    cfg = _api_config()
    async with httpx.AsyncClient(verify=cfg["verify_ssl"]) as client:
        token = await _get_jwt(client)
        r = await client.get(
            f"{cfg['url']}{path}",
            params=params or {},
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        )
        r.raise_for_status()
        data = r.json().get("data", {})
        return data.get("affected_items", [])


async def list_agent_groups() -> list[Any]:
    """Return Wazuh Manager agent groups.

    Used by setup readiness checks to confirm that optional EdgeSec-Pi
    centralized agent-group hardening has actually been deployed.
    """
    return await _get_affected_items("/groups", {"limit": 100})


async def list_agents_with_groups() -> list[dict[str, Any]]:
    """Return agents including their Wazuh group membership when available."""
    return await _get_affected_items(
        "/agents",
        {"limit": 500, "select": "id,name,status,os.platform,os.name,group"},
    )


async def restart_agent(agent_id: str) -> dict[str, Any]:
    """Ask Wazuh to restart one agent.

    In the dashboard this is presented as "重新檢查這台電腦" because the useful
    management outcome is a fresh SCA scan. Restarting the agent does not replay
    old application logs; it makes the agent reload configuration and, when SCA
    scan_on_start is enabled, run the security configuration assessment again.
    """
    agent_id = str(agent_id or "").strip()
    if not agent_id:
        raise ValueError("agent_id is required")

    cfg = _api_config()
    async with httpx.AsyncClient(verify=cfg["verify_ssl"]) as client:
        for force_refresh in (False, True):
            token = await _get_jwt(client, force_refresh=force_refresh)
            r = await client.put(
                f"{cfg['url']}/agents/{agent_id}/restart",
                headers={"Authorization": f"Bearer {token}"},
                timeout=15,
            )
            if r.status_code != 401:
                break
            log.info("JWT expired, refreshing and retrying agent restart…")

        r.raise_for_status()
        return r.json()


async def get_rule_details(rule_id: str) -> dict[str, Any]:
    """Fetch the currently loaded Wazuh rule metadata and XML rule block.

    The bridge intentionally queries the Wazuh Manager API instead of keeping a
    local ruleset cache. That keeps LLM/MCP explanations aligned with the
    manager's active default rules, custom rules, and future ruleset updates.
    """
    rule_id = str(rule_id or "").strip()
    if not rule_id:
        raise ValueError("rule_id is required")

    cfg = _api_config()
    async with httpx.AsyncClient(verify=cfg["verify_ssl"]) as client:
        data = await _wazuh_get_json(
            client,
            "/rules",
            params={
                "rule_ids": rule_id,
                "limit": 1,
            },
            timeout=10,
        )
        item = _first_affected_item(data)
        if not item:
            return {
                "ok": False,
                "rule_id": rule_id,
                "error": "rule not found in Wazuh Manager API",
            }

        filename = str(item.get("filename") or "").strip()
        relative_dirname = str(item.get("relative_dirname") or "").strip()
        raw_file = ""
        rule_xml = ""
        if filename:
            try:
                raw_file = await _wazuh_get_rules_file(
                    client,
                    filename=filename,
                    relative_dirname=relative_dirname,
                )
                rule_xml = extract_rule_xml(raw_file, rule_id)
            except Exception as exc:
                log.warning(
                    "failed to fetch Wazuh rule XML rule_id=%s file=%s dir=%s: %s",
                    rule_id,
                    filename,
                    relative_dirname,
                    exc,
                )

        return {
            "ok": True,
            "source": "wazuh_manager_api",
            "rule_id": rule_id,
            "metadata": item,
            "filename": filename,
            "relative_dirname": relative_dirname,
            "rule_xml": rule_xml,
            "rule_file_available": bool(raw_file),
        }


async def _wazuh_get_json(
    client: httpx.AsyncClient,
    path: str,
    *,
    params: dict[str, Any] | None = None,
    timeout: float = 10,
) -> dict[str, Any]:
    for force_refresh in (False, True):
        cfg = _api_config()
        token = await _get_jwt(client, force_refresh=force_refresh)
        r = await client.get(
            f"{cfg['url']}{path}",
            params=params or {},
            headers={"Authorization": f"Bearer {token}"},
            timeout=timeout,
        )
        if r.status_code != 401:
            break
        log.info("JWT expired, refreshing and retrying Wazuh API GET %s…", path)
    r.raise_for_status()
    return r.json()


async def _wazuh_get_rules_file(
    client: httpx.AsyncClient,
    *,
    filename: str,
    relative_dirname: str = "",
) -> str:
    path = f"/rules/files/{quote(filename, safe='')}"
    params: dict[str, Any] = {"raw": "true"}
    if relative_dirname:
        params["relative_dirname"] = relative_dirname
    for force_refresh in (False, True):
        cfg = _api_config()
        token = await _get_jwt(client, force_refresh=force_refresh)
        r = await client.get(
            f"{cfg['url']}{path}",
            params=params,
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        )
        if r.status_code != 401:
            break
        log.info("JWT expired, refreshing and retrying Wazuh rule file GET…")
    r.raise_for_status()
    content_type = r.headers.get("content-type", "")
    if "application/json" not in content_type:
        return r.text
    payload = r.json()
    item = _first_affected_item(payload)
    if isinstance(item, str):
        return item
    if isinstance(item, dict):
        return str(item.get("content") or item.get("file") or item.get("raw") or "")
    return ""


def _first_affected_item(payload: dict[str, Any]) -> Any:
    data = payload.get("data") if isinstance(payload, dict) else None
    items = data.get("affected_items") if isinstance(data, dict) else None
    if isinstance(items, list) and items:
        return items[0]
    return None


def extract_rule_xml(xml_text: str, rule_id: str) -> str:
    """Return the exact `<rule id="...">...</rule>` block from a rule file."""
    rule_id = re.escape(str(rule_id))
    pattern = re.compile(
        rf"<rule\b(?=[^>]*\bid\s*=\s*['\"]{rule_id}['\"])[^>]*>.*?</rule>",
        re.IGNORECASE | re.DOTALL,
    )
    match = pattern.search(str(xml_text or ""))
    if not match:
        return ""
    return match.group(0).strip()


def _as_int(value: Any) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


async def list_sca_policies(agent_id: str) -> list[dict[str, Any]]:
    """Return Security Configuration Assessment policy summaries for an agent.

    Wazuh may return more than one SCA policy per endpoint. The dashboard keeps
    them separate from agent connectivity because an online agent can still have
    weak security configuration.
    """
    cfg = _api_config()
    async with httpx.AsyncClient(verify=cfg["verify_ssl"]) as client:
        token = await _get_jwt(client)
        r = await client.get(
            f"{cfg['url']}/sca/{agent_id}",
            params={"limit": 100},
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        )
        r.raise_for_status()
        return r.json().get("data", {}).get("affected_items", [])


async def list_sca_failed_checks(
    agent_id: str,
    policy_id: str,
    limit: int = 5,
) -> list[dict[str, Any]]:
    """Return top failed SCA checks for one policy.

    This powers the management dashboard's "why is this score low?" drawer.
    We intentionally fetch only a few failed checks so the screen gives a next
    action instead of dumping a CIS benchmark.
    """
    if not policy_id:
        return []
    cfg = _api_config()
    async with httpx.AsyncClient(verify=cfg["verify_ssl"]) as client:
        token = await _get_jwt(client)
        r = await client.get(
            f"{cfg['url']}/sca/{agent_id}/checks/{policy_id}",
            params={"limit": max(1, min(int(limit), 20)), "result": "failed"},
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        )
        r.raise_for_status()
        items = r.json().get("data", {}).get("affected_items", [])
        checks = []
        for item in items:
            checks.append({
                "id": str(item.get("id") or ""),
                "title": str(item.get("title") or ""),
                "rationale": str(item.get("rationale") or ""),
                "description": str(item.get("description") or ""),
                "remediation": str(item.get("remediation") or ""),
            })
        return checks


async def get_agent_sca_summary(agent_id: str) -> dict[str, Any]:
    """Return the conservative SCA score for one agent.

    If multiple SCA policies exist, the lowest score is shown. For a management
    dashboard this is easier to trust than an average that can hide a weak
    policy behind a stronger one.
    """
    policies = await list_sca_policies(agent_id)
    scored: list[dict[str, Any]] = []
    for policy in policies:
        score_value = policy.get("score")
        if score_value is None:
            continue
        passed = _as_int(policy.get("pass") or policy.get("passed"))
        failed = _as_int(policy.get("fail") or policy.get("failed"))
        invalid = _as_int(policy.get("invalid"))
        total = _as_int(policy.get("total_checks") or policy.get("total"))
        if not total:
            total = passed + failed + invalid
        scored.append({
            "score": _as_int(score_value),
            "policy": str(policy.get("name") or policy.get("policy_id") or ""),
            "policy_id": str(policy.get("policy_id") or ""),
            "passed": passed,
            "failed": failed,
            "invalid": invalid,
            "total": total,
            "last_scan": str(policy.get("end_scan") or policy.get("last_scan") or ""),
        })
    if not scored:
        return {
            "score": None,
            "policy": "",
            "policy_id": "",
            "passed": 0,
            "failed": 0,
            "invalid": 0,
            "total": 0,
            "last_scan": "",
            "available": False,
        }
    summary = min(scored, key=lambda item: item["score"])
    try:
        failed_checks = await list_sca_failed_checks(
            agent_id,
            summary.get("policy_id") or "",
            limit=5,
        )
        summary["failed_checks"] = failed_checks
        summary["plain_failed_checks"] = await sca_explainer.explain_failed_checks(failed_checks, limit=3)
    except Exception as exc:
        log.warning("failed to fetch SCA checks for agent=%s policy=%s: %s", agent_id, summary.get("policy_id"), exc)
        summary["failed_checks"] = []
        summary["plain_failed_checks"] = []
    summary["available"] = True
    return summary
