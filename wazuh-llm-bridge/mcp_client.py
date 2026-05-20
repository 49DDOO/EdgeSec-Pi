"""MCP client for gensecaihq/Wazuh-MCP-Server.

Handles the API-key → /auth/token → JWT exchange the server requires
(plain API key as Bearer is rejected — see the server's auth.py:284
 verify_bearer_token: only `wst_*` session tokens or short-lived JWTs
 from /auth/token are accepted).

Public API (used by app.py):
  is_enabled()                                 → bool
  list_tools()                                 → list of tool descriptors
  call_tool(name, args)                        → str (the tool's text result) or None
  get_tool_names()                             → cached list of available tool names
  enrich_alert(alert)                          → str (MCP context block for LLM prompt)
  format_correlation_for_prompt(rows, ...)     → str (correlation context block)

Falls back silently to disabled state when MCP_SERVER_URL or MCP_API_KEY
aren't set — the rest of the bridge keeps running.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Any, Optional

import httpx

log = logging.getLogger("mcp-client")

MCP_SERVER_URL = os.getenv("MCP_SERVER_URL", "").rstrip("/").strip() or None
MCP_API_KEY    = os.getenv("MCP_API_KEY", "").strip() or None

# Wazuh-MCP-Server v4.2.1 issues 24h JWTs by default. Refresh well before
# expiry so concurrent calls don't race the token boundary.
JWT_TTL_S = float(os.getenv("MCP_JWT_TTL_S", "82800"))   # 23h cache lifetime

# HTTP timeouts. We split connect vs total so a failing/paused MCP server
# is detected within a few seconds instead of stalling each tool call for
# the full read timeout. When MCP works, calls finish in <1s; the 10s total
# is generous. When MCP is paused/down, connect_timeout=3s kicks in first.
MCP_CONNECT_TIMEOUT_S = float(os.getenv("MCP_CONNECT_TIMEOUT_S", "3"))
HTTP_TIMEOUT_S        = float(os.getenv("MCP_HTTP_TIMEOUT_S",   "10"))
_TIMEOUT = httpx.Timeout(HTTP_TIMEOUT_S, connect=MCP_CONNECT_TIMEOUT_S)

_jwt_lock: Optional[asyncio.Lock] = None
_jwt_cache: dict[str, Any] = {"token": None, "expires_at": 0.0}
_tool_names_cache: Optional[list[str]] = None


def _get_lock() -> asyncio.Lock:
    global _jwt_lock
    if _jwt_lock is None:
        _jwt_lock = asyncio.Lock()
    return _jwt_lock


def is_enabled() -> bool:
    """True iff the MCP integration is configured. The bridge code checks
    this before every MCP-dependent code path so unset env vars are a no-op."""
    return bool(MCP_SERVER_URL and MCP_API_KEY)


# ── JWT lifecycle ──────────────────────────────────────────────────────
async def _fetch_jwt(client: httpx.AsyncClient) -> str:
    """POST our wazuh_xxx API key to /auth/token, return the JWT."""
    log.info("MCP: exchanging API key for JWT at %s/auth/token", MCP_SERVER_URL)
    r = await client.post(
        f"{MCP_SERVER_URL}/auth/token",
        json={"api_key": MCP_API_KEY},
        timeout=_TIMEOUT,
    )
    r.raise_for_status()
    return r.json()["access_token"]


async def _get_jwt(client: httpx.AsyncClient, force: bool = False) -> str:
    """Return a valid JWT, fetching+caching as needed."""
    async with _get_lock():
        now = time.time()
        if (not force
                and _jwt_cache["token"]
                and _jwt_cache["expires_at"] > now):
            return _jwt_cache["token"]
        token = await _fetch_jwt(client)
        _jwt_cache["token"] = token
        _jwt_cache["expires_at"] = now + JWT_TTL_S
        return token


# ── JSON-RPC over MCP ──────────────────────────────────────────────────
async def _rpc(method: str,
               params: Optional[dict[str, Any]] = None,
               request_id: int = 1) -> dict[str, Any]:
    """Send a JSON-RPC request to /mcp. Refreshes JWT once on 401."""
    if not is_enabled():
        raise RuntimeError(
            "MCP client not enabled — set MCP_SERVER_URL and MCP_API_KEY in .env"
        )
    body: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        body["params"] = params

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        # Try with cached JWT first; on 401, refresh once and retry.
        for force_refresh in (False, True):
            jwt = await _get_jwt(client, force=force_refresh)
            r = await client.post(
                f"{MCP_SERVER_URL}/mcp",
                headers={
                    "Authorization": f"Bearer {jwt}",
                    "Content-Type": "application/json",
                },
                json=body,
            )
            if r.status_code == 401 and not force_refresh:
                log.info("MCP: JWT rejected (401), refreshing and retrying")
                continue
            r.raise_for_status()
            return r.json()
    # unreachable
    raise RuntimeError("MCP RPC failed after JWT refresh")


# ── Public API ─────────────────────────────────────────────────────────
async def list_tools() -> list[dict[str, Any]]:
    """Enumerate the tools the MCP server exposes."""
    res = await _rpc("tools/list")
    return (res.get("result") or {}).get("tools", [])


async def get_tool_names() -> list[str]:
    """Cached list of tool names. First call talks to the server; subsequent
    calls are free. Returns empty list (with warning) on any error so the
    bridge degrades gracefully when the MCP server is unavailable."""
    global _tool_names_cache
    if _tool_names_cache is not None:
        return _tool_names_cache
    try:
        tools = await list_tools()
        _tool_names_cache = [t["name"] for t in tools]
        log.info("MCP: %d tools loaded from %s",
                 len(_tool_names_cache), MCP_SERVER_URL)
        return _tool_names_cache
    except Exception as e:
        log.warning("MCP get_tool_names failed: %s", e)
        return []


async def call_tool(name: str,
                    arguments: Optional[dict[str, Any]] = None) -> Optional[str]:
    """Call one MCP tool. Returns concatenated text of its output, or None
    on error (logged). Bridges typical Wazuh-MCP response shape:

        {"result": {"content": [{"type": "text", "text": "..."}], "isError": false}}
    """
    try:
        res = await _rpc("tools/call",
                         {"name": name, "arguments": arguments or {}})
    except Exception as e:
        # Use repr(e) so empty-message exceptions (e.g. ConnectTimeout) still
        # surface their type — bare str(e) often gives "" for those.
        log.warning("MCP call_tool %s failed: %r", name, e)
        return None

    result = res.get("result") or {}
    if result.get("isError"):
        log.warning("MCP tool %s reported error: %s",
                    name, str(result)[:200])
        return None

    content = result.get("content") or []
    return "\n".join(
        item.get("text", "")
        for item in content
        if item.get("type") == "text"
    )


# ── Alert enrichment (business logic) ─────────────────────────────────────
async def enrich_alert(alert: dict[str, Any]) -> str:
    """Phase 3a — MCP-driven alert enrichment.

    If the alert has a source IP, query the Wazuh MCP server for related
    events from that IP in the past 7 days. The result is injected into
    the LLM prompt as additional context — turning a single-alert
    notification into a cross-time-window investigation.

    Returns an empty string (silently) when:
      - MCP server isn't configured (no MCP_SERVER_URL/MCP_API_KEY)
      - the alert has no source IP to pivot on
      - the MCP call fails (logged warning, doesn't break the pipeline)
    """
    if not is_enabled():
        return ""

    data = alert.get("data") or {}
    srcip = data.get("srcip") or data.get("src_ip")
    if not srcip:
        return ""

    try:
        # search_security_events schema (per server.py:1339):
        #   - `query` is REQUIRED (Lucene syntax). Use "*" for match-all.
        #   - `srcip` is a structured filter that AND-combines with `query`.
        #   - I assumed only `src_ip` and got "Invalid parameter 'query'" — RTFM next time.
        text = await call_tool(
            "search_security_events",
            {
                "query": "*",
                "srcip": srcip,
                "time_range": "7d",
                "limit": 30,
                "compact": True,
            },
        )
    except Exception as e:
        log.warning("MCP enrichment failed: %r", e)
        return ""

    if not text:
        return ""

    # Cap at ~3KB so prompt stays sane on small models. Most enrichment
    # value is in the *summary numbers* (how many alerts, how many agents)
    # not in the raw rows; the LLM picks up the trend without needing all 30.
    snippet = text[:3000]
    if len(text) > 3000:
        snippet += f"\n[…truncated {len(text)-3000} chars]"

    return (
        "MCP RELATED CONTEXT — Wazuh historical events from this source IP "
        f"({srcip}) in the past 7 days:\n"
        f"{snippet}\n"
        "When writing summary_zh and assigning severity, account for this history. "
        "Same IP hitting multiple agents or rules over days indicates targeted "
        "campaign — escalate severity and mention it explicitly."
    )


def format_correlation_for_prompt(rows: list[dict[str, Any]],
                                  srcip: str | None,
                                  agent_name: str | None,
                                  window_minutes: int) -> str:
    """Render related-alerts list into a compact prompt block.

    Skipped automatically when there are no related events (≤ 1 hit just
    means 'we've seen the same alert once' — not useful signal).
    """
    if not rows or len(rows) < 2:
        return ""

    # Compact one-line summary per related alert. The LLM does not need
    # millisecond timestamps; relative minutes is enough.
    now = time.time()
    lines: list[str] = []
    distinct_rules: set[str] = set()
    distinct_agents: set[str] = set()
    for r in rows[:8]:                                          # cap to keep prompt small
        ago_min = max(0, int((now - (r.get("received_at") or now)) // 60))
        sev     = (r.get("llm_severity") or "?").lower()
        mitre   = r.get("llm_mitre") or "—"
        rid     = r.get("rule_id") or "?"
        rdesc   = (r.get("rule_description") or "").strip()[:80]
        ag      = r.get("agent_name") or "?"
        rip     = r.get("srcip") or "—"
        lines.append(
            f"  • {ago_min:>3}m ago | rule {rid} ({rdesc}) "
            f"| agent={ag} | srcip={rip} | sev={sev} | mitre={mitre}"
        )
        if r.get("rule_id"):
            distinct_rules.add(str(r["rule_id"]))
        if r.get("agent_name"):
            distinct_agents.add(str(r["agent_name"]))

    header_bits = []
    if srcip:
        header_bits.append(f"same source IP {srcip}")
    if agent_name:
        header_bits.append(f"same agent {agent_name}")
    pivot = " or ".join(header_bits) or "related signals"

    return (
        f"CORRELATION CONTEXT — {len(rows)} alert(s) in the past {window_minutes} min "
        f"sharing {pivot} "
        f"(distinct rules: {len(distinct_rules)}, agents: {len(distinct_agents)}):\n"
        + "\n".join(lines)
        + "\n"
        "Interpret this as a multi-stage / multi-host pattern, NOT as duplicate noise. "
        "If 3+ distinct rules fire from the same source IP within an hour, that is a "
        "campaign — raise severity at least one notch and explicitly mention in "
        "summary_zh and root_cause that this is part of an ongoing attack pattern. "
        "If multiple agents are hit, mention lateral movement risk."
    )
