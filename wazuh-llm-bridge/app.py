"""
Wazuh → LM Studio bridge
========================

Minimal async FastAPI webhook:

  1. POST /webhook receives a Wazuh alert (JSON)
  2. The handler enqueues the alert and returns 202 immediately,
     so Wazuh's integrator is NEVER blocked by LLM inference time.
  3. Background workers pull alerts from the queue, extract
     `rule.description` + `full_log`, and call LM Studio's
     OpenAI-compatible /v1/chat/completions endpoint.
  4. A bounded queue gives back-pressure (503) when bursts exceed
     what the local LLM can handle, so the host never OOMs.

Run:  uvicorn app:app --host 0.0.0.0 --port $BRIDGE_PORT  (env BRIDGE_PORT, default 8001)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Optional

# Load .env BEFORE any os.getenv() calls below so the bridge picks up
# WAZUH_API_PASS / ADMIN_PASS / WEBHOOK_SECRET / etc. even when launched
# via plain `python -m uvicorn app:app` without --env-file. python-dotenv
# is already pulled in via uvicorn[standard]. Silently no-op when the
# file is absent.
try:
    from dotenv import load_dotenv
    _shared_env_path = Path(__file__).resolve().parent.parent / "bridge.env"
    if _shared_env_path.exists():
        load_dotenv(_shared_env_path, override=False)
    _env_path = Path(__file__).parent / ".env"
    if _env_path.exists():
        load_dotenv(_env_path, override=False)
except ImportError:
    pass  # dotenv not installed → caller must export env vars manually

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import httpx

import db        # local module: SQLite persistence for alerts + LLM verdicts
import digest    # local module: daily freshness check (Wazuh ver / CVE feed / agents)
import slack_actions  # local module: Socket Mode listener for interactive buttons
import mcp_client     # local module: Wazuh MCP Server client (LLM enrichment)
import triage_router  # local module: Phase 3 — 3-layer routing decision
import agent_loop     # local module: Phase 3 — tool-using agentic investigation
import admin_ui       # local module: Phase 4 — /admin browser editor (split from app.py)
import dashboard_ui   # local module: management-facing /dashboard summary
import slack_render   # local module: Slack payload builders + send_to_slack
import notify_channels  # local module: LINE / email owner notifications
import prompting      # local module: build_prompt + parse_llm_reply + _extract_extra_context (split from app.py)
import active_response_api  # local module: destructive /active-response controls
import ops_api        # local module: health, query, and admin-triggered ops routes
import webhook_api    # local module: SIEM alert intake and queue handoff

# ──────────────────────────────────────────────────────────────────────────
# Config (env-driven — see .env.example)
# ──────────────────────────────────────────────────────────────────────────

# Defaults are tracked so we can warn at startup when a value is still
# at its baked-in default (i.e. was NOT set in the .env).
_DEFAULTS: dict[str, str] = {
    "LM_STUDIO_URL": "http://localhost:1234/v1/chat/completions",
    "LM_MODEL":      "local-model",
    "QUEUE_MAXSIZE": "1000",
    "WORKER_COUNT":  "2",
    "LM_TIMEOUT_S":  "60",
}


def _cfg(key: str) -> str:
    """Return os.getenv(key, _DEFAULTS[key]) with fallback for unknown keys."""
    return os.getenv(key, _DEFAULTS.get(key, ""))


LM_STUDIO_URL = _cfg("LM_STUDIO_URL")
LM_MODEL      = _cfg("LM_MODEL")
QUEUE_MAXSIZE = int(_cfg("QUEUE_MAXSIZE"))   # back-pressure threshold
WORKER_COUNT  = int(_cfg("WORKER_COUNT"))    # parallel inference slots
LM_TIMEOUT_S  = float(_cfg("LM_TIMEOUT_S"))

# Optional Slack incoming-webhook for AI-triaged alert notifications.
# Set this in the environment (or .env loaded by your shell). If unset,
# Slack notifications are silently skipped — the rest of the pipeline
# still works. Slack-format webhooks also work with Discord (append
# "?slack=true" to the Discord webhook URL).
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "").strip() or None


def _log_config() -> None:
    """Print every effective config value at startup.

    - Values sourced from env are shown as-is.
    - Values still at the baked-in default are tagged [default].
    - Known bad combinations trigger a WARNING so they're impossible to miss.
    """
    def _src(key: str, val: str) -> str:
        """Return '[default]' if the env var was absent (we're using the fallback)."""
        return "[default]" if os.getenv(key) is None else "[env]"

    log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  EdgeSec-Pi config  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

    # ── LM Studio ──
    log.info("  LM_STUDIO_URL  = %s  %s", LM_STUDIO_URL, _src("LM_STUDIO_URL", LM_STUDIO_URL))
    log.info("  LM_MODEL       = %s  %s", LM_MODEL,      _src("LM_MODEL", LM_MODEL))
    log.info("  LM_TIMEOUT_S   = %.0f  %s",  LM_TIMEOUT_S,  _src("LM_TIMEOUT_S", str(LM_TIMEOUT_S)))

    # ── Queue / workers ──
    log.info("  QUEUE_MAXSIZE  = %d  %s", QUEUE_MAXSIZE, _src("QUEUE_MAXSIZE", str(QUEUE_MAXSIZE)))
    log.info("  WORKER_COUNT   = %d  %s", WORKER_COUNT,  _src("WORKER_COUNT",  str(WORKER_COUNT)))

    # ── Slack ──
    if SLACK_WEBHOOK_URL:
        masked = SLACK_WEBHOOK_URL[:45] + "…"
        log.info("  SLACK_WEBHOOK_URL = %s  [env]", masked)
    else:
        log.info("  SLACK_WEBHOOK_URL = (not set)")

    bot_tok  = bool(os.getenv("SLACK_BOT_TOKEN"))
    app_tok  = bool(os.getenv("SLACK_APP_TOKEN"))
    chan_id   = os.getenv("SLACK_CHANNEL_ID", "")
    if bot_tok and app_tok and chan_id:
        log.info("  Slack bot mode   = ENABLED  (channel=%s)", chan_id)
    elif bot_tok or app_tok or chan_id:
        log.warning("  Slack bot mode   = INCOMPLETE — set all three of "
                    "SLACK_BOT_TOKEN / SLACK_APP_TOKEN / SLACK_CHANNEL_ID for buttons")
    else:
        log.info("  Slack bot mode   = disabled (webhook-only or silent)")

    # ── MCP ──
    mcp_url = os.getenv("MCP_SERVER_URL", "")
    mcp_key = os.getenv("MCP_API_KEY", "")
    if mcp_url and mcp_key:
        log.info("  MCP_SERVER_URL   = %s  [env]", mcp_url)
    else:
        log.info("  MCP              = disabled (MCP_SERVER_URL / MCP_API_KEY not set)")

    # ── Agentic ──
    import agent_loop as _al
    log.info("  AGENTIC_MAX_ITER = %d  /  TIMEOUT = %.0fs  /  TOOL_MAX = %d chars",
             _al.MAX_ITERATIONS, _al.TOTAL_TIMEOUT_S, _al.TOOL_RESULT_MAX_CHARS)

    # ── Active Response ──
    if active_response_api.active_response_enabled():
        log.info("  ACTIVE_RESPONSE  = ENABLED (token set)")
    else:
        log.info("  ACTIVE_RESPONSE  = disabled (ACTIVE_RESPONSE_TOKEN not set)")

    webhook_secret = bool(os.getenv("WEBHOOK_SECRET", "").strip())
    bind_host = os.getenv("BRIDGE_BIND_HOST", "").strip()
    if webhook_secret:
        log.info("  WEBHOOK_SECRET   = set")
    else:
        log.warning("  ⚠  WEBHOOK_SECRET is not set — only safe when the bridge is bound to localhost")
    if bind_host:
        log.info("  BRIDGE_BIND_HOST = %s", bind_host)
    public_url = os.getenv("BRIDGE_PUBLIC_URL", "").strip()
    if public_url.startswith("http://"):
        log.warning("  ⚠  BRIDGE_PUBLIC_URL uses plain HTTP; use HTTPS before installing agents from another computer")

    # ── Sanity warnings ──
    log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    if LM_MODEL == "local-model":
        log.warning("  ⚠  LM_MODEL is still 'local-model' — set it to the exact model string "
                    "shown in LM Studio to ensure the right model is used")
    if not SLACK_WEBHOOK_URL and not (bot_tok and app_tok and chan_id):
        log.warning("  ⚠  No Slack output configured — alerts will be processed but not pushed anywhere")
    if WORKER_COUNT > 4:
        log.warning("  ⚠  WORKER_COUNT=%d is high — may cause GPU memory thrashing on a single local model",
                    WORKER_COUNT)
    log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s | %(message)s",
)
log = logging.getLogger("wazuh-bridge")


async def analyze(alert: dict[str, Any],
                  client: httpx.AsyncClient,
                  worker_id: int) -> None:
    """Phase 3 pipeline:

        triage_router.decide(alert) ─┐
                                     ├─ "agentic"     → agent_loop.run() (skip Stage-1)
                                     ├─ "quick"       → Stage-1 LLM only
                                     └─ "llm_decides" → Stage-1; if it sets
                                                        needs_investigation=true,
                                                        escalate to agent_loop

    Why a fallback chain? The agent_loop is the most expensive path
    (6+ LLM calls, 60+ seconds). On admin-forced agentic we still want
    a notification if the loop blows up — so on exception we degrade
    gracefully to a Stage-1 quick verdict instead of dropping the alert.
    """
    rule    = alert.get("rule") or {}
    rule_id = rule.get("id", "?")
    level   = rule.get("level", "?")

    decision = triage_router.decide(alert)
    log.info("worker-%d triage rule=%s level=%s → %s",
             worker_id, rule_id, level, decision)

    # Phase 3a — fetch historical context before building the prompt.
    # This runs once for any LLM path (Stage-1 and/or agentic).
    enrichment = await mcp_client.enrich_alert(alert)
    if enrichment:
        alert["_mcp_enrichment"] = enrichment       # picked up by build_prompt
        log.info("worker-%d ← MCP enriched (%d chars)", worker_id, len(enrichment))

    # Phase 3b — correlation: look up our own SQLite for related recent
    # alerts (same srcip / same agent in the last 60 min). This is the
    # cheap, local equivalent of XDR cross-alert linking.
    try:
        data        = alert.get("data") or {}
        srcip       = data.get("srcip") or data.get("src_ip") or None
        agent_name  = (alert.get("agent") or {}).get("name") or None
        window_min  = 60
        related = await db.fetch_correlation_context(
            srcip=srcip,
            agent_name=agent_name,
            window_seconds=window_min * 60,
            limit=10,
        )
        corr_chunk = mcp_client.format_correlation_for_prompt(
            related, srcip, agent_name, window_min
        )
        if corr_chunk:
            alert["_correlation_context"] = corr_chunk
            log.info("worker-%d ← correlation: %d related alert(s)",
                     worker_id, len(related))
    except Exception as e:                           # pragma: no cover - defensive
        log.warning("worker-%d correlation lookup failed: %r", worker_id, e)

    prompt, _, _ = prompting.build_prompt(alert)

    t0         = time.perf_counter()
    answer:    str                       = ""
    parsed:    Optional[dict[str, Any]]  = None
    evidence:  Optional[list[dict]]      = None
    error_msg: Optional[str]             = None

    # ── Direct-to-agentic (admin FORCE policy) ────────────────────────
    if decision == "agentic":
        log.info("worker-%d → agentic loop (admin policy)", worker_id)
        try:
            verdict, evidence = await agent_loop.run(
                alert, client, prompt,
                reason_to_investigate="admin triage policy forced deep investigation",
            )
            parsed = verdict
            answer = json.dumps(verdict, ensure_ascii=False)
        except Exception as e:
            error_msg = f"agentic failed: {e!r}"
            log.warning("worker-%d agentic loop failed (%s); falling back to Stage-1",
                        worker_id, e)
            decision = "quick"        # fall through into Stage-1 below

    # ── Stage-1 (quick / llm_decides / agentic-fallback) ──────────────
    if decision in ("quick", "llm_decides"):
        log.info("worker-%d → LM Studio Stage-1 (route=%s)", worker_id, decision)
        s1_payload = {
            "model":       LM_MODEL,
            "messages":    [{"role": "user", "content": prompt}],
            "temperature": 0.1,
            "stream":      False,
            # NOTE: We rely on prompt-level "Output JSON only" rather than
            # response_format=json_object — some LM Studio versions HTTP-400
            # that field. Modern instruct models comply with the instruction
            # reliably; parse_llm_reply tolerates imperfect JSON.
        }
        try:
            r = await client.post(LM_STUDIO_URL, json=s1_payload, timeout=LM_TIMEOUT_S)
            r.raise_for_status()
            answer = r.json()["choices"][0]["message"]["content"].strip()
            parsed = prompting.parse_llm_reply(answer)
            log.info("worker-%d ← Stage-1 reply=%r", worker_id, answer[:200])
        except (httpx.HTTPError, KeyError, ValueError) as e:
            err_s1 = f"stage1: {e!r}"
            error_msg = f"{error_msg} | {err_s1}" if error_msg else err_s1
            log.warning("worker-%d Stage-1 error: %s", worker_id, e)

        # Stage-2 escalation: only on the LLM-deciding path, only when
        # Stage-1 itself flagged the alert as worth investigating deeper.
        if decision == "llm_decides" and parsed and parsed.get("needs_investigation"):
            inv_reason = str(parsed.get("investigation_reason", ""))
            log.info("worker-%d → escalating to agentic loop (reason=%r)",
                     worker_id, inv_reason[:100])
            try:
                verdict, evidence = await agent_loop.run(
                    alert, client, prompt,
                    reason_to_investigate=inv_reason,
                    prior_stage1=parsed,
                )
                # Agentic verdict supersedes Stage-1 output.
                parsed = verdict
                answer = json.dumps(verdict, ensure_ascii=False)
            except Exception as e:
                err_a = f"agentic-escalate: {e!r}"
                error_msg = f"{error_msg} | {err_a}" if error_msg else err_a
                log.warning("worker-%d agentic escalation failed: %s "
                            "(falling back to Stage-1 verdict)", worker_id, e)
                # answer + parsed from Stage-1 remain; we still notify on those.

    # ── Notify Slack once with the final verdict + (optional) evidence
    if answer:
        try:
            await slack_render.send_to_slack(alert, parsed, client, evidence=evidence)
        except Exception as e:
            log.warning("worker-%d slack send failed: %s", worker_id, e)
        try:
            extra_notify = await notify_channels.send_secondary_notifications(alert, parsed, client)
            if extra_notify:
                log.info("worker-%d secondary notifications: %s", worker_id, extra_notify)
        except Exception as e:
            log.warning("worker-%d secondary notifications failed: %s", worker_id, e)

    latency_ms = int((time.perf_counter() - t0) * 1000)

    # Persist to SQLite — both successful triage and LLM failures are recorded
    # so we have an honest history for audit and future analysis.
    try:
        await db.save_alert(alert, answer, parsed, latency_ms, error_msg)
    except Exception as e:
        log.warning("worker-%d DB save failed: %s", worker_id, e)


async def consume(queue: asyncio.Queue,
                  client: httpx.AsyncClient,
                  worker_id: int) -> None:
    log.info("worker-%d started", worker_id)
    while True:
        alert = await queue.get()
        try:
            await analyze(alert, client, worker_id)
        except asyncio.CancelledError:
            raise
        except httpx.HTTPError as e:
            log.warning("worker-%d LM Studio error: %s", worker_id, e)
        except Exception:
            log.exception("worker-%d unexpected error", worker_id)
        finally:
            queue.task_done()


# ──────────────────────────────────────────────────────────────────────────
# App lifecycle — spawn workers on startup, drain on shutdown
# ──────────────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    await db.init_db()
    log.info("DB ready at %s", db.DB_PATH)

    _log_config()
    log.info("triage policy: %s", triage_router.describe_policy())

    queue: asyncio.Queue = asyncio.Queue(maxsize=QUEUE_MAXSIZE)
    client = httpx.AsyncClient()
    workers = [
        asyncio.create_task(consume(queue, client, i))
        for i in range(WORKER_COUNT)
    ]
    # Daily 09:00 freshness digest (Wazuh ver / CVE feed / agents / 24h alerts)
    digest_task = asyncio.create_task(digest.daily_scheduler(SLACK_WEBHOOK_URL))

    # Slack interactive buttons via Socket Mode (no-op if env vars missing)
    await slack_actions.start_listener()

    app.state.queue = queue
    try:
        yield
    finally:
        log.info("draining queue (%d pending)…", queue.qsize())
        await queue.join()
        digest_task.cancel()
        for w in workers:
            w.cancel()
        await asyncio.gather(digest_task, *workers, return_exceptions=True)
        await slack_actions.stop_listener()
        await client.aclose()
        log.info("shutdown complete")


app = FastAPI(title="SIEM → LM Studio bridge", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:3000",
        "http://localhost:3000",
        "https://127.0.0.1:3000",
        "https://localhost:3000",
    ],
    allow_credentials=False,
    allow_methods=["GET", "PATCH", "POST", "OPTIONS"],
    allow_headers=["*"],
)
app.include_router(dashboard_ui.router)     # /dashboard management-facing summary
app.include_router(admin_ui.router)         # /admin and /admin/quick-add routes
app.include_router(active_response_api.router)
app.include_router(ops_api.router)
app.include_router(webhook_api.router)
