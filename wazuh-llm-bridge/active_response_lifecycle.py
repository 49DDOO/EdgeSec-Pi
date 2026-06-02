"""Background lifecycle tasks for Active Response actions."""
from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Any

import active_response_safety
import wazuh

log = logging.getLogger("active-response-lifecycle")

DEFAULT_SWEEP_INTERVAL_S = 60
DEFAULT_SWEEP_BATCH_SIZE = 20

_sweeper_task: asyncio.Task | None = None


def ttl_sweeper_enabled() -> bool:
    raw = os.getenv("ACTIVE_RESPONSE_TTL_SWEEPER_ENABLED", "1").strip().lower()
    return raw not in {"0", "false", "no", "off"}


def sweep_interval_s() -> int:
    raw = os.getenv("ACTIVE_RESPONSE_TTL_SWEEP_INTERVAL_S", str(DEFAULT_SWEEP_INTERVAL_S)).strip()
    try:
        seconds = int(raw)
    except ValueError:
        seconds = DEFAULT_SWEEP_INTERVAL_S
    return max(5, min(seconds, 3600))


def sweep_batch_size() -> int:
    raw = os.getenv("ACTIVE_RESPONSE_TTL_SWEEP_BATCH_SIZE", str(DEFAULT_SWEEP_BATCH_SIZE)).strip()
    try:
        size = int(raw)
    except ValueError:
        size = DEFAULT_SWEEP_BATCH_SIZE
    return max(1, min(size, 200))


async def sweep_expired_blocks(*, limit: int | None = None) -> dict[str, Any]:
    """Try to remove expired tracked IP blocks from endpoint firewalls.

    Returns a compact summary for tests and future admin endpoints. The task
    never raises for per-block failures; failed rows are marked explicitly so
    IT can see which TTL cleanup still needs manual handling.
    """
    active_response_safety.init_db_sync()
    expired = active_response_safety.list_expired_active_blocks(limit or sweep_batch_size())
    results: list[dict[str, Any]] = []
    for row in expired:
        claimed = active_response_safety.claim_expired_block(int(row["id"]))
        if not claimed:
            continue
        results.append(await _expire_block(claimed))
    return {
        "checked": len(expired),
        "processed": len(results),
        "results": results,
    }


async def sweep_expired_isolations(*, limit: int | None = None) -> dict[str, Any]:
    """Try to release expired tracked endpoint isolations."""
    active_response_safety.init_db_sync()
    expired = active_response_safety.list_expired_active_isolations(limit or sweep_batch_size())
    results: list[dict[str, Any]] = []
    for row in expired:
        claimed = active_response_safety.claim_expired_isolation(int(row["id"]))
        if not claimed:
            continue
        results.append(await _expire_isolation(claimed))
    return {
        "checked": len(expired),
        "processed": len(results),
        "results": results,
    }


async def _expire_block(block: dict[str, Any]) -> dict[str, Any]:
    record_id = int(block["id"])
    agent_id = str(block["agent_id"])
    ip = str(block["ip"])
    attempt = int(block.get("attempt_count") or 0)
    started_at = time.time()
    try:
        result = await wazuh.unblock_ip(
            agent_id,
            ip,
            require_tracked=False,
            record_state=False,
        )
    except Exception as exc:
        log.exception("TTL unblock failed: agent=%s ip=%s", agent_id, ip)
        status, next_retry_at = _retry_status(attempt, started_at)
        active_response_safety.mark_block_status(
            record_id,
            status,
            next_retry_at=next_retry_at,
            details=_failure_details(
                started_at,
                agent_id,
                ip,
                attempt,
                {"error": str(exc)},
                status,
                next_retry_at,
            ),
        )
        return {"id": record_id, "agent_id": agent_id, "ip": ip, "status": status}

    if result.get("ok"):
        active_response_safety.record_unblock(
            agent_id,
            ip,
            record_id=record_id,
            actor="ttl-sweeper",
            reason="block TTL expired",
            details={
                "attempted_at": started_at,
                "agent_id": agent_id,
                "ip": ip,
                "result": result,
            },
        )
        log.info("TTL unblock completed: agent=%s ip=%s", agent_id, ip)
        return {"id": record_id, "agent_id": agent_id, "ip": ip, "status": "unblocked"}

    if result.get("manual_required"):
        status = "manual_unblock_required"
        next_retry_at = None
    else:
        status, next_retry_at = _retry_status(attempt, started_at)
    active_response_safety.mark_block_status(
        record_id,
        status,
        next_retry_at=next_retry_at,
        details=_failure_details(started_at, agent_id, ip, attempt, {"result": result}, status, next_retry_at),
    )
    if status == "manual_unblock_required":
        log.warning("TTL unblock needs manual handling: agent=%s ip=%s", agent_id, ip)
    else:
        log.warning("TTL unblock failed: agent=%s ip=%s result=%s", agent_id, ip, result)
    return {"id": record_id, "agent_id": agent_id, "ip": ip, "status": status}


async def _expire_isolation(row: dict[str, Any]) -> dict[str, Any]:
    record_id = int(row["id"])
    agent_id = str(row["agent_id"])
    attempt = int(row.get("attempt_count") or 0)
    started_at = time.time()
    try:
        result = await wazuh.release_isolation(
            agent_id,
            require_tracked=False,
            record_state=False,
            reason="isolation TTL expired",
        )
    except Exception as exc:
        log.exception("TTL release isolation failed: agent=%s", agent_id)
        status, next_retry_at = _release_retry_status(attempt, started_at)
        active_response_safety.mark_isolation_status(
            record_id,
            status,
            next_retry_at=next_retry_at,
            details=_isolation_failure_details(
                started_at,
                agent_id,
                attempt,
                {"error": str(exc)},
                status,
                next_retry_at,
            ),
        )
        return {"id": record_id, "agent_id": agent_id, "status": status}

    if result.get("ok"):
        # Endpoint firewall rules are intentionally non-persistent. If an
        # endpoint reboots while isolated, the local script may report that it
        # is already released; a successful release dispatch still closes the
        # bridge-side lifecycle state.
        active_response_safety.record_release_isolation(
            agent_id,
            record_id=record_id,
            actor="ttl-sweeper",
            reason="isolation TTL expired",
            details={
                "attempted_at": started_at,
                "agent_id": agent_id,
                "result": result,
            },
        )
        log.info("TTL isolation release completed: agent=%s", agent_id)
        return {"id": record_id, "agent_id": agent_id, "status": "released"}

    if result.get("manual_required"):
        status = "manual_release_required"
        next_retry_at = None
    else:
        status, next_retry_at = _release_retry_status(attempt, started_at)
    active_response_safety.mark_isolation_status(
        record_id,
        status,
        next_retry_at=next_retry_at,
        details=_isolation_failure_details(
            started_at,
            agent_id,
            attempt,
            {"result": result},
            status,
            next_retry_at,
        ),
    )
    if status == "manual_release_required":
        log.warning("TTL isolation release needs manual handling: agent=%s", agent_id)
    else:
        log.warning("TTL isolation release failed: agent=%s result=%s", agent_id, result)
    return {"id": record_id, "agent_id": agent_id, "status": status}


def _retry_status(attempt: int, attempted_at: float) -> tuple[str, float | None]:
    max_attempts = active_response_safety.unblock_max_attempts()
    if attempt >= max_attempts:
        return "manual_unblock_required", None
    delay_s = active_response_safety.unblock_retry_delay_s(attempt)
    return "unblock_failed", attempted_at + delay_s


def _release_retry_status(attempt: int, attempted_at: float) -> tuple[str, float | None]:
    max_attempts = active_response_safety.release_max_attempts()
    if attempt >= max_attempts:
        return "manual_release_required", None
    delay_s = active_response_safety.release_retry_delay_s(attempt)
    return "release_failed", attempted_at + delay_s


def _failure_details(
    attempted_at: float,
    agent_id: str,
    ip: str,
    attempt: int,
    result: dict[str, Any],
    status: str,
    next_retry_at: float | None,
) -> dict[str, Any]:
    max_attempts = active_response_safety.unblock_max_attempts()
    return {
        "attempted_at": attempted_at,
        "agent_id": agent_id,
        "ip": ip,
        "attempt": attempt,
        "max_attempts": max_attempts,
        "next_retry_at": next_retry_at,
        "attempts_exhausted": status == "manual_unblock_required" and attempt >= max_attempts,
        **result,
    }


def _isolation_failure_details(
    attempted_at: float,
    agent_id: str,
    attempt: int,
    result: dict[str, Any],
    status: str,
    next_retry_at: float | None,
) -> dict[str, Any]:
    max_attempts = active_response_safety.release_max_attempts()
    return {
        "attempted_at": attempted_at,
        "agent_id": agent_id,
        "attempt": attempt,
        "max_attempts": max_attempts,
        "next_retry_at": next_retry_at,
        "attempts_exhausted": status == "manual_release_required" and attempt >= max_attempts,
        **result,
    }


def start_sweeper() -> None:
    global _sweeper_task
    if not ttl_sweeper_enabled():
        log.info("active-response TTL sweeper disabled")
        return
    if _sweeper_task and not _sweeper_task.done():
        return
    active_response_safety.init_db_sync()
    _sweeper_task = asyncio.create_task(_sweeper_loop(), name="active-response-ttl-sweeper")
    log.info("active-response TTL sweeper started; interval=%ss", sweep_interval_s())


async def stop_sweeper() -> None:
    global _sweeper_task
    if not _sweeper_task:
        return
    _sweeper_task.cancel()
    await asyncio.gather(_sweeper_task, return_exceptions=True)
    _sweeper_task = None
    log.info("active-response TTL sweeper stopped")


async def _sweeper_loop() -> None:
    while True:
        try:
            block_summary = await sweep_expired_blocks()
            isolation_summary = await sweep_expired_isolations()
            if block_summary["processed"] or isolation_summary["processed"]:
                log.info(
                    "active-response TTL sweep processed %d block(s), %d isolation(s)",
                    block_summary["processed"],
                    isolation_summary["processed"],
                )
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("active-response TTL sweep failed")
        await asyncio.sleep(sweep_interval_s())
