"""Operational and read-only API routes for EdgeSec-Pi.

Keep app.py focused on lifecycle and alert processing. Routes here are
supporting surfaces used by health checks, the dashboard, diagnostics, and
admin-triggered notification tests.
"""
from __future__ import annotations

import asyncio
import os
from typing import Any, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request

import admin_auth
import db
import digest
import self_test
import slack_render

router = APIRouter(tags=["ops"])

QUEUE_MAXSIZE = int(os.getenv("QUEUE_MAXSIZE", "1000"))
WORKER_COUNT = int(os.getenv("WORKER_COUNT", "2"))
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "").strip() or None


@router.get("/health")
async def health(request: Request) -> dict[str, Any]:
    queue: Optional[asyncio.Queue] = getattr(request.app.state, "queue", None)
    return {
        "status": "ok",
        "queue_size": queue.qsize() if queue else 0,
        "queue_max": QUEUE_MAXSIZE,
        "workers": WORKER_COUNT,
    }


@router.get("/alerts")
async def get_alerts(
    limit: int = 50,
    severity: Optional[str] = None,
    rule_id: Optional[str] = None,
) -> list[dict[str, Any]]:
    """Recent alerts, newest first."""
    limit = max(1, min(int(limit), 500))
    return await db.list_alerts(limit=limit, severity=severity, rule_id=rule_id)


@router.get("/stats")
async def get_stats() -> dict[str, Any]:
    """Aggregate counts: total, last 24h, by severity, top rules, avg latency."""
    return await db.compute_stats()


@router.get("/status")
async def get_status() -> dict[str, Any]:
    """On-demand JSON form of the daily freshness digest."""
    return await digest.collect_status()


@router.get("/self-test")
async def get_self_test(request: Request) -> dict[str, Any]:
    """Management-facing readiness check."""
    queue = getattr(request.app.state, "queue", None)
    queue_size = queue.qsize() if queue else 0
    queue_max = getattr(queue, "maxsize", 0) or 0
    return await self_test.run_self_test(queue_size=queue_size, queue_max=queue_max)


@router.post("/test-slack")
async def test_slack(_: str = Depends(admin_auth.check_admin)) -> dict[str, Any]:
    """Send a canned Slack alert. Admin-only because it pushes notifications."""
    if not SLACK_WEBHOOK_URL:
        raise HTTPException(
            status_code=400,
            detail="SLACK_WEBHOOK_URL is not set in env. Restart the bridge with it set.",
        )
    fake_alert = {
        "rule": {
            "id": "5712",
            "level": 10,
            "description": "sshd: brute force trying to get access to the system. Non existent user.",
        },
        "agent": {"id": "001", "name": "wazuh-agent-01", "ip": "172.18.0.5"},
        "full_log": (
            "May 10 17:05:00 wazuh-agent-01 sshd[1234]: Failed password for invalid "
            "user admin from 192.0.2.111 port 55501 ssh2"
        ),
    }
    fake_parsed = {
        "severity": "high",
        "summary_zh": "有人從外部 IP（192.0.2.111）不斷用「admin」這個帳號嘗試登入你的伺服器，已連續失敗 8 次以上。",
        "impact_zh": "若對方繼續猜下去成功登入，可能會進入系統竊取或破壞資料、安裝後門程式。",
        "next_step_zh": "請聯絡 IT 把 192.0.2.111 這個 IP 暫時封鎖，並確認沒有任何人不小心成功登入。",
        "root_cause": "SSH brute-force from external IP targeting non-existent user 'admin'.",
        "iocs": ["192.0.2.111", "admin"],
        "action": (
            "Block 192.0.2.111 at the firewall; verify no successful auths "
            "from that IP in the last 24h; consider disabling SSH password auth in favour of keys."
        ),
        "mitre": "T1110",
    }
    async with httpx.AsyncClient() as client:
        await slack_render.send_to_slack(fake_alert, fake_parsed, client)
    return {"sent": True, "webhook": SLACK_WEBHOOK_URL[:40] + "..."}


@router.post("/test-digest")
async def test_digest(_: str = Depends(admin_auth.check_admin)) -> dict[str, Any]:
    """Send the freshness digest immediately. Admin-only notification action."""
    return await digest.send_digest(SLACK_WEBHOOK_URL)
