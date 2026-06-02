"""Dashboard sample-data replay routes."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Optional

import httpx
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

import sample_data
import siem

router = APIRouter(tags=["dashboard-sample-data"])


class SampleReplayRequest(BaseModel):
    category: str = "security"
    limit: int = 3
    min_level: int = 7


def built_in_test_alert() -> dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    return {
        "timestamp": now,
        "@timestamp": now,
        "@sampledata": True,
        "rule": {
            "id": "edgesec-test-001",
            "level": 10,
            "description": "EdgeSec-Pi built-in notification flow test",
            "groups": ["edgesec", "test"],
        },
        "agent": {
            "id": "edgesec-test",
            "name": "EdgeSec-Pi 測試電腦",
            "ip": "192.0.2.10",
        },
        "data": {
            "srcip": "203.0.113.10",
            "dstuser": "demo-admin",
            "test": True,
        },
        "full_log": (
            "EdgeSec-Pi built-in test alert: simulated repeated login attempt "
            "from 203.0.113.10 to demo-admin on EdgeSec-Pi 測試電腦."
        ),
        "_edgesec": {
            "sampledata": True,
            "built_in_test": True,
            "sample_source": "edgesec_builtin",
            "sample_replayed_at": now,
            "business_context": {
                "role": "通知測試",
                "owner": "管理者",
                "criticality": "medium",
                "business_hours": "24/7",
                "notes": "這是 EdgeSec-Pi 內建測試告警，不代表公司真的被攻擊。",
            },
        },
    }


@router.get("/api/dashboard/sample-data/status")
async def get_dashboard_sample_data_status(category: str = "security") -> dict[str, Any]:
    """Tell the Dashboard whether Wazuh Sample Data is loaded."""
    try:
        return await sample_data.sample_status(category=category)
    except sample_data.SampleDataError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            index_pattern = sample_data.index_pattern_for_category(category)
            return {
                "category": category,
                "index_pattern": index_pattern,
                "available": False,
                "total": 0,
                "sampledata_total": 0,
                "message": "尚未在 Wazuh Dashboard 加入 Sample Data。",
            }
        raise HTTPException(status_code=502, detail=f"Wazuh Indexer sample data query failed: {exc}")
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Wazuh Indexer sample data query failed: {exc}")


@router.post("/api/dashboard/sample-data/replay")
async def post_dashboard_sample_data_replay(
    request: Request,
    payload: SampleReplayRequest,
) -> dict[str, Any]:
    """Queue a small batch of Wazuh Sample Data through the real pipeline."""
    queue: Optional[asyncio.Queue] = getattr(request.app.state, "queue", None)
    if queue is None:
        raise HTTPException(status_code=503, detail="queue not initialized")

    try:
        alerts = await sample_data.load_sample_alerts(
            category=payload.category,
            limit=payload.limit,
            min_level=payload.min_level,
        )
    except sample_data.SampleDataError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            raise HTTPException(
                status_code=404,
                detail="尚未在 Wazuh Dashboard 加入 Sample Data，請先使用 EdgeSec-Pi 內建測試告警。",
            ) from exc
        raise HTTPException(status_code=502, detail=f"Wazuh Indexer sample data query failed: {exc}") from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Wazuh Indexer sample data query failed: {exc}")

    if not alerts:
        raise HTTPException(
            status_code=404,
            detail="No Wazuh sample alerts found. Add Sample Data in Wazuh Dashboard first.",
        )

    queued = 0
    for alert in alerts:
        if alert.get("@sampledata") is not True:
            continue
        try:
            normalized = siem.normalize_alert(alert, source_hint="wazuh")
            queue.put_nowait(normalized)
            queued += 1
        except asyncio.QueueFull:
            raise HTTPException(status_code=503, detail=f"queue full after queuing {queued} sample alerts")

    return {
        "queued": queued,
        "queue_size": queue.qsize(),
        "sampledata": True,
        "category": payload.category,
        "message": f"已送出 {queued} 筆 Wazuh 測試告警；通知內容會標示為測試資料。",
    }


@router.post("/api/dashboard/test-alert/replay")
async def post_dashboard_builtin_test_alert(request: Request) -> dict[str, Any]:
    """Queue one built-in test alert without requiring Wazuh Sample Data."""
    queue: Optional[asyncio.Queue] = getattr(request.app.state, "queue", None)
    if queue is None:
        raise HTTPException(status_code=503, detail="queue not initialized")

    try:
        normalized = siem.normalize_alert(built_in_test_alert(), source_hint="wazuh")
        queue.put_nowait(normalized)
    except asyncio.QueueFull:
        raise HTTPException(status_code=503, detail="queue full")

    return {
        "queued": 1,
        "queue_size": queue.qsize(),
        "sampledata": True,
        "category": "edgesec_builtin",
        "message": "已送出 1 筆 EdgeSec-Pi 內建測試告警；通知內容會標示為測試資料。",
    }
