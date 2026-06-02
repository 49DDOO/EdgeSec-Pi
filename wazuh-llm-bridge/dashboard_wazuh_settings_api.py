"""Dashboard Wazuh connection settings routes."""
from __future__ import annotations

from typing import Optional

import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

import wazuh_settings

router = APIRouter(tags=["dashboard-wazuh-settings"])


class WazuhSettingsPatch(BaseModel):
    WAZUH_DEPLOYMENT_MODE: Optional[str] = None
    WAZUH_API_URL: Optional[str] = None
    WAZUH_API_USER: Optional[str] = None
    WAZUH_API_PASS: Optional[str] = None
    WAZUH_VERIFY_SSL: Optional[bool] = None
    WAZUH_INDEXER_URL: Optional[str] = None
    WAZUH_INDEXER_USER: Optional[str] = None
    WAZUH_INDEXER_PASS: Optional[str] = None
    WAZUH_INDEXER_VERIFY_SSL: Optional[bool] = None
    BRIDGE_PUBLIC_URL: Optional[str] = None
    WEBHOOK_SECRET: Optional[str] = None
    clear_WAZUH_API_PASS: bool = False
    clear_WAZUH_INDEXER_PASS: bool = False
    clear_WEBHOOK_SECRET: bool = False


@router.get("/api/dashboard/wazuh-settings")
async def get_dashboard_wazuh_settings() -> dict[str, object]:
    return wazuh_settings.values()


@router.put("/api/dashboard/wazuh-settings")
async def put_dashboard_wazuh_settings(payload: WazuhSettingsPatch) -> dict[str, object]:
    values = payload.dict(exclude_none=True)
    return wazuh_settings.save(values)


@router.post("/api/dashboard/wazuh-settings/test-manager")
async def post_dashboard_wazuh_manager_test() -> dict[str, object]:
    cfg = wazuh_settings.api_config()
    if not cfg["password"]:
        raise HTTPException(status_code=400, detail="Wazuh Manager 密碼尚未設定。")
    try:
        async with httpx.AsyncClient(verify=bool(cfg["verify_ssl"]), timeout=15.0) as client:
            auth_response = await client.post(
                f"{cfg['url']}/security/user/authenticate",
                auth=(cfg["user"], cfg["password"]),
            )
            auth_response.raise_for_status()
            token = auth_response.json()["data"]["token"]
            agents_response = await client.get(
                f"{cfg['url']}/agents",
                params={"limit": 1, "select": "id,name,status"},
                headers={"Authorization": f"Bearer {token}"},
            )
            agents_response.raise_for_status()
            data = agents_response.json().get("data", {})
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Wazuh Manager 連線測試失敗：{exc}")
    total = int(data.get("total_affected_items") or len(data.get("affected_items") or []))
    return {
        "ok": True,
        "message": f"Wazuh Manager 連線測試成功；可讀取 Agent 清單（目前 {total} 台）。",
        "agents_total": total,
    }


@router.post("/api/dashboard/wazuh-settings/test-indexer")
async def post_dashboard_wazuh_indexer_test() -> dict[str, object]:
    cfg = wazuh_settings.indexer_config()
    if not cfg["password"]:
        raise HTTPException(status_code=400, detail="Wazuh Indexer 密碼尚未設定。")
    try:
        async with httpx.AsyncClient(
            auth=(cfg["user"], cfg["password"]),
            verify=bool(cfg["verify_ssl"]),
            timeout=15.0,
        ) as client:
            response = await client.get(f"{cfg['url']}/_cluster/health")
            response.raise_for_status()
            data = response.json()
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Wazuh Indexer 連線測試失敗：{exc}")
    return {
        "ok": True,
        "message": f"Wazuh Indexer 連線測試成功；cluster 狀態：{data.get('status', 'unknown')}。",
        "status": data.get("status"),
        "cluster_name": data.get("cluster_name"),
    }
