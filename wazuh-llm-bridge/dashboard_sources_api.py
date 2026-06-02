"""Dashboard data source registry routes."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

import source_settings

router = APIRouter(tags=["dashboard-sources"])


@router.get("/api/dashboard/sources")
async def get_dashboard_sources() -> dict[str, object]:
    return source_settings.list_sources()


@router.get("/api/dashboard/sources/{source_key}")
async def get_dashboard_source(source_key: str) -> dict[str, object]:
    try:
        return source_settings.get_source(source_key)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/api/dashboard/sources/{source_key}/test")
async def post_dashboard_source_test(source_key: str) -> dict[str, object]:
    try:
        return source_settings.test_source(source_key)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
