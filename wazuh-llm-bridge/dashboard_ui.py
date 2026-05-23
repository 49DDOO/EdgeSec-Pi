"""Legacy Dashboard compatibility routes.

The release Dashboard lives in ``dashboard/`` and talks to the bridge through
``/api/dashboard/*`` routes in ``ops_api.py``.  This module intentionally does
not render a second HTML dashboard; it only keeps old bookmarks and old action
forms from breaking.
"""
from __future__ import annotations

import os
from urllib.parse import urljoin

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse

import db

router = APIRouter()

DASHBOARD_V2_URL = os.getenv("DASHBOARD_V2_URL", "http://127.0.0.1:3000").rstrip("/")

_PATH_BY_LEGACY_VIEW = {
    "today": "/",
    "services": "/settings/endpoints",
    "setup": "/settings/status",
    "platform": "/settings/status",
    "advanced": "/settings/testing",
    "notifications": "/settings/notifications",
    "testing": "/settings/testing",
    "status": "/settings/status",
}


def _dashboard_v2_redirect_url(request: Request) -> str:
    """Translate old bridge Dashboard URLs to the new Next.js Dashboard."""
    view = (request.query_params.get("view") or "today").strip().lower()
    target_path = _PATH_BY_LEGACY_VIEW.get(view, "/")
    return urljoin(f"{DASHBOARD_V2_URL}/", target_path.lstrip("/"))


@router.get("/", include_in_schema=False)
async def root(request: Request) -> RedirectResponse:
    return RedirectResponse(url=_dashboard_v2_redirect_url(request))


@router.get("/dashboard", include_in_schema=False)
async def dashboard(request: Request) -> RedirectResponse:
    return RedirectResponse(url=_dashboard_v2_redirect_url(request))


@router.post("/dashboard/alerts/{alert_id}/case", include_in_schema=False)
async def update_dashboard_alert_case(alert_id: int, request: Request) -> RedirectResponse:
    """Accept old form posts and send the user back to the new Dashboard."""
    form = await request.form()
    status = str(form.get("status") or "").strip()
    note = str(form.get("note") or "").strip()
    try:
        await db.update_alert_case(alert_id, status, note, actor="dashboard-legacy")
        raw_group_ids = str(form.get("group_ids") or "").strip()
        group_ids = [
            int(part)
            for part in raw_group_ids.split(",")
            if part.strip().isdigit()
        ]
        if group_ids:
            await db.update_alert_cases(group_ids, status, note, actor="dashboard-legacy")
    except ValueError:
        pass
    return RedirectResponse(url=urljoin(f"{DASHBOARD_V2_URL}/", ""), status_code=303)
