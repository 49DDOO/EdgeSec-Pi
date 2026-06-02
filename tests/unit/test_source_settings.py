from __future__ import annotations

import asyncio

import pytest
from fastapi import HTTPException

from support import fresh_bridge_import


def _fresh_sources(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("WAZUH_API_PASS", "")
    monkeypatch.setenv("WAZUH_INDEXER_PASS", "")
    monkeypatch.setenv("WEBHOOK_SECRET", "")
    return fresh_bridge_import(["source_settings", "wazuh_settings"])


@pytest.mark.unit
def test_source_registry_does_not_mark_unconfigured_wazuh_active(monkeypatch: pytest.MonkeyPatch) -> None:
    modules = _fresh_sources(monkeypatch)
    source_settings = modules["source_settings"]

    payload = source_settings.list_sources()
    wazuh = next(item for item in payload["sources"] if item["key"] == "wazuh")
    planned = [item for item in payload["sources"] if item["status"] == "planned"]

    assert payload["primary_source"] == "wazuh"
    assert wazuh["status"] == "needs_setup"
    assert wazuh["enabled"] is False
    assert wazuh["can_configure"] is True
    assert wazuh["setup_href"] == "/settings/setup?source=wazuh"
    assert planned
    assert all(item["configured"] is False for item in planned)
    assert all(item["setup_href"] == "" for item in planned)


@pytest.mark.unit
def test_source_registry_marks_wazuh_active_when_required_settings_exist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    modules = _fresh_sources(monkeypatch)
    source_settings = modules["source_settings"]
    wazuh_settings = modules["wazuh_settings"]

    wazuh_settings.save({
        "WAZUH_API_PASS": "manager-secret",
        "WAZUH_INDEXER_PASS": "indexer-secret",
    })

    wazuh = source_settings.get_source("wazuh")
    result = source_settings.test_source("wazuh")

    assert wazuh["status"] == "active"
    assert wazuh["configured"] is True
    assert result["ok"] is True
    assert result["status"] == "configured"


@pytest.mark.unit
def test_future_source_is_planned_not_testable(monkeypatch: pytest.MonkeyPatch) -> None:
    modules = _fresh_sources(monkeypatch)
    source_settings = modules["source_settings"]

    source = source_settings.get_source("google_workspace")
    result = source_settings.test_source("google_workspace")

    assert source["status"] == "planned"
    assert source["test_supported"] is False
    assert result["ok"] is False
    assert result["status"] == "planned"


@pytest.mark.unit
def test_dashboard_sources_api_reports_unknown_source(monkeypatch: pytest.MonkeyPatch) -> None:
    _fresh_sources(monkeypatch)
    dashboard_sources_api = fresh_bridge_import(["dashboard_sources_api"])["dashboard_sources_api"]

    with pytest.raises(HTTPException) as exc:
        asyncio.run(dashboard_sources_api.get_dashboard_source("not-a-source"))

    assert exc.value.status_code == 404
