from __future__ import annotations

import asyncio

import pytest

from support import fresh_bridge_import


@pytest.mark.unit
def test_self_test_summary_fails_only_required_failures() -> None:
    self_test = fresh_bridge_import(["self_test"])["self_test"]

    summary = self_test._summarize(
        [
            {"status": "ok", "required": True},
            {"status": "fail", "required": True},
            {"status": "warn", "required": False},
        ]
    )

    assert summary["overall"] == "fail"
    assert "IT" in summary["title_zh"]


@pytest.mark.unit
def test_self_test_summary_warns_on_non_required_warnings() -> None:
    self_test = fresh_bridge_import(["self_test"])["self_test"]

    summary = self_test._summarize(
        [
            {"status": "ok", "required": True},
            {"status": "warn", "required": False},
        ]
    )

    assert summary["overall"] == "warn"
    assert "可以使用" in summary["title_zh"]


@pytest.mark.unit
def test_self_test_summary_ok_when_all_checks_ok_or_skipped() -> None:
    self_test = fresh_bridge_import(["self_test"])["self_test"]

    summary = self_test._summarize(
        [
            {"status": "ok", "required": True},
            {"status": "skip", "required": False},
        ]
    )

    assert summary["overall"] == "ok"
    assert "正常使用" in summary["title_zh"]


@pytest.mark.unit
def test_alert_flow_ok_when_latest_analysis_recovered(monkeypatch: pytest.MonkeyPatch) -> None:
    modules = fresh_bridge_import(["self_test", "db"])
    self_test = modules["self_test"]
    db = modules["db"]

    async def fake_compute_stats() -> dict[str, object]:
        return {
            "total_alerts": 20,
            "alerts_last_24h": 8,
            "errors_last_24h": 2,
            "latest_error_received_at_24h": 1000.0,
            "latest_ok_received_at_24h": 1200.0,
        }

    monkeypatch.setattr(db, "compute_stats", fake_compute_stats)

    check = asyncio.run(self_test._check_alert_flow())

    assert check["status"] == "ok"
    assert "最近一次分析已成功" in check["summary_zh"]
    assert "errors=2" in check["detail_zh"]


@pytest.mark.unit
def test_alert_flow_warns_when_latest_analysis_is_error(monkeypatch: pytest.MonkeyPatch) -> None:
    modules = fresh_bridge_import(["self_test", "db"])
    self_test = modules["self_test"]
    db = modules["db"]

    async def fake_compute_stats() -> dict[str, object]:
        return {
            "total_alerts": 20,
            "alerts_last_24h": 8,
            "errors_last_24h": 2,
            "latest_error_received_at_24h": 1300.0,
            "latest_ok_received_at_24h": 1200.0,
        }

    monkeypatch.setattr(db, "compute_stats", fake_compute_stats)

    check = asyncio.run(self_test._check_alert_flow())

    assert check["status"] == "warn"
    assert "尚未看到後續成功分析" in check["summary_zh"]
