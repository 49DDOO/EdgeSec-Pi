from __future__ import annotations

import asyncio

import pytest

from support import fresh_bridge_import


@pytest.mark.unit
def test_hardening_status_ok_when_groups_and_agents_match() -> None:
    wazuh_hardening = fresh_bridge_import(["wazuh_hardening"])["wazuh_hardening"]

    result = wazuh_hardening.evaluate_status(
        groups=[
            {"name": "default"},
            {"name": "macos"},
            {"name": "linux"},
            {"name": "windows"},
        ],
        agents=[
            {
                "id": "000",
                "name": "wazuh.manager",
                "status": "active",
                "os": {"platform": "Linux"},
                "group": [],
            },
            {
                "id": "001",
                "name": "office-ubuntu",
                "status": "active",
                "os": {"platform": "Linux"},
                "group": ["default", "linux"],
            },
            {
                "id": "002",
                "name": "boss-macbook",
                "status": "active",
                "os": {"platform": "Darwin"},
                "group": ["default", "macos"],
            },
        ],
        recipe_files_present=True,
    )

    assert result["status"] == "ok"
    assert result["missing_groups"] == []
    assert result["agents_checked"] == 2
    assert result["agents_missing_group"] == []


@pytest.mark.unit
def test_hardening_status_warns_when_manager_groups_are_missing() -> None:
    wazuh_hardening = fresh_bridge_import(["wazuh_hardening"])["wazuh_hardening"]

    result = wazuh_hardening.evaluate_status(
        groups=[{"name": "default"}],
        agents=[],
        recipe_files_present=True,
    )

    assert result["status"] == "warn"
    assert result["missing_groups"] == ["linux", "macos", "windows"]
    assert "setup-agent-groups.sh" in result["next_step_zh"]


@pytest.mark.unit
def test_hardening_status_warns_when_online_agent_lacks_os_group() -> None:
    wazuh_hardening = fresh_bridge_import(["wazuh_hardening"])["wazuh_hardening"]

    result = wazuh_hardening.evaluate_status(
        groups=["default", "macos", "linux", "windows"],
        agents=[
            {
                "id": "003",
                "name": "win-finance",
                "status": "active",
                "os": {"platform": "windows"},
                "group": ["default"],
            }
        ],
        recipe_files_present=True,
    )

    assert result["status"] == "warn"
    assert result["agents_missing_group"] == [
        {
            "id": "003",
            "name": "win-finance",
            "expected_group": "windows",
            "groups": ["default"],
        }
    ]


@pytest.mark.unit
def test_hardening_status_warns_when_recipe_files_are_missing() -> None:
    wazuh_hardening = fresh_bridge_import(["wazuh_hardening"])["wazuh_hardening"]

    result = wazuh_hardening.evaluate_status(
        groups=["default", "macos", "linux", "windows"],
        agents=[],
        recipe_files_present=False,
    )

    assert result["status"] == "warn"
    assert "找不到" in result["summary_zh"]


@pytest.mark.unit
def test_hardening_status_skips_until_first_endpoint_is_installed() -> None:
    wazuh_hardening = fresh_bridge_import(["wazuh_hardening"])["wazuh_hardening"]

    result = wazuh_hardening.evaluate_status(
        groups=["default", "macos", "linux", "windows"],
        agents=[
            {
                "id": "000",
                "name": "wazuh.manager",
                "status": "active",
                "os": {"platform": "Linux"},
                "group": [],
            }
        ],
        recipe_files_present=True,
    )

    assert result["status"] == "skip"
    assert "尚未安裝" in result["summary_zh"]
    assert result["agents_checked"] == 0


@pytest.mark.unit
def test_self_test_hardening_check_is_non_required(monkeypatch) -> None:
    modules = fresh_bridge_import(["self_test", "wazuh_hardening"])
    self_test = modules["self_test"]
    wazuh_hardening = modules["wazuh_hardening"]

    async def fake_collect_status() -> dict[str, object]:
        return {
            "status": "warn",
            "summary_zh": "尚未套用。",
            "next_step_zh": "執行 setup-agent-groups.sh。",
            "groups_present": ["default", "linux", "macos", "windows"],
            "missing_groups": [],
            "agents_checked": 1,
            "agents_missing_group": [
                {
                    "id": "003",
                    "name": "boss-macbook",
                    "expected_group": "macos",
                    "groups": ["default"],
                }
            ],
            "recipe_files_present": True,
        }

    monkeypatch.setattr(wazuh_hardening, "collect_status", fake_collect_status)
    check = asyncio.run(self_test._check_wazuh_hardening())

    assert check["id"] == "wazuh_hardening"
    assert check["status"] == "warn"
    assert check["required"] is False
    assert "missing_groups=none" in check["detail_zh"]
    assert "003:boss-macbook->macos" in check["detail_zh"]


@pytest.mark.unit
def test_module_event_flow_summarizes_recent_hardening_modules(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("DB_PATH", str(tmp_path / "alerts.db"))
    db = fresh_bridge_import(["db"])["db"]
    db.init_db_sync()

    db._save_alert_sync(
        {
            "rule": {"id": "5902", "groups": ["syscheck"], "description": "File modified"},
            "agent": {"name": "linux-01"},
            "data": {"syscheck": {"path": "/etc/passwd"}},
        },
        "{}",
        {"severity": "medium"},
        1,
        None,
    )
    db._save_alert_sync(
        {
            "rule": {"id": "19007", "groups": ["sca"], "description": "CIS check failed"},
            "agent": {"name": "linux-01"},
            "data": {"sca": {"check": "ssh root login disabled"}},
        },
        "{}",
        {"severity": "low"},
        1,
        None,
    )
    db._save_alert_sync(
        {
            "rule": {"id": "61603", "groups": ["sysmon"], "description": "Sysmon process event"},
            "agent": {"name": "win-01"},
            "data": {"win": {"system": {"channel": "Microsoft-Windows-Sysmon/Operational"}}},
        },
        "{}",
        {"severity": "medium"},
        1,
        None,
    )

    flow = db._module_event_flow_sync(days=7)

    assert flow["total"] == 3
    assert flow["modules"]["fim"]["count"] == 1
    assert flow["modules"]["sca"]["count"] == 1
    assert flow["modules"]["sysmon"]["count"] == 1
    assert {"fim", "sca", "sysmon"}.issubset(set(flow["observed_expected"]))


@pytest.mark.unit
def test_module_event_flow_excludes_sampledata_by_default(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("DB_PATH", str(tmp_path / "alerts.db"))
    db = fresh_bridge_import(["db"])["db"]
    db.init_db_sync()

    db._save_alert_sync(
        {
            "@sampledata": True,
            "rule": {"id": "19007", "groups": ["sca"], "description": "CIS check failed"},
            "agent": {"name": "demo"},
            "data": {"sca": {"check": "demo"}},
        },
        "{}",
        {"severity": "low"},
        1,
        None,
    )

    assert db._module_event_flow_sync(days=7)["total"] == 0
    assert db._module_event_flow_sync(days=7, include_sampledata=True)["total"] == 1


@pytest.mark.unit
def test_self_test_module_flow_is_non_required_and_honest(monkeypatch) -> None:
    modules = fresh_bridge_import(["self_test", "db"])
    self_test = modules["self_test"]
    db = modules["db"]

    async def fake_module_event_flow(days: int = 7, include_sampledata: bool = False) -> dict[str, object]:
        assert days == 3
        return {
            "total": 2,
            "rows_scanned": 2,
            "observed": ["authentication"],
            "observed_expected": [],
            "missing_expected": ["fim", "sca"],
            "labels_zh": {"authentication": "登入/認證", "fim": "FIM 檔案異動", "sca": "SCA 組態稽核"},
        }

    monkeypatch.setenv("WAZUH_MODULE_FLOW_DAYS", "3")
    monkeypatch.setattr(db, "module_event_flow", fake_module_event_flow)

    check = asyncio.run(self_test._check_wazuh_module_flow())

    assert check["id"] == "wazuh_module_flow"
    assert check["status"] == "warn"
    assert check["required"] is False
    assert "尚未看到強化模組事件流" in check["summary_zh"]
    assert "不等於每個偵測模組" in check["detail_zh"]
