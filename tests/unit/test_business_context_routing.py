from __future__ import annotations

import pytest

from support import fresh_bridge_import


def _alert(
    agent: str,
    level: int = 8,
    groups: list[str] | None = None,
    timestamp: str = "2026-05-21T01:00:00Z",
) -> dict:
    return {
        "timestamp": timestamp,
        "rule": {"id": "5712", "level": level, "description": "auth anomaly", "groups": groups or ["syslog"]},
        "agent": {"name": agent},
        "full_log": "Failed password for admin from 198.51.100.42",
        "data": {"srcip": "198.51.100.42", "dstuser": "admin"},
    }


@pytest.mark.unit
def test_critical_asset_forces_agentic_investigation(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.setenv("ORG_PROFILE_PATH", str(tmp_path / "org_profile.yaml"))
    monkeypatch.setenv("AGENTIC_FORCE_LEVEL_GTE", "12")
    monkeypatch.setenv("AGENTIC_NEVER_GROUPS", "sca,ossec")
    monkeypatch.setenv("AGENTIC_BUSINESS_CONTEXT", "true")
    monkeypatch.setenv("AGENTIC_BUSINESS_MIN_LEVEL", "8")
    modules = fresh_bridge_import(["org_profile", "triage_router"])
    org_profile = modules["org_profile"]
    triage_router = modules["triage_router"]

    org_profile.upsert_asset(
        "finance-mac",
        {
            "role": "財務主管筆電",
            "owner": "Alice",
            "criticality": "critical",
            "business_hours": "Mon-Fri 09:00-19:00 Asia/Taipei",
        },
    )

    assert triage_router.decide(_alert("finance-mac", level=8)) == "agentic"


@pytest.mark.unit
def test_never_group_still_skips_business_upgrade(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.setenv("ORG_PROFILE_PATH", str(tmp_path / "org_profile.yaml"))
    monkeypatch.setenv("AGENTIC_FORCE_LEVEL_GTE", "12")
    monkeypatch.setenv("AGENTIC_NEVER_GROUPS", "sca,ossec")
    monkeypatch.setenv("AGENTIC_BUSINESS_CONTEXT", "true")
    modules = fresh_bridge_import(["org_profile", "triage_router"])
    org_profile = modules["org_profile"]
    triage_router = modules["triage_router"]

    org_profile.upsert_asset(
        "finance-mac",
        {"role": "財務主管筆電", "criticality": "critical"},
    )

    assert triage_router.decide(_alert("finance-mac", level=10, groups=["sca"])) == "quick"


@pytest.mark.unit
def test_off_hours_can_force_agentic_below_critical_threshold(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.setenv("ORG_PROFILE_PATH", str(tmp_path / "org_profile.yaml"))
    monkeypatch.setenv("AGENTIC_FORCE_LEVEL_GTE", "12")
    monkeypatch.setenv("AGENTIC_BUSINESS_MIN_LEVEL", "8")
    monkeypatch.setenv("AGENTIC_BUSINESS_OFFHOURS_MIN_LEVEL", "6")
    modules = fresh_bridge_import(["org_profile", "triage_router"])
    org_profile = modules["org_profile"]
    triage_router = modules["triage_router"]

    org_profile.upsert_asset(
        "backoffice-pc",
        {
            "role": "後台作業電腦",
            "criticality": "medium",
            "business_hours": "Mon-Fri 09:00-19:00 Asia/Taipei",
        },
    )

    assert triage_router.decide(
        _alert("backoffice-pc", level=6, timestamp="2026-05-20T20:00:00Z")
    ) == "agentic"
