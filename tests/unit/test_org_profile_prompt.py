from __future__ import annotations

import pytest

from support import fresh_bridge_import


@pytest.mark.unit
def test_business_context_includes_asset_owner_and_notes(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.setenv("ORG_PROFILE_PATH", str(tmp_path / "org_profile.yaml"))
    modules = fresh_bridge_import(["org_profile", "prompting"])
    org_profile = modules["org_profile"]
    prompting = modules["prompting"]

    org_profile.upsert_asset(
        "boss-mac",
        {
            "role": "管理者筆電",
            "owner": "Titan",
            "criticality": "critical",
            "business_hours": "Daily 09:00-21:00 Asia/Taipei",
            "notes": "處理公司帳務與管理後台",
        },
    )

    prompt, _, _ = prompting.build_prompt(
        {
            "timestamp": "2026-05-21T01:00:00Z",
            "agent": {"name": "boss-mac"},
            "rule": {"id": "5712", "level": 10, "description": "sshd brute force"},
            "full_log": "Failed password for admin from 198.51.100.42",
            "data": {"srcip": "198.51.100.42", "dstuser": "admin"},
        }
    )

    assert "BUSINESS CONTEXT (from organization profile):" in prompt
    assert "Asset role:    管理者筆電" in prompt
    assert "Asset owner:   Titan" in prompt
    assert "Criticality:   critical" in prompt
    assert "Asset notes:   處理公司帳務與管理後台" in prompt
