from __future__ import annotations

import sqlite3

import pytest

from support import fresh_bridge_import


@pytest.mark.unit
def test_alert_case_status_hides_closed_items_from_active_list(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.setenv("DB_PATH", str(tmp_path / "alerts.db"))
    db = fresh_bridge_import(["db"])["db"]
    db.init_db_sync()

    alert_id = db._save_alert_sync(
        {
            "rule": {"id": "5712", "level": 10, "description": "SSH brute force"},
            "agent": {"name": "PC001", "ip": "192.0.2.10"},
            "full_log": "Failed password",
        },
        "{}",
        {"severity": "high", "iocs": ["198.51.100.42"]},
        42,
        None,
    )

    active_rows = db._list_alerts_sync(10, "high", None, active_only=True)
    assert [row["id"] for row in active_rows] == [alert_id]
    assert active_rows[0]["case_status"] == "open"

    assert db._update_alert_case_sync(alert_id, "in_progress", actor="test") is True
    active_rows = db._list_alerts_sync(10, "high", None, active_only=True)
    assert active_rows[0]["case_status"] == "in_progress"

    assert db._update_alert_case_sync(alert_id, "resolved", "done", "test") is True
    assert db._list_alerts_sync(10, "high", None, active_only=True) == []

    all_rows = db._list_alerts_sync(10, "high", None)
    assert all_rows[0]["case_status"] == "resolved"
    assert all_rows[0]["case_note"] == "done"


@pytest.mark.unit
def test_stats_separate_open_and_closed_alerts(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.setenv("DB_PATH", str(tmp_path / "alerts.db"))
    db = fresh_bridge_import(["db"])["db"]
    db.init_db_sync()

    closed_id = db._save_alert_sync(
        {"rule": {"id": "1"}, "agent": {"name": "PC001"}},
        "{}",
        {"severity": "high"},
        1,
        None,
    )
    db._save_alert_sync(
        {"rule": {"id": "2"}, "agent": {"name": "PC002"}},
        "{}",
        {"severity": "medium"},
        1,
        None,
    )
    db._update_alert_case_sync(closed_id, "false_positive", actor="test")

    stats = db._compute_stats_sync()
    assert stats["by_severity_24h"]["high"] == 1
    assert stats["by_severity_24h"]["medium"] == 1
    assert stats["open_by_severity_24h"] == {"medium": 1}
    assert stats["open_cases_24h"] == 1
    assert stats["closed_cases_24h"] == 1


@pytest.mark.unit
def test_existing_database_migrates_case_columns(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    db_path = tmp_path / "legacy-alerts.db"
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            """
            CREATE TABLE alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                received_at REAL NOT NULL,
                rule_id TEXT,
                rule_level INTEGER,
                rule_description TEXT,
                siem_source TEXT NOT NULL DEFAULT 'wazuh',
                agent_id TEXT,
                agent_name TEXT,
                agent_ip TEXT,
                full_log TEXT,
                llm_status TEXT NOT NULL DEFAULT 'pending',
                llm_severity TEXT,
                llm_root_cause TEXT,
                llm_action TEXT,
                llm_iocs TEXT,
                llm_mitre TEXT,
                llm_raw_reply TEXT,
                llm_latency_ms INTEGER,
                llm_error TEXT,
                raw_alert TEXT NOT NULL
            )
            """
        )

    monkeypatch.setenv("DB_PATH", str(db_path))
    db = fresh_bridge_import(["db"])["db"]
    db.init_db_sync()

    with sqlite3.connect(str(db_path)) as conn:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(alerts)")}
        indexes = {row[1] for row in conn.execute("PRAGMA index_list(alerts)")}

    assert {"case_status", "case_note", "case_actor", "case_updated_at"} <= columns
    assert "idx_alerts_case" in indexes
