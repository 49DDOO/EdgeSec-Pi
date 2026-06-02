from __future__ import annotations

import asyncio
import sqlite3
import time

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
def test_update_alert_cases_marks_repeated_event_group(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.setenv("DB_PATH", str(tmp_path / "alerts.db"))
    db = fresh_bridge_import(["db"])["db"]
    db.init_db_sync()

    ids = [
        db._save_alert_sync(
            {"rule": {"id": "5712"}, "agent": {"name": "PC001"}},
            "{}",
            {"severity": "high"},
            1,
            None,
        )
        for _ in range(3)
    ]

    changed = db._update_alert_cases_sync(ids, "resolved", "same incident", "test")

    assert changed == 3
    assert db._list_alerts_sync(10, "high", None, active_only=True) == []
    rows = db._list_alerts_sync(10, "high", None)
    assert {row["case_status"] for row in rows} == {"resolved"}
    assert {row["case_note"] for row in rows} == {"same incident"}


@pytest.mark.unit
def test_false_positive_status_creates_scoped_suppression(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("DB_PATH", str(tmp_path / "alerts.db"))
    monkeypatch.setenv("FALSE_POSITIVE_SUPPRESSION_ENABLED", "1")
    monkeypatch.setenv("FALSE_POSITIVE_SUPPRESSION_TTL_S", "604800")
    db = fresh_bridge_import(["db"])["db"]
    db.init_db_sync()

    alert = {
        "rule": {"id": "5712", "level": 10, "description": "SSH brute force"},
        "agent": {"name": "web-prod", "ip": "192.0.2.10"},
        "data": {"srcip": "203.0.113.45"},
        "full_log": "Failed password for admin from 203.0.113.45",
    }
    alert_id = db._save_alert_sync(alert, "{}", {"severity": "high"}, 1, None)

    assert db._update_alert_case_sync(alert_id, "false_positive", "lab noise", "test") is True

    suppressions = db._list_false_positive_suppressions_sync()
    assert len(suppressions) == 1
    suppression = suppressions[0]
    assert suppression["rule_id"] == "5712"
    assert suppression["agent_name"] == "web-prod"
    assert suppression["source_ip"] == "203.0.113.45"
    assert suppression["actor"] == "test"
    assert suppression["reason"] == "lab noise"

    assert db._match_false_positive_suppression_sync(alert)["id"] == suppression["id"]
    assert db._match_false_positive_suppression_sync(
        {
            "rule": {"id": "5712", "level": 10},
            "agent": {"name": "web-prod"},
            "data": {"srcip": "198.51.100.99"},
        }
    ) is None
    assert db._match_false_positive_suppression_sync(
        {
            "rule": {"id": "5712", "level": 10},
            "agent": {"name": "db-prod"},
            "data": {"srcip": "203.0.113.45"},
        }
    ) is None

    assert db._disable_false_positive_suppression_sync(suppression["id"]) is True
    assert db._disable_false_positive_suppression_sync(suppression["id"]) is False
    assert db._match_false_positive_suppression_sync(alert) is None


@pytest.mark.unit
def test_false_positive_suppression_respects_disabled_and_sampledata_guards(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("DB_PATH", str(tmp_path / "alerts.db"))
    monkeypatch.setenv("FALSE_POSITIVE_SUPPRESSION_ENABLED", "0")
    db = fresh_bridge_import(["db"])["db"]
    db.init_db_sync()

    alert = {
        "rule": {"id": "5712", "level": 10, "description": "SSH brute force"},
        "agent": {"name": "web-prod", "ip": "192.0.2.10"},
        "data": {"srcip": "203.0.113.45"},
        "full_log": "Failed password for admin from 203.0.113.45",
    }
    disabled_id = db._save_alert_sync(alert, "{}", {"severity": "high"}, 1, None)
    assert db._update_alert_case_sync(disabled_id, "false_positive", "disabled", "test")
    assert db._list_false_positive_suppressions_sync(include_expired=True) == []
    assert db._match_false_positive_suppression_sync(alert) is None

    monkeypatch.setenv("FALSE_POSITIVE_SUPPRESSION_ENABLED", "1")
    sample_alert = {
        **alert,
        "@sampledata": True,
        "_edgesec": {"sampledata": True},
    }
    sample_id = db._save_alert_sync(sample_alert, "{}", {"severity": "high"}, 1, None)
    assert db._update_alert_case_sync(sample_id, "false_positive", "sample", "test")
    assert db._list_false_positive_suppressions_sync(include_expired=True) == []
    assert db._match_false_positive_suppression_sync(sample_alert) is None


@pytest.mark.unit
def test_expired_false_positive_suppression_is_not_matched(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("DB_PATH", str(tmp_path / "alerts.db"))
    monkeypatch.setenv("FALSE_POSITIVE_SUPPRESSION_ENABLED", "1")
    db = fresh_bridge_import(["db"])["db"]
    db.init_db_sync()

    alert = {
        "rule": {"id": "5712", "level": 10, "description": "SSH brute force"},
        "agent": {"name": "web-prod", "ip": "192.0.2.10"},
        "data": {"srcip": "203.0.113.45"},
        "full_log": "Failed password for admin from 203.0.113.45",
    }
    alert_id = db._save_alert_sync(alert, "{}", {"severity": "high"}, 1, None)
    assert db._update_alert_case_sync(alert_id, "false_positive", "lab noise", "test")
    suppression = db._list_false_positive_suppressions_sync()[0]

    with db._connect() as conn:
        conn.execute(
            "UPDATE false_positive_suppressions SET expires_at = ? WHERE id = ?",
            (time.time() - 1, int(suppression["id"])),
        )

    assert db._match_false_positive_suppression_sync(alert) is None
    assert db._list_false_positive_suppressions_sync() == []
    expired = db._list_false_positive_suppressions_sync(include_expired=True)
    assert len(expired) == 1
    assert expired[0]["id"] == suppression["id"]


@pytest.mark.unit
def test_analyze_auto_archives_false_positive_suppression_without_llm_or_slack(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("DB_PATH", str(tmp_path / "alerts.db"))
    monkeypatch.setenv("FALSE_POSITIVE_SUPPRESSION_ENABLED", "1")
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "")
    monkeypatch.setenv("SLACK_BOT_TOKEN", "")
    monkeypatch.setenv("SLACK_APP_TOKEN", "")
    monkeypatch.setenv("SLACK_CHANNEL_ID", "")
    modules = fresh_bridge_import(["app", "db"])
    app = modules["app"]
    db = modules["db"]
    db.init_db_sync()

    seed_alert = {
        "rule": {"id": "5712", "level": 10, "description": "SSH brute force"},
        "agent": {"name": "web-prod", "ip": "192.0.2.10"},
        "data": {"srcip": "203.0.113.45"},
        "full_log": "Failed password for admin from 203.0.113.45",
    }
    seed_id = db._save_alert_sync(seed_alert, "{}", {"severity": "high"}, 1, None)
    assert db._update_alert_case_sync(seed_id, "false_positive", "scanner lab", "test")

    async def fail_chat_completion(*args, **kwargs):
        raise AssertionError("LLM should not be called for suppressed false positives")

    async def fail_slack(*args, **kwargs):
        raise AssertionError("Slack should not be notified for suppressed false positives")

    monkeypatch.setattr(app.llm_client, "chat_completion", fail_chat_completion)
    monkeypatch.setattr(app.slack_render, "send_to_slack", fail_slack)

    asyncio.run(app.analyze(dict(seed_alert), None, 7))

    rows = db._list_alerts_sync(10, None, "5712")
    latest = rows[0]
    assert latest["id"] != seed_id
    assert latest["llm_status"] == "skipped"
    assert latest["llm_severity"] == "info"
    assert latest["case_status"] == "false_positive"
    assert latest["case_actor"] == "fp-suppression"
    assert "auto-suppressed by false-positive rule" in latest["case_note"]
    assert "false-positive suppression matched" in latest["llm_root_cause"]


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
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        fp_indexes = {
            row[1]
            for row in conn.execute("PRAGMA index_list(false_positive_suppressions)")
        }

    assert {"case_status", "case_note", "case_actor", "case_updated_at", "canonical_signal"} <= columns
    assert "idx_alerts_case" in indexes
    assert "false_positive_suppressions" in tables
    assert "idx_fp_suppression_match" in fp_indexes
