"""SQLite persistence for EdgeSec-Pi.

Every SIEM alert that reaches the bridge — whether the LLM analysis
succeeds or fails — gets a row in `alerts.db`. Schema is denormalised on
purpose: a row contains both SIEM-side metadata (rule id/level, agent,
raw log) and Gemma-side verdict (severity, root cause, IOCs, action,
MITRE, latency). The full original alert JSON is kept in `raw_alert`
for forensics.

Why sqlite3 + `asyncio.to_thread` instead of aiosqlite?
  - Zero extra dependencies.
  - SOC alert volume is tiny (10s–100s/min worst case).
  - WAL journaling lets concurrent readers (e.g. the dashboard widget)
    while a writer is active.

Public API:
  init_db()                — call once on startup
  save_alert(...)          — async insert (called from worker)
  list_alerts(...)         — async query for /alerts endpoint
  compute_stats()          — async aggregate for /stats endpoint
"""
from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any

DB_PATH = Path(os.getenv("DB_PATH", "data/alerts.db")).resolve()


# ─── connection helper ─────────────────────────────────────────────────
def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), timeout=10.0)
    conn.execute("PRAGMA journal_mode=WAL")     # concurrent reads while writing
    conn.execute("PRAGMA synchronous=NORMAL")   # ~10x faster, durable enough for alerts
    conn.row_factory = sqlite3.Row
    return conn


# ─── schema ─────────────────────────────────────────────────────────────
_SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    received_at      REAL    NOT NULL,                  -- unix epoch (float)
    rule_id          TEXT,
    rule_level       INTEGER,
    rule_description TEXT,
    siem_source      TEXT    NOT NULL DEFAULT 'wazuh',
    agent_id         TEXT,
    agent_name       TEXT,
    agent_ip         TEXT,
    full_log         TEXT,
    -- Gemma's structured verdict (NULL if LLM call failed):
    llm_status       TEXT    NOT NULL DEFAULT 'pending', -- 'ok' | 'error'
    llm_severity     TEXT,                                -- critical|high|medium|low|info
    llm_root_cause   TEXT,
    llm_action       TEXT,
    llm_iocs         TEXT,                                -- JSON array
    llm_mitre        TEXT,
    llm_raw_reply    TEXT,
    llm_latency_ms   INTEGER,
    llm_error        TEXT,
    case_status      TEXT    NOT NULL DEFAULT 'open',
    case_note        TEXT,
    case_actor       TEXT,
    case_updated_at  REAL,
    raw_alert        TEXT    NOT NULL                     -- full normalized alert JSON
);
CREATE INDEX IF NOT EXISTS idx_alerts_received ON alerts (received_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_rule     ON alerts (rule_id);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (llm_severity);
CREATE INDEX IF NOT EXISTS idx_alerts_agent    ON alerts (agent_name);
"""


def init_db_sync() -> None:
    with _connect() as conn:
        conn.executescript(_SCHEMA)
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(alerts)")}
        if "siem_source" not in columns:
            conn.execute("ALTER TABLE alerts ADD COLUMN siem_source TEXT NOT NULL DEFAULT 'wazuh'")
        if "case_status" not in columns:
            conn.execute("ALTER TABLE alerts ADD COLUMN case_status TEXT NOT NULL DEFAULT 'open'")
        if "case_note" not in columns:
            conn.execute("ALTER TABLE alerts ADD COLUMN case_note TEXT")
        if "case_actor" not in columns:
            conn.execute("ALTER TABLE alerts ADD COLUMN case_actor TEXT")
        if "case_updated_at" not in columns:
            conn.execute("ALTER TABLE alerts ADD COLUMN case_updated_at REAL")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_siem ON alerts (siem_source)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_case ON alerts (case_status)")


# ─── INSERT ─────────────────────────────────────────────────────────────
def _save_alert_sync(alert: dict[str, Any],
                     llm_reply: str,
                     parsed: dict[str, Any] | None,
                     latency_ms: int,
                     error: str | None) -> int:
    rule  = alert.get("rule")  or {}
    agent = alert.get("agent") or {}
    meta  = alert.get("_edgesec") or {}
    p     = parsed or {}
    iocs  = p.get("iocs") or []

    with _connect() as conn:
        cur = conn.execute(
            """
            INSERT INTO alerts (
                received_at, rule_id, rule_level, rule_description, siem_source,
                agent_id, agent_name, agent_ip, full_log,
                llm_status, llm_severity, llm_root_cause, llm_action,
                llm_iocs, llm_mitre, llm_raw_reply, llm_latency_ms, llm_error,
                raw_alert
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                time.time(),
                str(rule.get("id")) if rule.get("id") is not None else None,
                rule.get("level"),
                rule.get("description"),
                meta.get("siem_source") or "wazuh",
                agent.get("id"),
                agent.get("name"),
                agent.get("ip"),
                alert.get("full_log"),
                "error" if error else "ok",
                (p.get("severity") or "").lower() or None,
                p.get("root_cause"),
                p.get("action"),
                json.dumps(iocs, ensure_ascii=False) if iocs else None,
                p.get("mitre"),
                llm_reply or None,
                latency_ms,
                error,
                json.dumps(alert, ensure_ascii=False),
            ),
        )
        return int(cur.lastrowid or 0)


# ─── queries ────────────────────────────────────────────────────────────
_LIST_COLUMNS = (
    "id, received_at, rule_id, rule_level, rule_description, "
    "siem_source, agent_name, agent_ip, llm_status, llm_severity, llm_root_cause, "
    "llm_action, llm_iocs, llm_mitre, llm_latency_ms, llm_error, full_log, "
    "case_status, case_note, case_actor, case_updated_at, "
    "raw_alert"
)

_NOT_SAMPLEDATA_SQL = (
    "COALESCE(json_extract(raw_alert, '$.\"@sampledata\"'), 0) != 1 "
    "AND COALESCE(json_extract(raw_alert, '$._edgesec.sampledata'), 0) != 1"
)


def _list_alerts_sync(limit: int, severity: str | None,
                      rule_id: str | None,
                      agent_name: str | None = None,
                      active_only: bool = False,
                      include_sampledata: bool = False) -> list[dict[str, Any]]:
    where, args = [], []
    if severity:
        where.append("llm_severity = ?")
        args.append(severity.lower())
    if rule_id:
        where.append("rule_id = ?")
        args.append(rule_id)
    if agent_name:
        where.append("agent_name = ?")
        args.append(agent_name)
    if active_only:
        where.append("case_status IN ('open', 'in_progress')")
    if not include_sampledata:
        where.append(_NOT_SAMPLEDATA_SQL)
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    args.append(int(limit))
    with _connect() as conn:
        cur = conn.execute(
            f"SELECT {_LIST_COLUMNS} FROM alerts {where_sql} "
            f"ORDER BY received_at DESC LIMIT ?",
            args,
        )
        rows = [dict(r) for r in cur.fetchall()]
    # Re-hydrate iocs JSON for caller convenience.
    for r in rows:
        if r.get("llm_iocs"):
            try:
                r["llm_iocs"] = json.loads(r["llm_iocs"])
            except json.JSONDecodeError:
                pass
    return rows


_ALLOWED_CASE_STATUSES = {"open", "in_progress", "normal", "resolved", "false_positive"}


def _update_alert_case_sync(alert_id: int,
                            status: str,
                            note: str = "",
                            actor: str = "dashboard") -> bool:
    normalized = str(status or "").strip().lower()
    if normalized not in _ALLOWED_CASE_STATUSES:
        raise ValueError(f"unsupported case status: {status}")

    with _connect() as conn:
        cur = conn.execute(
            """
            UPDATE alerts
               SET case_status = ?,
                   case_note = ?,
                   case_actor = ?,
                   case_updated_at = ?
             WHERE id = ?
            """,
            (
                normalized,
                str(note or "").strip() or None,
                str(actor or "dashboard").strip() or "dashboard",
                time.time(),
                int(alert_id),
            ),
        )
        return cur.rowcount > 0


def _update_alert_cases_sync(alert_ids: list[int],
                             status: str,
                             note: str = "",
                             actor: str = "dashboard") -> int:
    normalized = str(status or "").strip().lower()
    if normalized not in _ALLOWED_CASE_STATUSES:
        raise ValueError(f"unsupported case status: {status}")

    ids = [int(alert_id) for alert_id in alert_ids if int(alert_id) > 0]
    if not ids:
        return 0

    placeholders = ",".join("?" for _ in ids)
    args: list[Any] = [
        normalized,
        str(note or "").strip() or None,
        str(actor or "dashboard").strip() or "dashboard",
        time.time(),
        *ids,
    ]
    with _connect() as conn:
        cur = conn.execute(
            f"""
            UPDATE alerts
               SET case_status = ?,
                   case_note = ?,
                   case_actor = ?,
                   case_updated_at = ?
             WHERE id IN ({placeholders})
            """,
            args,
        )
        return cur.rowcount


# ─── correlation: find related recent alerts ────────────────────────────
def _fetch_correlation_context_sync(srcip: str | None,
                                    agent_name: str | None,
                                    window_seconds: int,
                                    limit: int) -> list[dict[str, Any]]:
    """Return recent alerts that share a source IP or agent with the current one.

    Uses json_extract on the stored raw_alert so we don't need a schema
    migration to surface srcip. Cheap at SMB volume (10s-100s alerts/min,
    rows under a few hundred thousand).
    """
    if not srcip and not agent_name:
        return []

    where_parts: list[str] = []
    args: list[Any] = []
    if srcip:
        where_parts.append("json_extract(raw_alert, '$.data.srcip') = ?")
        args.append(srcip)
    if agent_name:
        where_parts.append("agent_name = ?")
        args.append(agent_name)
    where_sql = "(" + " OR ".join(where_parts) + ")"
    args.extend([int(window_seconds), int(limit)])

    with _connect() as conn:
        cur = conn.execute(
            f"""
            SELECT id, received_at, rule_id, rule_level, rule_description,
                   agent_name, llm_severity, llm_mitre,
                   json_extract(raw_alert, '$.data.srcip') AS srcip
            FROM alerts
            WHERE {where_sql}
              AND received_at > strftime('%s','now') - ?
            ORDER BY received_at DESC
            LIMIT ?
            """,
            args,
        )
        return [dict(r) for r in cur.fetchall()]


def _compute_stats_sync() -> dict[str, Any]:
    with _connect() as conn:
        total = conn.execute(
            f"SELECT COUNT(*) FROM alerts WHERE {_NOT_SAMPLEDATA_SQL}"
        ).fetchone()[0]

        last_24h = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE "
            f"{_NOT_SAMPLEDATA_SQL} "
            "AND received_at > strftime('%s','now') - 86400"
        ).fetchone()[0]

        cur = conn.execute(
            "SELECT COALESCE(llm_severity, 'unclassified') AS s, COUNT(*) AS c "
            "FROM alerts WHERE "
            f"{_NOT_SAMPLEDATA_SQL} "
            "AND received_at > strftime('%s','now') - 86400 "
            "GROUP BY s"
        )
        by_severity_24h = {row["s"]: row["c"] for row in cur.fetchall()}

        cur = conn.execute(
            "SELECT COALESCE(llm_severity, 'unclassified') AS s, COUNT(*) AS c "
            "FROM alerts WHERE "
            f"{_NOT_SAMPLEDATA_SQL} "
            "AND received_at > strftime('%s','now') - 86400 "
            "AND case_status IN ('open', 'in_progress') "
            "GROUP BY s"
        )
        open_by_severity_24h = {row["s"]: row["c"] for row in cur.fetchall()}

        open_cases_24h = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE "
            f"{_NOT_SAMPLEDATA_SQL} "
            "AND received_at > strftime('%s','now') - 86400 "
            "AND case_status IN ('open', 'in_progress')"
        ).fetchone()[0]

        closed_cases_24h = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE "
            f"{_NOT_SAMPLEDATA_SQL} "
            "AND received_at > strftime('%s','now') - 86400 "
            "AND case_status NOT IN ('open', 'in_progress')"
        ).fetchone()[0]

        cur = conn.execute(
            "SELECT AVG(llm_latency_ms) FROM "
            "(SELECT llm_latency_ms FROM alerts "
            f" WHERE llm_status='ok' AND {_NOT_SAMPLEDATA_SQL} "
            " ORDER BY received_at DESC LIMIT 100)"
        )
        avg_lat = cur.fetchone()[0]

        cur = conn.execute(
            "SELECT rule_id, rule_description, COUNT(*) AS c FROM alerts "
            "WHERE "
            f"{_NOT_SAMPLEDATA_SQL} "
            "AND received_at > strftime('%s','now') - 86400 "
            "GROUP BY rule_id ORDER BY c DESC LIMIT 5"
        )
        top_rules = [dict(row) for row in cur.fetchall()]

        errors_24h = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE "
            f"{_NOT_SAMPLEDATA_SQL} "
            "AND received_at > strftime('%s','now') - 86400 "
            "AND llm_status = 'error'"
        ).fetchone()[0]

    return {
        "total_alerts":        total,
        "alerts_last_24h":     last_24h,
        "errors_last_24h":     errors_24h,
        "by_severity_24h":     by_severity_24h,
        "open_by_severity_24h": open_by_severity_24h,
        "open_cases_24h":      open_cases_24h,
        "closed_cases_24h":    closed_cases_24h,
        "top_rules_24h":       top_rules,
        "avg_llm_latency_ms":  int(avg_lat) if avg_lat else None,
    }


# ─── async wrappers ─────────────────────────────────────────────────────
async def init_db() -> None:
    await asyncio.to_thread(init_db_sync)


async def save_alert(alert: dict[str, Any],
                     llm_reply: str,
                     parsed: dict[str, Any] | None,
                     latency_ms: int,
                     error: str | None) -> int:
    return await asyncio.to_thread(
        _save_alert_sync, alert, llm_reply, parsed, latency_ms, error
    )


async def list_alerts(limit: int = 50,
                      severity: str | None = None,
                      rule_id: str | None = None,
                      agent_name: str | None = None,
                      active_only: bool = False,
                      include_sampledata: bool = False) -> list[dict[str, Any]]:
    return await asyncio.to_thread(
        _list_alerts_sync, limit, severity, rule_id, agent_name, active_only, include_sampledata
    )


async def compute_stats() -> dict[str, Any]:
    return await asyncio.to_thread(_compute_stats_sync)


async def update_alert_case(alert_id: int,
                            status: str,
                            note: str = "",
                            actor: str = "dashboard") -> bool:
    return await asyncio.to_thread(
        _update_alert_case_sync, alert_id, status, note, actor
    )


async def update_alert_cases(alert_ids: list[int],
                             status: str,
                             note: str = "",
                             actor: str = "dashboard") -> int:
    return await asyncio.to_thread(
        _update_alert_cases_sync, alert_ids, status, note, actor
    )


async def fetch_correlation_context(srcip: str | None,
                                    agent_name: str | None,
                                    window_seconds: int = 3600,
                                    limit: int = 10) -> list[dict[str, Any]]:
    """Async wrapper around correlation lookup. Returns recent related alerts."""
    return await asyncio.to_thread(
        _fetch_correlation_context_sync, srcip, agent_name, window_seconds, limit
    )
