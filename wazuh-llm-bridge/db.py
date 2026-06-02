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

import canonical_signal

DB_PATH = Path(os.getenv("DB_PATH", "data/alerts.db")).resolve()
DEFAULT_FP_SUPPRESSION_TTL_S = 7 * 24 * 3600


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
    llm_status       TEXT    NOT NULL DEFAULT 'pending', -- 'ok' | 'error' | 'skipped'
    llm_severity     TEXT,                                -- critical|high|medium|low|info
    llm_root_cause   TEXT,
    llm_action       TEXT,
    llm_iocs         TEXT,                                -- JSON array
    llm_mitre        TEXT,
    -- 白話繁中欄位：直接落地，避免每次都重新 parse llm_raw_reply
    llm_summary_zh        TEXT,
    llm_impact_zh         TEXT,
    llm_next_step_zh      TEXT,
    llm_investigation_zh  TEXT,                            -- MDR 調查說明（無調查時為 NULL）
    llm_raw_reply    TEXT,
    llm_latency_ms   INTEGER,
    llm_error        TEXT,
    case_status      TEXT    NOT NULL DEFAULT 'open',
    case_note        TEXT,
    case_actor       TEXT,
    case_updated_at  REAL,
    raw_alert        TEXT    NOT NULL,                    -- full normalized alert JSON
    canonical_signal TEXT                                 -- source-neutral signal JSON
);
CREATE INDEX IF NOT EXISTS idx_alerts_received ON alerts (received_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_rule     ON alerts (rule_id);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (llm_severity);
CREATE INDEX IF NOT EXISTS idx_alerts_agent    ON alerts (agent_name);

CREATE TABLE IF NOT EXISTS false_positive_suppressions (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at            REAL    NOT NULL,
    updated_at            REAL,
    expires_at            REAL    NOT NULL,
    rule_id               TEXT    NOT NULL,
    agent_name            TEXT    NOT NULL DEFAULT '',
    source_ip             TEXT    NOT NULL DEFAULT '',
    rule_description      TEXT,
    created_from_alert_id INTEGER,
    actor                 TEXT,
    reason                TEXT,
    hits                  INTEGER NOT NULL DEFAULT 0,
    last_hit_at           REAL,
    enabled               INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_fp_suppression_match
    ON false_positive_suppressions (enabled, rule_id, agent_name, source_ip, expires_at);
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
        for col in ("llm_summary_zh", "llm_impact_zh", "llm_next_step_zh", "llm_investigation_zh"):
            if col not in columns:
                conn.execute(f"ALTER TABLE alerts ADD COLUMN {col} TEXT")
        if "canonical_signal" not in columns:
            conn.execute("ALTER TABLE alerts ADD COLUMN canonical_signal TEXT")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_siem ON alerts (siem_source)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_case ON alerts (case_status)")
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_fp_suppression_match
            ON false_positive_suppressions (enabled, rule_id, agent_name, source_ip, expires_at)
            """
        )


# ─── INSERT ─────────────────────────────────────────────────────────────
def _save_alert_sync(alert: dict[str, Any],
                     llm_reply: str,
                     parsed: dict[str, Any] | None,
                     latency_ms: int,
                     error: str | None,
                     llm_status: str | None = None,
                     case_status: str = "open",
                     case_note: str = "",
                     case_actor: str = "") -> int:
    rule  = alert.get("rule")  or {}
    agent = alert.get("agent") or {}
    meta  = alert.get("_edgesec") or {}
    p     = parsed or {}
    iocs  = p.get("iocs") or []
    normalized_case_status = str(case_status or "open").strip().lower()
    if normalized_case_status not in _ALLOWED_CASE_STATUSES:
        normalized_case_status = "open"
    received_at = time.time()
    case_updated_at = received_at if normalized_case_status != "open" else None
    canonical = canonical_signal.safe_from_alert(alert, received_at=received_at)

    with _connect() as conn:
        cur = conn.execute(
            """
            INSERT INTO alerts (
                received_at, rule_id, rule_level, rule_description, siem_source,
                agent_id, agent_name, agent_ip, full_log,
                llm_status, llm_severity, llm_root_cause, llm_action,
                llm_iocs, llm_mitre,
                llm_summary_zh, llm_impact_zh, llm_next_step_zh, llm_investigation_zh,
                llm_raw_reply, llm_latency_ms, llm_error,
                case_status, case_note, case_actor, case_updated_at,
                raw_alert, canonical_signal
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                received_at,
                str(rule.get("id")) if rule.get("id") is not None else None,
                rule.get("level"),
                rule.get("description"),
                meta.get("siem_source") or "wazuh",
                agent.get("id"),
                agent.get("name"),
                agent.get("ip"),
                alert.get("full_log"),
                llm_status or ("error" if error else "ok"),
                (p.get("severity") or "").lower() or None,
                p.get("root_cause"),
                p.get("action"),
                json.dumps(iocs, ensure_ascii=False) if iocs else None,
                p.get("mitre"),
                p.get("summary_zh") or None,
                p.get("impact_zh") or None,
                p.get("next_step_zh") or None,
                p.get("investigation_summary_zh") or None,
                llm_reply or None,
                latency_ms,
                error,
                normalized_case_status,
                str(case_note or "").strip() or None,
                str(case_actor or "").strip() or None,
                case_updated_at,
                json.dumps(alert, ensure_ascii=False),
                json.dumps(canonical, ensure_ascii=False),
            ),
        )
        return int(cur.lastrowid or 0)


# ─── queries ────────────────────────────────────────────────────────────
_LIST_COLUMNS = (
    "id, received_at, rule_id, rule_level, rule_description, "
    "siem_source, agent_name, agent_ip, llm_status, llm_severity, llm_root_cause, "
    "llm_action, llm_iocs, llm_mitre, "
    "llm_summary_zh, llm_impact_zh, llm_next_step_zh, llm_investigation_zh, "
    "llm_latency_ms, llm_error, full_log, "
    "case_status, case_note, case_actor, case_updated_at, "
    "raw_alert, canonical_signal"
)

_NOT_SAMPLEDATA_SQL = (
    "COALESCE(json_extract(raw_alert, '$.\"@sampledata\"'), 0) != 1 "
    "AND COALESCE(json_extract(raw_alert, '$._edgesec.sampledata'), 0) != 1"
)

MODULE_EVENT_LABELS_ZH = {
    "authentication": "登入/認證",
    "fim": "FIM 檔案異動",
    "sca": "SCA 組態稽核",
    "sysmon": "Sysmon",
    "windows": "Windows 事件",
    "vulnerability": "弱點/CVE",
    "virustotal": "VirusTotal",
    "yara": "YARA",
    "rootcheck": "Rootcheck",
    "syscollector": "Syscollector",
    "other": "其他",
}
EXPECTED_HARDENING_EVENT_MODULES = (
    "fim",
    "sca",
    "sysmon",
    "vulnerability",
    "virustotal",
    "yara",
    "rootcheck",
    "syscollector",
)


def _env_bool(name: str, default: bool = True) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() not in {"0", "false", "no", "off"}


def fp_suppression_enabled() -> bool:
    return _env_bool("FALSE_POSITIVE_SUPPRESSION_ENABLED", True)


def fp_suppression_ttl_s() -> int:
    raw = os.getenv("FALSE_POSITIVE_SUPPRESSION_TTL_S", str(DEFAULT_FP_SUPPRESSION_TTL_S))
    try:
        ttl = int(str(raw).strip())
    except ValueError:
        ttl = DEFAULT_FP_SUPPRESSION_TTL_S
    return max(3600, min(ttl, 30 * 86400))


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _raw_alert_from_row(row: dict[str, Any]) -> dict[str, Any]:
    raw = row.get("raw_alert")
    if isinstance(raw, str) and raw:
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


def _is_sampledata_alert(alert: dict[str, Any]) -> bool:
    meta = _as_dict(alert.get("_edgesec"))
    return bool(alert.get("@sampledata") or meta.get("sampledata"))


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value in (None, ""):
        return []
    return [value]


def _event_module_from_alert(alert: dict[str, Any]) -> str:
    data = _as_dict(alert.get("data"))
    rule = _as_dict(alert.get("rule"))
    groups = {str(item).lower() for item in _as_list(rule.get("groups"))}
    description = _as_text(rule.get("description")).lower()
    full_log = _as_text(alert.get("full_log")).lower()
    win = _as_dict(data.get("win"))
    win_system = _as_dict(win.get("system"))
    channel = _as_text(win_system.get("channel")).lower()

    if _as_dict(data.get("sca")) or "sca" in groups or "cis" in description:
        return "sca"
    if "virustotal" in groups or "virus total" in description or "virustotal" in full_log:
        return "virustotal"
    if "yara" in groups or "yara" in description or "yara" in full_log:
        return "yara"
    if _as_dict(data.get("vulnerability")) or "vulnerability" in groups or "cve-" in full_log:
        return "vulnerability"
    if _as_dict(data.get("syscheck")) or {"syscheck", "fim"} & groups:
        return "fim"
    if "rootcheck" in groups or "rootkit" in description:
        return "rootcheck"
    if "sysmon" in groups or "sysmon" in channel or "sysmon" in description:
        return "sysmon"
    if _as_dict(data.get("win")) or "windows" in groups:
        return "windows"
    if any(key in groups for key in ("authentication_failed", "authentication_success", "sshd", "pam")):
        return "authentication"
    if "syscollector" in groups or any(key in description for key in ("netstat", "listening", "port", "network connection")):
        return "syscollector"
    if any(token in full_log for token in ("sshd", "failed password", "invalid user", "authentication failure", "sudo")):
        return "authentication"
    return "other"


def _source_ip_from_alert(alert: dict[str, Any]) -> str:
    data = _as_dict(alert.get("data"))
    for key in ("srcip", "src_ip", "source_ip", "source.ip", "clientip", "client_ip"):
        value = _as_text(data.get(key))
        if value:
            return value
    return ""


def _suppression_fields_from_alert(alert: dict[str, Any]) -> dict[str, str]:
    rule = _as_dict(alert.get("rule"))
    agent = _as_dict(alert.get("agent"))
    return {
        "rule_id": _as_text(rule.get("id")),
        "agent_name": _as_text(agent.get("name")),
        "source_ip": _source_ip_from_alert(alert),
        "rule_description": _as_text(rule.get("description")),
    }


def _create_false_positive_suppression_for_alert(
    conn: sqlite3.Connection,
    *,
    alert_id: int,
    alert: dict[str, Any],
    actor: str,
    reason: str,
) -> dict[str, Any] | None:
    if not fp_suppression_enabled() or _is_sampledata_alert(alert):
        return None

    fields = _suppression_fields_from_alert(alert)
    rule_id = fields["rule_id"]
    agent_name = fields["agent_name"]
    source_ip = fields["source_ip"]
    if not rule_id or not (agent_name or source_ip):
        return None

    now = time.time()
    expires_at = now + fp_suppression_ttl_s()
    row = conn.execute(
        """
        SELECT *
          FROM false_positive_suppressions
         WHERE rule_id = ?
           AND agent_name = ?
           AND source_ip = ?
           AND enabled = 1
         ORDER BY expires_at DESC
         LIMIT 1
        """,
        (rule_id, agent_name, source_ip),
    ).fetchone()
    if row:
        conn.execute(
            """
            UPDATE false_positive_suppressions
               SET updated_at = ?,
                   expires_at = ?,
                   rule_description = ?,
                   created_from_alert_id = ?,
                   actor = ?,
                   reason = ?,
                   enabled = 1
             WHERE id = ?
            """,
            (
                now,
                expires_at,
                fields["rule_description"] or None,
                int(alert_id),
                _as_text(actor) or "dashboard",
                _as_text(reason) or None,
                int(row["id"]),
            ),
        )
        suppression_id = int(row["id"])
    else:
        cur = conn.execute(
            """
            INSERT INTO false_positive_suppressions (
                created_at, updated_at, expires_at,
                rule_id, agent_name, source_ip, rule_description,
                created_from_alert_id, actor, reason
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                now,
                now,
                expires_at,
                rule_id,
                agent_name,
                source_ip,
                fields["rule_description"] or None,
                int(alert_id),
                _as_text(actor) or "dashboard",
                _as_text(reason) or None,
            ),
        )
        suppression_id = int(cur.lastrowid or 0)

    result = conn.execute(
        "SELECT * FROM false_positive_suppressions WHERE id = ?",
        (suppression_id,),
    ).fetchone()
    return dict(result) if result else None


def _create_false_positive_suppression_from_row(
    conn: sqlite3.Connection,
    row: dict[str, Any],
    actor: str,
    reason: str,
) -> dict[str, Any] | None:
    alert = _raw_alert_from_row(row)
    if not alert:
        rule: dict[str, Any] = {"id": row.get("rule_id"), "description": row.get("rule_description")}
        agent: dict[str, Any] = {"name": row.get("agent_name"), "ip": row.get("agent_ip")}
        alert = {"rule": rule, "agent": agent, "full_log": row.get("full_log")}
    return _create_false_positive_suppression_for_alert(
        conn,
        alert_id=int(row.get("id") or 0),
        alert=alert,
        actor=actor,
        reason=reason,
    )


def _match_false_positive_suppression_sync(alert: dict[str, Any]) -> dict[str, Any] | None:
    if not fp_suppression_enabled() or _is_sampledata_alert(alert):
        return None

    fields = _suppression_fields_from_alert(alert)
    rule_id = fields["rule_id"]
    if not rule_id:
        return None

    now = time.time()
    with _connect() as conn:
        row = conn.execute(
            """
            SELECT *
              FROM false_positive_suppressions
             WHERE enabled = 1
               AND expires_at > ?
               AND rule_id = ?
               AND (agent_name = '' OR agent_name = ?)
               AND (source_ip = '' OR source_ip = ?)
             ORDER BY (agent_name != '') DESC,
                      (source_ip != '') DESC,
                      COALESCE(updated_at, created_at) DESC,
                      created_at DESC
             LIMIT 1
            """,
            (now, rule_id, fields["agent_name"], fields["source_ip"]),
        ).fetchone()
        if not row:
            return None
        conn.execute(
            """
            UPDATE false_positive_suppressions
               SET hits = hits + 1,
                   last_hit_at = ?
             WHERE id = ?
            """,
            (now, int(row["id"])),
        )
        refreshed = conn.execute(
            "SELECT * FROM false_positive_suppressions WHERE id = ?",
            (int(row["id"]),),
        ).fetchone()
        return dict(refreshed or row)


def _list_false_positive_suppressions_sync(include_expired: bool = False) -> list[dict[str, Any]]:
    now = time.time()
    where = "" if include_expired else "WHERE enabled = 1 AND expires_at > ?"
    args: tuple[Any, ...] = () if include_expired else (now,)
    with _connect() as conn:
        cur = conn.execute(
            f"""
            SELECT *
              FROM false_positive_suppressions
              {where}
             ORDER BY expires_at DESC, created_at DESC
             LIMIT 200
            """,
            args,
        )
        return [dict(row) for row in cur.fetchall()]


def _disable_false_positive_suppression_sync(suppression_id: int) -> bool:
    with _connect() as conn:
        cur = conn.execute(
            """
            UPDATE false_positive_suppressions
               SET enabled = 0,
                   updated_at = ?
             WHERE id = ?
               AND enabled = 1
            """,
            (time.time(), int(suppression_id)),
        )
        return cur.rowcount > 0


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


def _get_alert_sync(alert_id: int) -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute(
            f"SELECT {_LIST_COLUMNS} FROM alerts WHERE id = ?",
            (int(alert_id),),
        ).fetchone()
    if not row:
        return None
    result = dict(row)
    if result.get("llm_iocs"):
        try:
            result["llm_iocs"] = json.loads(result["llm_iocs"])
        except json.JSONDecodeError:
            pass
    return result


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
        updated = cur.rowcount > 0
        if updated and normalized == "false_positive":
            row = conn.execute(
                f"SELECT {_LIST_COLUMNS} FROM alerts WHERE id = ?",
                (int(alert_id),),
            ).fetchone()
            if row:
                _create_false_positive_suppression_from_row(conn, dict(row), actor, note)
        return updated


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
        changed = int(cur.rowcount or 0)
        if changed and normalized == "false_positive":
            rows = conn.execute(
                f"SELECT {_LIST_COLUMNS} FROM alerts WHERE id IN ({placeholders})",
                ids,
            ).fetchall()
            for row in rows:
                _create_false_positive_suppression_from_row(conn, dict(row), actor, note)
        return changed


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
        where_parts.append(
            "COALESCE("
            "json_extract(raw_alert, '$.data.srcip'), "
            "json_extract(raw_alert, '$.data.src_ip'), "
            "json_extract(raw_alert, '$.data.source_ip')"
            ") = ?"
        )
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
                   COALESCE(
                       json_extract(raw_alert, '$.data.srcip'),
                       json_extract(raw_alert, '$.data.src_ip'),
                       json_extract(raw_alert, '$.data.source_ip')
                   ) AS srcip
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

        latest_ok_24h = conn.execute(
            "SELECT MAX(received_at) FROM alerts WHERE "
            f"{_NOT_SAMPLEDATA_SQL} "
            "AND received_at > strftime('%s','now') - 86400 "
            "AND llm_status = 'ok'"
        ).fetchone()[0]

        latest_error_24h = conn.execute(
            "SELECT MAX(received_at) FROM alerts WHERE "
            f"{_NOT_SAMPLEDATA_SQL} "
            "AND received_at > strftime('%s','now') - 86400 "
            "AND llm_status = 'error'"
        ).fetchone()[0]

    return {
        "total_alerts":        total,
        "alerts_last_24h":     last_24h,
        "errors_last_24h":     errors_24h,
        "latest_ok_received_at_24h": latest_ok_24h,
        "latest_error_received_at_24h": latest_error_24h,
        "by_severity_24h":     by_severity_24h,
        "open_by_severity_24h": open_by_severity_24h,
        "open_cases_24h":      open_cases_24h,
        "closed_cases_24h":    closed_cases_24h,
        "top_rules_24h":       top_rules,
        "avg_llm_latency_ms":  int(avg_lat) if avg_lat else None,
    }


def _alert_trends_sync(days: int = 7, include_sampledata: bool = False) -> list[dict[str, Any]]:
    day_count = max(1, min(int(days or 7), 30))
    now = time.time()
    start = now - ((day_count - 1) * 86400)
    labels = [
        time.strftime("%m/%d", time.localtime(start + (index * 86400)))
        for index in range(day_count)
    ]
    trends = {
        label: {"date": label, "critical": 0, "high": 0, "medium": 0, "low": 0, "endpoints": {}}
        for label in labels
    }
    where = ["received_at >= ?"]
    args: list[Any] = [start]
    if not include_sampledata:
        where.append(_NOT_SAMPLEDATA_SQL)
    where_sql = " AND ".join(where)

    with _connect() as conn:
        cur = conn.execute(
            f"""
            SELECT strftime('%m/%d', received_at, 'unixepoch', 'localtime') AS day,
                   COALESCE(llm_severity, 'unclassified') AS severity,
                   COUNT(*) AS count
              FROM alerts
             WHERE {where_sql}
             GROUP BY day, severity
            """,
            args,
        )
        for row in cur.fetchall():
            day = row["day"]
            severity = row["severity"]
            if day in trends and severity in ("critical", "high", "medium", "low"):
                trends[day][severity] = int(row["count"] or 0)

        cur = conn.execute(
            f"""
            SELECT strftime('%m/%d', received_at, 'unixepoch', 'localtime') AS day,
                   COALESCE(NULLIF(agent_name, ''), '未知設備') AS endpoint,
                   COUNT(*) AS count
              FROM alerts
             WHERE {where_sql}
             GROUP BY day, endpoint
            """,
            args,
        )
        for row in cur.fetchall():
            day = row["day"]
            if day in trends:
                trends[day]["endpoints"][row["endpoint"]] = int(row["count"] or 0)

    return [trends[label] for label in labels]


def _module_event_flow_sync(
    days: int = 7,
    include_sampledata: bool = False,
    limit: int = 10000,
) -> dict[str, Any]:
    day_count = max(1, min(int(days or 7), 30))
    row_limit = max(100, min(int(limit or 10000), 50000))
    since = time.time() - (day_count * 86400)
    where = ["received_at >= ?"]
    args: list[Any] = [since]
    if not include_sampledata:
        where.append(_NOT_SAMPLEDATA_SQL)
    where_sql = " AND ".join(where)

    modules: dict[str, dict[str, Any]] = {}
    with _connect() as conn:
        cur = conn.execute(
            f"""
            SELECT received_at, rule_id, rule_description, agent_name, full_log, raw_alert
              FROM alerts
             WHERE {where_sql}
             ORDER BY received_at DESC
             LIMIT ?
            """,
            [*args, row_limit],
        )
        rows = [dict(row) for row in cur.fetchall()]

    for row in rows:
        alert = _raw_alert_from_row(row)
        if not alert:
            alert = {
                "rule": {"id": row.get("rule_id"), "description": row.get("rule_description")},
                "agent": {"name": row.get("agent_name")},
                "full_log": row.get("full_log"),
            }
        module = _event_module_from_alert(alert)
        received_at = float(row.get("received_at") or 0)
        entry = modules.setdefault(
            module,
            {
                "key": module,
                "label_zh": MODULE_EVENT_LABELS_ZH.get(module, module),
                "count": 0,
                "last_seen": None,
            },
        )
        entry["count"] = int(entry["count"]) + 1
        if not entry["last_seen"] or received_at > float(entry["last_seen"] or 0):
            entry["last_seen"] = received_at

    observed = sorted(module for module, entry in modules.items() if int(entry.get("count") or 0) > 0)
    observed_expected = [module for module in EXPECTED_HARDENING_EVENT_MODULES if module in observed]
    missing_expected = [module for module in EXPECTED_HARDENING_EVENT_MODULES if module not in observed]
    return {
        "window_days": day_count,
        "rows_scanned": len(rows),
        "truncated": len(rows) >= row_limit,
        "total": sum(int(entry.get("count") or 0) for entry in modules.values()),
        "modules": modules,
        "observed": observed,
        "observed_expected": observed_expected,
        "missing_expected": missing_expected,
        "expected_modules": list(EXPECTED_HARDENING_EVENT_MODULES),
        "labels_zh": MODULE_EVENT_LABELS_ZH,
    }


# ─── async wrappers ─────────────────────────────────────────────────────
async def init_db() -> None:
    await asyncio.to_thread(init_db_sync)


async def save_alert(alert: dict[str, Any],
                     llm_reply: str,
                     parsed: dict[str, Any] | None,
                     latency_ms: int,
                     error: str | None,
                     llm_status: str | None = None,
                     case_status: str = "open",
                     case_note: str = "",
                     case_actor: str = "") -> int:
    return await asyncio.to_thread(
        _save_alert_sync,
        alert,
        llm_reply,
        parsed,
        latency_ms,
        error,
        llm_status,
        case_status,
        case_note,
        case_actor,
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


async def get_alert(alert_id: int) -> dict[str, Any] | None:
    return await asyncio.to_thread(_get_alert_sync, alert_id)


async def compute_stats() -> dict[str, Any]:
    return await asyncio.to_thread(_compute_stats_sync)


async def alert_trends(days: int = 7, include_sampledata: bool = False) -> list[dict[str, Any]]:
    return await asyncio.to_thread(_alert_trends_sync, days, include_sampledata)


async def module_event_flow(days: int = 7, include_sampledata: bool = False) -> dict[str, Any]:
    return await asyncio.to_thread(_module_event_flow_sync, days, include_sampledata)


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


async def match_false_positive_suppression(alert: dict[str, Any]) -> dict[str, Any] | None:
    return await asyncio.to_thread(_match_false_positive_suppression_sync, alert)


async def list_false_positive_suppressions(include_expired: bool = False) -> list[dict[str, Any]]:
    return await asyncio.to_thread(_list_false_positive_suppressions_sync, include_expired)


async def disable_false_positive_suppression(suppression_id: int) -> bool:
    return await asyncio.to_thread(_disable_false_positive_suppression_sync, suppression_id)


async def fetch_correlation_context(srcip: str | None,
                                    agent_name: str | None,
                                    window_seconds: int = 3600,
                                    limit: int = 10) -> list[dict[str, Any]]:
    """Async wrapper around correlation lookup. Returns recent related alerts."""
    return await asyncio.to_thread(
        _fetch_correlation_context_sync, srcip, agent_name, window_seconds, limit
    )
