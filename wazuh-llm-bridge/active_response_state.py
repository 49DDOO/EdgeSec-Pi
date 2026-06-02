"""SQLite-backed audit state for Active Response lifecycle."""
from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any


DB_PATH = Path(os.getenv("DB_PATH", "data/alerts.db")).resolve()
DEFAULT_BLOCK_TTL_S = 3600
DEFAULT_ISOLATION_TTL_S = 900
DEFAULT_UNBLOCK_MAX_ATTEMPTS = 3
DEFAULT_UNBLOCK_RETRY_BASE_S = 300
DEFAULT_UNBLOCK_RETRY_MAX_S = 1800
DEFAULT_EXPIRING_STALE_S = 600
OPEN_BLOCK_STATUSES = ("active", "expiring", "manual_unblock_required", "unblock_failed")
OPEN_ISOLATION_STATUSES = (
    "isolated",
    "releasing",
    "release_failed",
    "manual_release_required",
)


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), timeout=10.0)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.row_factory = sqlite3.Row
    return conn


def init_db_sync() -> None:
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS active_response_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                ip TEXT NOT NULL,
                status TEXT NOT NULL,
                actor TEXT,
                reason TEXT,
                requested_at REAL NOT NULL,
                completed_at REAL,
                expires_at REAL,
                ttl_s INTEGER,
                attempt_count INTEGER NOT NULL DEFAULT 0,
                last_attempt_at REAL,
                next_retry_at REAL,
                details TEXT
            )
            """
        )
        _ensure_lifecycle_columns(conn)
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_ar_active_block
            ON active_response_actions (agent_id, ip, status, expires_at)
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_ar_expired_block
            ON active_response_actions (status, expires_at)
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_ar_retry_block
            ON active_response_actions (status, next_retry_at, last_attempt_at)
            """
        )


def _ensure_lifecycle_columns(conn: sqlite3.Connection) -> None:
    columns = {
        str(row["name"])
        for row in conn.execute("PRAGMA table_info(active_response_actions)").fetchall()
    }
    if "attempt_count" not in columns:
        conn.execute(
            "ALTER TABLE active_response_actions "
            "ADD COLUMN attempt_count INTEGER NOT NULL DEFAULT 0"
        )
    if "last_attempt_at" not in columns:
        conn.execute("ALTER TABLE active_response_actions ADD COLUMN last_attempt_at REAL")
    if "next_retry_at" not in columns:
        conn.execute("ALTER TABLE active_response_actions ADD COLUMN next_retry_at REAL")


def block_ttl_s() -> int:
    raw = str(os.getenv("ACTIVE_RESPONSE_BLOCK_TTL_S", str(DEFAULT_BLOCK_TTL_S))).strip()
    try:
        ttl = int(raw)
    except ValueError:
        ttl = DEFAULT_BLOCK_TTL_S
    return max(60, min(ttl, 86400))


def isolation_ttl_s() -> int:
    raw = str(os.getenv("ACTIVE_RESPONSE_ISOLATION_TTL_S", str(DEFAULT_ISOLATION_TTL_S))).strip()
    try:
        ttl = int(raw)
    except ValueError:
        ttl = DEFAULT_ISOLATION_TTL_S
    return max(60, min(ttl, 86400))


def unblock_max_attempts() -> int:
    raw = os.getenv("ACTIVE_RESPONSE_TTL_UNBLOCK_MAX_ATTEMPTS", str(DEFAULT_UNBLOCK_MAX_ATTEMPTS))
    try:
        attempts = int(str(raw).strip())
    except ValueError:
        attempts = DEFAULT_UNBLOCK_MAX_ATTEMPTS
    return max(1, min(attempts, 10))


def release_max_attempts() -> int:
    raw = os.getenv(
        "ACTIVE_RESPONSE_TTL_RELEASE_MAX_ATTEMPTS",
        os.getenv("ACTIVE_RESPONSE_TTL_UNBLOCK_MAX_ATTEMPTS", str(DEFAULT_UNBLOCK_MAX_ATTEMPTS)),
    )
    try:
        attempts = int(str(raw).strip())
    except ValueError:
        attempts = DEFAULT_UNBLOCK_MAX_ATTEMPTS
    return max(1, min(attempts, 10))


def unblock_retry_delay_s(attempt_count: int) -> int:
    base_raw = os.getenv(
        "ACTIVE_RESPONSE_TTL_UNBLOCK_RETRY_BASE_S",
        str(DEFAULT_UNBLOCK_RETRY_BASE_S),
    )
    max_raw = os.getenv(
        "ACTIVE_RESPONSE_TTL_UNBLOCK_RETRY_MAX_S",
        str(DEFAULT_UNBLOCK_RETRY_MAX_S),
    )
    try:
        base_s = int(str(base_raw).strip())
    except ValueError:
        base_s = DEFAULT_UNBLOCK_RETRY_BASE_S
    try:
        max_s = int(str(max_raw).strip())
    except ValueError:
        max_s = DEFAULT_UNBLOCK_RETRY_MAX_S
    exponent = max(0, int(attempt_count) - 1)
    return max(5, min(max(base_s, 5) * (2 ** exponent), max(max_s, 5)))


def release_retry_delay_s(attempt_count: int) -> int:
    base_raw = os.getenv(
        "ACTIVE_RESPONSE_TTL_RELEASE_RETRY_BASE_S",
        os.getenv("ACTIVE_RESPONSE_TTL_UNBLOCK_RETRY_BASE_S", str(DEFAULT_UNBLOCK_RETRY_BASE_S)),
    )
    max_raw = os.getenv(
        "ACTIVE_RESPONSE_TTL_RELEASE_RETRY_MAX_S",
        os.getenv("ACTIVE_RESPONSE_TTL_UNBLOCK_RETRY_MAX_S", str(DEFAULT_UNBLOCK_RETRY_MAX_S)),
    )
    try:
        base_s = int(str(base_raw).strip())
    except ValueError:
        base_s = DEFAULT_UNBLOCK_RETRY_BASE_S
    try:
        max_s = int(str(max_raw).strip())
    except ValueError:
        max_s = DEFAULT_UNBLOCK_RETRY_MAX_S
    exponent = max(0, int(attempt_count) - 1)
    return max(5, min(max(base_s, 5) * (2 ** exponent), max(max_s, 5)))


def expiring_stale_s() -> int:
    raw = os.getenv("ACTIVE_RESPONSE_TTL_EXPIRING_STALE_S", str(DEFAULT_EXPIRING_STALE_S))
    try:
        seconds = int(str(raw).strip())
    except ValueError:
        seconds = DEFAULT_EXPIRING_STALE_S
    return max(30, min(seconds, 7200))


def _decode_details(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if not value:
        return {}
    try:
        parsed = json.loads(str(value))
    except Exception:
        return {"previous_details": str(value)}
    return parsed if isinstance(parsed, dict) else {"previous_details": parsed}


def _details_payload(existing: Any, key: str, details: dict[str, Any] | None) -> str:
    payload = _decode_details(existing)
    if details:
        payload[key] = details
    return json.dumps(payload, ensure_ascii=False)


def record_block(
    agent_id: str,
    ip: str,
    *,
    ttl_s: int | None = None,
    expires_at: float | None = None,
    actor: str = "",
    reason: str = "",
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    init_db_sync()
    now = time.time()
    ttl = ttl_s or block_ttl_s()
    expiry = expires_at or (now + ttl)
    with _connect() as conn:
        cur = conn.execute(
            """
            INSERT INTO active_response_actions (
                action, agent_id, ip, status, actor, reason,
                requested_at, expires_at, ttl_s, details
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "block_ip",
                str(agent_id),
                str(ip),
                "active",
                actor,
                reason,
                now,
                expiry,
                int(ttl),
                json.dumps(details or {}, ensure_ascii=False),
            ),
        )
    return {
        "id": cur.lastrowid,
        "agent_id": str(agent_id),
        "ip": str(ip),
        "status": "active",
        "ttl_s": int(ttl),
        "expires_at": expiry,
    }


def record_isolation(
    agent_id: str,
    *,
    agent_name: str = "",
    ttl_s: int | None = None,
    expires_at: float | None = None,
    actor: str = "",
    reason: str = "",
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    init_db_sync()
    now = time.time()
    ttl = ttl_s or isolation_ttl_s()
    expiry = expires_at or (now + ttl)
    payload = {
        "agent_name": str(agent_name or ""),
        **(details or {}),
    }
    with _connect() as conn:
        cur = conn.execute(
            """
            INSERT INTO active_response_actions (
                action, agent_id, ip, status, actor, reason,
                requested_at, expires_at, ttl_s, details
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "isolate_endpoint",
                str(agent_id),
                "",
                "isolated",
                actor,
                reason,
                now,
                expiry,
                int(ttl),
                json.dumps(payload, ensure_ascii=False),
            ),
        )
    return {
        "id": cur.lastrowid,
        "agent_id": str(agent_id),
        "agent_name": str(agent_name or ""),
        "status": "isolated",
        "ttl_s": int(ttl),
        "expires_at": expiry,
    }


def find_active_block(agent_id: str, ip: str) -> dict[str, Any] | None:
    init_db_sync()
    now = time.time()
    with _connect() as conn:
        row = conn.execute(
            """
            SELECT * FROM active_response_actions
            WHERE action = 'block_ip'
              AND agent_id = ?
              AND ip = ?
              AND status = 'active'
              AND (expires_at IS NULL OR expires_at > ?)
            ORDER BY id DESC
            LIMIT 1
            """,
            (str(agent_id), str(ip), now),
        ).fetchone()
    return dict(row) if row else None


def find_open_block(agent_id: str, ip: str) -> dict[str, Any] | None:
    """Return the latest tracked block that has not been confirmed removed."""
    init_db_sync()
    placeholders = ",".join("?" for _ in OPEN_BLOCK_STATUSES)
    with _connect() as conn:
        row = conn.execute(
            f"""
            SELECT * FROM active_response_actions
            WHERE action = 'block_ip'
              AND agent_id = ?
              AND ip = ?
              AND status IN ({placeholders})
            ORDER BY id DESC
            LIMIT 1
            """,
            (str(agent_id), str(ip), *OPEN_BLOCK_STATUSES),
        ).fetchone()
    return dict(row) if row else None


def find_open_isolation(agent_id: str) -> dict[str, Any] | None:
    """Return the latest tracked endpoint isolation not confirmed released."""
    init_db_sync()
    placeholders = ",".join("?" for _ in OPEN_ISOLATION_STATUSES)
    with _connect() as conn:
        row = conn.execute(
            f"""
            SELECT * FROM active_response_actions
            WHERE action = 'isolate_endpoint'
              AND agent_id = ?
              AND status IN ({placeholders})
            ORDER BY id DESC
            LIMIT 1
            """,
            (str(agent_id), *OPEN_ISOLATION_STATUSES),
        ).fetchone()
    return dict(row) if row else None


def list_expired_active_blocks(limit: int = 50) -> list[dict[str, Any]]:
    init_db_sync()
    now = time.time()
    stale_before = now - expiring_stale_s()
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT * FROM active_response_actions
            WHERE action = 'block_ip'
              AND (
                (
                  status = 'active'
                  AND expires_at IS NOT NULL
                  AND expires_at <= ?
                )
                OR (
                  status = 'unblock_failed'
                  AND COALESCE(attempt_count, 0) < ?
                  AND (next_retry_at IS NULL OR next_retry_at <= ?)
                )
                OR (
                  status = 'expiring'
                  AND (last_attempt_at IS NULL OR last_attempt_at <= ?)
                )
              )
            ORDER BY expires_at ASC
            LIMIT ?
            """,
            (now, unblock_max_attempts(), now, stale_before, int(limit)),
        ).fetchall()
    return [dict(row) for row in rows]


def list_expired_active_isolations(limit: int = 50) -> list[dict[str, Any]]:
    init_db_sync()
    now = time.time()
    stale_before = now - expiring_stale_s()
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT * FROM active_response_actions
            WHERE action = 'isolate_endpoint'
              AND (
                (
                  status = 'isolated'
                  AND expires_at IS NOT NULL
                  AND expires_at <= ?
                )
                OR (
                  status = 'release_failed'
                  AND COALESCE(attempt_count, 0) < ?
                  AND (next_retry_at IS NULL OR next_retry_at <= ?)
                )
                OR (
                  status = 'releasing'
                  AND (last_attempt_at IS NULL OR last_attempt_at <= ?)
                )
              )
            ORDER BY expires_at ASC
            LIMIT ?
            """,
            (now, release_max_attempts(), now, stale_before, int(limit)),
        ).fetchall()
    return [dict(row) for row in rows]


def claim_expired_block(record_id: int, *, actor: str = "ttl-sweeper") -> dict[str, Any] | None:
    init_db_sync()
    now = time.time()
    stale_before = now - expiring_stale_s()
    with _connect() as conn:
        row = conn.execute(
            """
            SELECT * FROM active_response_actions
            WHERE id = ?
              AND action = 'block_ip'
              AND (
                (
                  status = 'active'
                  AND expires_at IS NOT NULL
                  AND expires_at <= ?
                )
                OR (
                  status = 'unblock_failed'
                  AND COALESCE(attempt_count, 0) < ?
                  AND (next_retry_at IS NULL OR next_retry_at <= ?)
                )
                OR (
                  status = 'expiring'
                  AND (last_attempt_at IS NULL OR last_attempt_at <= ?)
                )
              )
            """,
            (int(record_id), now, unblock_max_attempts(), now, stale_before),
        ).fetchone()
        if not row:
            return None
        details = _details_payload(
            row["details"],
            "ttl_lifecycle",
            {
                "claimed_at": now,
                "actor": actor,
                "attempt": int(row["attempt_count"] or 0) + 1,
            },
        )
        cur = conn.execute(
            """
            UPDATE active_response_actions
            SET status = 'expiring',
                completed_at = NULL,
                last_attempt_at = ?,
                next_retry_at = NULL,
                attempt_count = COALESCE(attempt_count, 0) + 1,
                details = ?
            WHERE id = ?
              AND action = 'block_ip'
              AND (
                (
                  status = 'active'
                  AND expires_at IS NOT NULL
                  AND expires_at <= ?
                )
                OR (
                  status = 'unblock_failed'
                  AND COALESCE(attempt_count, 0) < ?
                  AND (next_retry_at IS NULL OR next_retry_at <= ?)
                )
                OR (
                  status = 'expiring'
                  AND (last_attempt_at IS NULL OR last_attempt_at <= ?)
                )
              )
            """,
            (
                now,
                details,
                int(record_id),
                now,
                unblock_max_attempts(),
                now,
                stale_before,
            ),
        )
        if cur.rowcount != 1:
            return None
        claimed = conn.execute(
            "SELECT * FROM active_response_actions WHERE id = ?",
            (int(record_id),),
        ).fetchone()
    return dict(claimed) if claimed else None


def claim_expired_isolation(record_id: int, *, actor: str = "ttl-sweeper") -> dict[str, Any] | None:
    init_db_sync()
    now = time.time()
    stale_before = now - expiring_stale_s()
    with _connect() as conn:
        row = conn.execute(
            """
            SELECT * FROM active_response_actions
            WHERE id = ?
              AND action = 'isolate_endpoint'
              AND (
                (
                  status = 'isolated'
                  AND expires_at IS NOT NULL
                  AND expires_at <= ?
                )
                OR (
                  status = 'release_failed'
                  AND COALESCE(attempt_count, 0) < ?
                  AND (next_retry_at IS NULL OR next_retry_at <= ?)
                )
                OR (
                  status = 'releasing'
                  AND (last_attempt_at IS NULL OR last_attempt_at <= ?)
                )
              )
            """,
            (int(record_id), now, release_max_attempts(), now, stale_before),
        ).fetchone()
        if not row:
            return None
        details = _details_payload(
            row["details"],
            "ttl_lifecycle",
            {
                "claimed_at": now,
                "actor": actor,
                "attempt": int(row["attempt_count"] or 0) + 1,
            },
        )
        cur = conn.execute(
            """
            UPDATE active_response_actions
            SET status = 'releasing',
                completed_at = NULL,
                last_attempt_at = ?,
                next_retry_at = NULL,
                attempt_count = COALESCE(attempt_count, 0) + 1,
                details = ?
            WHERE id = ?
              AND action = 'isolate_endpoint'
              AND (
                (
                  status = 'isolated'
                  AND expires_at IS NOT NULL
                  AND expires_at <= ?
                )
                OR (
                  status = 'release_failed'
                  AND COALESCE(attempt_count, 0) < ?
                  AND (next_retry_at IS NULL OR next_retry_at <= ?)
                )
                OR (
                  status = 'releasing'
                  AND (last_attempt_at IS NULL OR last_attempt_at <= ?)
                )
              )
            """,
            (
                now,
                details,
                int(record_id),
                now,
                release_max_attempts(),
                now,
                stale_before,
            ),
        )
        if cur.rowcount != 1:
            return None
        claimed = conn.execute(
            "SELECT * FROM active_response_actions WHERE id = ?",
            (int(record_id),),
        ).fetchone()
    return dict(claimed) if claimed else None


def mark_block_status(
    record_id: int,
    status: str,
    *,
    details: dict[str, Any] | None = None,
    next_retry_at: float | None = None,
) -> dict[str, Any] | None:
    if status not in {"manual_unblock_required", "unblock_failed", "unblocked", "expiring"}:
        raise ValueError(f"unsupported active-response block status: {status}")
    init_db_sync()
    now = time.time()
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM active_response_actions WHERE id = ? AND action = 'block_ip'",
            (int(record_id),),
        ).fetchone()
        if not row:
            return None
        payload = _details_payload(row["details"], "ttl_lifecycle", details or {})
        completed_at = now if status in {"manual_unblock_required", "unblocked"} else None
        conn.execute(
            """
            UPDATE active_response_actions
            SET status = ?, completed_at = ?, next_retry_at = ?, details = ?
            WHERE id = ?
            """,
            (status, completed_at, next_retry_at, payload, int(record_id)),
        )
        updated = conn.execute(
            "SELECT * FROM active_response_actions WHERE id = ?",
            (int(record_id),),
        ).fetchone()
    return dict(updated) if updated else None


def mark_isolation_status(
    record_id: int,
    status: str,
    *,
    details: dict[str, Any] | None = None,
    next_retry_at: float | None = None,
) -> dict[str, Any] | None:
    if status not in {"manual_release_required", "release_failed", "released", "releasing"}:
        raise ValueError(f"unsupported active-response isolation status: {status}")
    init_db_sync()
    now = time.time()
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM active_response_actions WHERE id = ? AND action = 'isolate_endpoint'",
            (int(record_id),),
        ).fetchone()
        if not row:
            return None
        payload = _details_payload(row["details"], "ttl_lifecycle", details or {})
        completed_at = now if status in {"manual_release_required", "released"} else None
        conn.execute(
            """
            UPDATE active_response_actions
            SET status = ?, completed_at = ?, next_retry_at = ?, details = ?
            WHERE id = ?
            """,
            (status, completed_at, next_retry_at, payload, int(record_id)),
        )
        updated = conn.execute(
            "SELECT * FROM active_response_actions WHERE id = ?",
            (int(record_id),),
        ).fetchone()
    return dict(updated) if updated else None


def list_blocks(*, include_inactive: bool = False) -> list[dict[str, Any]]:
    init_db_sync()
    now = time.time()
    with _connect() as conn:
        if include_inactive:
            rows = conn.execute(
                """
                SELECT * FROM active_response_actions
                WHERE action = 'block_ip'
                ORDER BY requested_at DESC
                LIMIT 200
                """
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT * FROM active_response_actions
                WHERE action = 'block_ip'
                  AND status = 'active'
                  AND (expires_at IS NULL OR expires_at > ?)
                ORDER BY requested_at DESC
                LIMIT 200
                """,
                (now,),
            ).fetchall()
    return [dict(row) for row in rows]


def list_active_blocks() -> list[dict[str, Any]]:
    return list_blocks(include_inactive=False)


def list_isolations(*, include_inactive: bool = False) -> list[dict[str, Any]]:
    init_db_sync()
    placeholders = ",".join("?" for _ in OPEN_ISOLATION_STATUSES)
    with _connect() as conn:
        if include_inactive:
            rows = conn.execute(
                """
                SELECT * FROM active_response_actions
                WHERE action IN ('isolate_endpoint', 'release_isolation')
                ORDER BY requested_at DESC
                LIMIT 200
                """
            ).fetchall()
        else:
            rows = conn.execute(
                f"""
                SELECT * FROM active_response_actions
                WHERE action = 'isolate_endpoint'
                  AND status IN ({placeholders})
                ORDER BY requested_at DESC
                LIMIT 200
                """,
                (*OPEN_ISOLATION_STATUSES,),
            ).fetchall()
    return [dict(row) for row in rows]


def list_active_isolations() -> list[dict[str, Any]]:
    return list_isolations(include_inactive=False)


def record_unblock(
    agent_id: str,
    ip: str,
    *,
    record_id: int | None = None,
    actor: str = "",
    reason: str = "",
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    init_db_sync()
    now = time.time()
    payload = json.dumps({"unblock": details or {}}, ensure_ascii=False)
    placeholders = ",".join("?" for _ in OPEN_BLOCK_STATUSES)
    with _connect() as conn:
        if record_id is not None:
            row = conn.execute(
                "SELECT details FROM active_response_actions WHERE id = ?",
                (int(record_id),),
            ).fetchone()
            payload = _details_payload(row["details"] if row else None, "unblock", details or {})
            conn.execute(
                f"""
                UPDATE active_response_actions
                SET status = 'unblocked',
                    completed_at = ?,
                    next_retry_at = NULL,
                    details = ?
                WHERE id = ?
                  AND action = 'block_ip'
                  AND status IN ({placeholders})
                """,
                (now, payload, int(record_id), *OPEN_BLOCK_STATUSES),
            )
        else:
            conn.execute(
                f"""
                UPDATE active_response_actions
                SET status = 'unblocked',
                    completed_at = ?,
                    next_retry_at = NULL,
                    details = ?
                WHERE action = 'block_ip'
                  AND agent_id = ?
                  AND ip = ?
                  AND status IN ({placeholders})
                """,
                (now, payload, str(agent_id), str(ip), *OPEN_BLOCK_STATUSES),
            )
        cur = conn.execute(
            """
            INSERT INTO active_response_actions (
                action, agent_id, ip, status, actor, reason,
                requested_at, completed_at, details
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            ("unblock_ip", str(agent_id), str(ip), "completed", actor, reason, now, now, payload),
        )
    return {
        "id": cur.lastrowid,
        "agent_id": str(agent_id),
        "ip": str(ip),
        "status": "completed",
        "completed_at": now,
    }


def record_release_isolation(
    agent_id: str,
    *,
    record_id: int | None = None,
    actor: str = "",
    reason: str = "",
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    init_db_sync()
    now = time.time()
    payload = json.dumps({"release_isolation": details or {}}, ensure_ascii=False)
    placeholders = ",".join("?" for _ in OPEN_ISOLATION_STATUSES)
    with _connect() as conn:
        if record_id is not None:
            row = conn.execute(
                "SELECT details FROM active_response_actions WHERE id = ?",
                (int(record_id),),
            ).fetchone()
            payload = _details_payload(
                row["details"] if row else None,
                "release_isolation",
                details or {},
            )
            conn.execute(
                f"""
                UPDATE active_response_actions
                SET status = 'released',
                    completed_at = ?,
                    next_retry_at = NULL,
                    details = ?
                WHERE id = ?
                  AND action = 'isolate_endpoint'
                  AND status IN ({placeholders})
                """,
                (now, payload, int(record_id), *OPEN_ISOLATION_STATUSES),
            )
        else:
            conn.execute(
                f"""
                UPDATE active_response_actions
                SET status = 'released',
                    completed_at = ?,
                    next_retry_at = NULL,
                    details = ?
                WHERE action = 'isolate_endpoint'
                  AND agent_id = ?
                  AND status IN ({placeholders})
                """,
                (now, payload, str(agent_id), *OPEN_ISOLATION_STATUSES),
            )
        cur = conn.execute(
            """
            INSERT INTO active_response_actions (
                action, agent_id, ip, status, actor, reason,
                requested_at, completed_at, details
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            ("release_isolation", str(agent_id), "", "completed", actor, reason, now, now, payload),
        )
    return {
        "id": cur.lastrowid,
        "agent_id": str(agent_id),
        "status": "completed",
        "completed_at": now,
    }
