"""Short-lived one-time tokens for remote remediation actions."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Any

log = logging.getLogger("remote-action-token")

DB_PATH = Path(os.getenv("DB_PATH", "data/alerts.db")).resolve()
TOKEN_TTL_S = int(os.getenv("REMOTE_ACTION_TOKEN_TTL_S", os.getenv("SLACK_ACTION_TOKEN_TTL_S", "300")))
_SECRET_FILE = Path(os.getenv(
    "REMOTE_ACTION_TOKEN_SECRET_FILE",
    os.getenv(
        "SLACK_ACTION_TOKEN_SECRET_FILE",
        str(Path(__file__).parent / "data" / ".remote_action_token_secret"),
    ),
))


class ActionTokenError(ValueError):
    """Raised when a remote action token is invalid or no longer usable."""


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn


def _init_db() -> None:
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS slack_action_tokens (
                nonce_hash TEXT PRIMARY KEY,
                action TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                target TEXT,
                issued_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                used_at REAL,
                used_by TEXT
            )
            """
        )


def _load_or_create_secret() -> bytes:
    env = os.getenv("REMOTE_ACTION_TOKEN_SECRET", os.getenv("SLACK_ACTION_TOKEN_SECRET", "")).strip()
    if env:
        return env.encode("utf-8")
    if _SECRET_FILE.exists():
        secret = _SECRET_FILE.read_bytes().strip()
        if secret:
            return secret
    _SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
    secret = secrets.token_urlsafe(48).encode("utf-8")
    _SECRET_FILE.write_bytes(secret)
    try:
        _SECRET_FILE.chmod(0o600)
    except Exception:
        pass
    log.warning("Remote action token secret generated at %s", _SECRET_FILE)
    return secret


_SECRET = _load_or_create_secret()


def _b64u_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64u_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _nonce_hash(nonce: str) -> str:
    return hashlib.sha256(nonce.encode("utf-8")).hexdigest()


def _allowed_users() -> set[str]:
    raw = os.getenv("REMOTE_ACTION_ALLOWED_USERS", os.getenv("SLACK_ACTION_ALLOWED_USERS", "")).strip()
    return {item.strip() for item in raw.split(",") if item.strip()}


def issue(action: str, agent_id: str, *, target: str = "", ttl_s: int = TOKEN_TTL_S) -> str:
    """Create a signed, one-time remote action token."""
    action = str(action or "").strip()
    agent_id = str(agent_id or "").strip()
    target = str(target or "").strip()
    if not action or not agent_id:
        raise ValueError("action and agent_id are required")

    _init_db()
    now = int(time.time())
    nonce = secrets.token_urlsafe(18)
    claims = {
        "action": action,
        "agent_id": agent_id,
        "target": target,
        "nonce": nonce,
        "iat": now,
        "exp": now + int(ttl_s),
    }
    payload = json.dumps(claims, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    sig = hmac.new(_SECRET, payload, hashlib.sha256).digest()
    token = f"{_b64u_encode(payload)}.{_b64u_encode(sig)}"

    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO slack_action_tokens (
                nonce_hash, action, agent_id, target, issued_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (_nonce_hash(nonce), action, agent_id, target, now, claims["exp"]),
        )
    return token


def consume(token: str, expected_action: str, *, clicker: str = "") -> dict[str, Any]:
    """Verify and consume a remote action token exactly once."""
    if not token or "." not in token:
        raise ActionTokenError("這是舊版處置按鈕，已失效。請改用新的告警訊息按鈕。")
    try:
        payload_b64, sig_b64 = token.split(".", 1)
        payload = _b64u_decode(payload_b64)
        provided = _b64u_decode(sig_b64)
    except Exception as exc:
        raise ActionTokenError("處置 token 格式不正確，已拒絕執行。") from exc

    expected = hmac.new(_SECRET, payload, hashlib.sha256).digest()
    if not hmac.compare_digest(provided, expected):
        raise ActionTokenError("處置 token 驗證失敗，已拒絕執行。")

    try:
        claims = json.loads(payload.decode("utf-8"))
    except Exception as exc:
        raise ActionTokenError("處置 token 內容無法讀取，已拒絕執行。") from exc

    action = str(claims.get("action") or "")
    agent_id = str(claims.get("agent_id") or "")
    nonce = str(claims.get("nonce") or "")
    exp = claims.get("exp")
    if action != expected_action or not agent_id or not nonce or not isinstance(exp, (int, float)):
        raise ActionTokenError("處置 token 內容不完整或動作不相符，已拒絕執行。")
    if time.time() > float(exp):
        raise ActionTokenError("處置 token 已過期，請改用新的告警訊息按鈕。")

    allowed = _allowed_users()
    if allowed and clicker not in allowed:
        raise ActionTokenError("你的帳號未被允許執行此處置。")

    _init_db()
    nonce_hash = _nonce_hash(nonce)
    with _connect() as conn:
        row = conn.execute(
            "SELECT used_at FROM slack_action_tokens WHERE nonce_hash = ?",
            (nonce_hash,),
        ).fetchone()
        if not row:
            raise ActionTokenError("處置 token 不在允許清單內，已拒絕執行。")
        if row["used_at"]:
            raise ActionTokenError("這個處置 token 已使用過，不能重複執行。")
        cur = conn.execute(
            """
            UPDATE slack_action_tokens
               SET used_at = ?, used_by = ?
             WHERE nonce_hash = ? AND used_at IS NULL
            """,
            (time.time(), str(clicker or ""), nonce_hash),
        )
        if cur.rowcount != 1:
            raise ActionTokenError("這個處置 token 已使用過，不能重複執行。")

    return claims
