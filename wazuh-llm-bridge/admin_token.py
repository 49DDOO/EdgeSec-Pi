"""HMAC-signed short-lived tokens for /admin/quick-add Slack deep-links.

Why not JWT? Keeps the dependency tree at zero (stdlib `hmac` + `base64`).
The wire format is intentionally JWT-compatible enough that swapping in
PyJWT later is trivial:

    <base64url(payload_json)>.<base64url(hmac_sha256)>

Payload is JSON:  {"agent": "db-finance-01", "exp": <unix_ts>}

Threat model:
  • Token IS reproducible by anyone holding the secret. The secret must
    live in env (ADMIN_TOKEN_SECRET) and never be committed.
  • Anyone holding a valid token can quick-add/edit the agent in the
    `agent` field, but NOT other agents — the form binds to the token's
    agent claim.
  • Tokens expire after TOKEN_TTL_S (default 30 min). Slack history
    leaking the URL is bearable: by the time it's read, it's likely expired.
  • Falls back to HTTP Basic Auth when no token is present — internal
    IT can still hit /admin/quick-add directly without needing a token.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from pathlib import Path

log = logging.getLogger("admin-token")

# 30 min default — long enough for management to see a Slack alert and
# click the link, but short enough that a leaked Slack history
# isn't a long-term risk.
TOKEN_TTL_S = int(os.getenv("ADMIN_TOKEN_TTL_S", "1800"))

# Secret resolution: env var > on-disk file > generated and persisted.
# Persisting to disk means restarts don't invalidate outstanding Slack links.
_SECRET_FILE = Path(os.getenv(
    "ADMIN_TOKEN_SECRET_FILE",
    Path(__file__).parent / "data" / ".admin_token_secret",
))


def _load_or_create_secret() -> bytes:
    env = os.getenv("ADMIN_TOKEN_SECRET", "").strip()
    if env:
        log.info("admin-token secret loaded from ADMIN_TOKEN_SECRET env var")
        return env.encode("utf-8")

    if _SECRET_FILE.exists():
        s = _SECRET_FILE.read_bytes().strip()
        if s:
            return s

    # Generate + persist (mode 600). Won't be in git because data/ is ignored.
    _SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
    s = secrets.token_urlsafe(48).encode("utf-8")
    _SECRET_FILE.write_bytes(s)
    try:
        _SECRET_FILE.chmod(0o600)
    except Exception:
        pass
    log.warning(
        "  ⚠  admin-token secret generated and persisted to %s. "
        "For stability across deployments set ADMIN_TOKEN_SECRET env var.",
        _SECRET_FILE,
    )
    return s


_SECRET = _load_or_create_secret()


# ─── base64url helpers ───────────────────────────────────────────────────
def _b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


# ─── public API ──────────────────────────────────────────────────────────
def sign(agent_name: str, ttl_s: int = TOKEN_TTL_S) -> str:
    """Return a signed token good for editing `agent_name` for ttl_s seconds."""
    if not agent_name:
        raise ValueError("agent_name required")
    payload = json.dumps({
        "agent": agent_name,
        "exp":   int(time.time()) + int(ttl_s),
    }, separators=(",", ":")).encode("utf-8")
    sig = hmac.new(_SECRET, payload, hashlib.sha256).digest()
    return f"{_b64u_encode(payload)}.{_b64u_encode(sig)}"


def verify(token: str) -> str | None:
    """Validate a token. Returns the agent_name if good, else None.

    Failure modes (all return None, never raise):
      • malformed (not two parts / non-base64)
      • bad signature (constant-time comparison)
      • expired
      • missing required claims
    """
    if not token or "." not in token:
        return None
    try:
        payload_b64, sig_b64 = token.split(".", 1)
        payload_bytes = _b64u_decode(payload_b64)
        sig_provided  = _b64u_decode(sig_b64)
    except Exception:
        return None

    sig_expected = hmac.new(_SECRET, payload_bytes, hashlib.sha256).digest()
    if not hmac.compare_digest(sig_provided, sig_expected):
        return None

    try:
        claims = json.loads(payload_bytes.decode("utf-8"))
    except Exception:
        return None

    agent = claims.get("agent")
    exp   = claims.get("exp")
    if not isinstance(agent, str) or not isinstance(exp, (int, float)):
        return None
    if time.time() > exp:
        return None
    return agent
