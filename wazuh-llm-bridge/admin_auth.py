"""Shared authentication helpers for browser admin routes."""
from __future__ import annotations

import os
import secrets
from typing import Optional

from fastapi import Depends, HTTPException
from fastapi.security import HTTPBasic, HTTPBasicCredentials

import admin_token


ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASS", "")

_WEAK_PASSWORDS = {"", "changeme", "password", "admin", "123456", "secret"}
if ADMIN_PASS in _WEAK_PASSWORDS:
    raise RuntimeError(
        "ADMIN_PASS is empty or a well-known weak value. Refusing to start "
        "with a vulnerable /admin endpoint. Set ADMIN_USER / ADMIN_PASS in "
        ".env to strong values before retrying. Generate one with: "
        "python3 -c 'import secrets; print(secrets.token_urlsafe(24))'"
    )

# auto_error=False lets signed-token routes decide before falling back to Basic.
basic_auth = HTTPBasic(auto_error=False)


def check_admin(creds: Optional[HTTPBasicCredentials] = Depends(basic_auth)) -> str:
    """Require Basic Auth for full admin access."""
    if creds is None:
        raise HTTPException(
            status_code=401, detail="Unauthorized",
            headers={"WWW-Authenticate": "Basic"},
        )
    ok_u = secrets.compare_digest(creds.username, ADMIN_USER)
    ok_p = secrets.compare_digest(creds.password, ADMIN_PASS)
    if not (ok_u and ok_p):
        raise HTTPException(
            status_code=401, detail="Unauthorized",
            headers={"WWW-Authenticate": "Basic"},
        )
    return creds.username


def authorize_quick_add(
    token: Optional[str],
    agent: Optional[str],
    creds: Optional[HTTPBasicCredentials],
) -> str:
    """Allow either a matching signed agent token or Basic Auth."""
    if token and agent:
        tok_agent = admin_token.verify(token)
        if tok_agent and tok_agent == agent:
            return f"token:{tok_agent}"
    return check_admin(creds)


def authorize_notifications(
    token: Optional[str],
    creds: Optional[HTTPBasicCredentials],
) -> str:
    """Allow either a notifications-scoped token or Basic Auth."""
    if token:
        tok_scope = admin_token.verify(token)
        if tok_scope == "__notifications__":
            return "token:notifications"
    return check_admin(creds)
