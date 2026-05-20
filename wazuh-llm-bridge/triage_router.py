"""3-layer triage routing for Phase 3.

Layer 1 — admin hard overrides via env vars:
    AGENTIC_FORCE_RULE_IDS=5712,31103,510,91802     → always deep-investigate
    AGENTIC_FORCE_GROUPS=attack,malware,intrusion_detection
    AGENTIC_FORCE_LEVEL_GTE=12                       → always deep at this level
    AGENTIC_NEVER_RULE_IDS=19007,19008               → always skip deep
    AGENTIC_NEVER_GROUPS=sca,ossec

Layer 2 — LLM decides (default):
    For alerts that don't match Layer 1, we let the LLM do a Stage-1
    quick triage that includes a `needs_investigation: bool` field in
    its output. If true, app.py escalates to the agentic loop.

Public API: `decide(alert) → 'quick' | 'agentic' | 'llm_decides'`
"""
from __future__ import annotations

import logging
import os
from typing import Literal

log = logging.getLogger("triage")

Path = Literal["quick", "agentic", "llm_decides"]


def _csv_set(env_name: str) -> set[str]:
    return {x.strip() for x in os.getenv(env_name, "").split(",") if x.strip()}


def _int(env_name: str, default: int) -> int:
    try:
        return int(os.getenv(env_name, str(default)))
    except ValueError:
        return default


# Load on import — bridge restart picks up env changes.
FORCE_RULE_IDS  = _csv_set("AGENTIC_FORCE_RULE_IDS")
FORCE_GROUPS    = _csv_set("AGENTIC_FORCE_GROUPS")
FORCE_LEVEL_GTE = _int("AGENTIC_FORCE_LEVEL_GTE", 12)

NEVER_RULE_IDS  = _csv_set("AGENTIC_NEVER_RULE_IDS")
NEVER_GROUPS    = _csv_set("AGENTIC_NEVER_GROUPS")


def describe_policy() -> str:
    """Human-readable policy summary for startup log."""
    return (
        f"FORCE rules={sorted(FORCE_RULE_IDS) or '—'} groups={sorted(FORCE_GROUPS) or '—'} "
        f"level≥{FORCE_LEVEL_GTE}; "
        f"NEVER rules={sorted(NEVER_RULE_IDS) or '—'} groups={sorted(NEVER_GROUPS) or '—'}"
    )


def decide(alert: dict) -> Path:
    """Return the routing decision for this alert.

    Precedence:
      1. NEVER rules win (override everything → 'quick')
      2. FORCE rules → 'agentic'
      3. Default → 'llm_decides' (Stage-1 LLM picks)
    """
    rule    = alert.get("rule") or {}
    rule_id = str(rule.get("id", ""))
    level   = rule.get("level", 0) or 0
    groups  = set(rule.get("groups") or [])

    # NEVER first (defensive — avoid burning compute on known noise)
    if rule_id and rule_id in NEVER_RULE_IDS:
        return "quick"
    if groups & NEVER_GROUPS:
        return "quick"

    # FORCE (admin's hard opinions)
    if rule_id and rule_id in FORCE_RULE_IDS:
        return "agentic"
    if groups & FORCE_GROUPS:
        return "agentic"
    if isinstance(level, int) and level >= FORCE_LEVEL_GTE:
        return "agentic"

    # Default: defer to LLM (Stage 1 will emit needs_investigation)
    return "llm_decides"
