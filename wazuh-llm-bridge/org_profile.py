"""Org profile loader — business context for the LLM's severity decisions.

Reads `org_profile.yaml` (path overridable via ORG_PROFILE_PATH env var) and
exposes two main things:

  * load() / save() / reload()
  * context_for_alert(alert) → str   ← injected into the LLM prompt by app.py

The "context_for_alert" function is the bridge between the YAML and the prompt:
it looks up which asset profile matches the alert's agent, computes whether
the timestamp falls inside business hours, finds any matching user, and
returns a compact prompt block.

Hot-reload: any save() through the admin endpoint refreshes the in-memory copy
so the very next alert sees the new config — no bridge restart needed.
"""
from __future__ import annotations

import fnmatch
import logging
import os
import re
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

try:
    from zoneinfo import ZoneInfo                # Python 3.9+
except ImportError:                              # pragma: no cover
    ZoneInfo = None                              # type: ignore

import yaml

log = logging.getLogger("org-profile")

PROFILE_PATH = Path(os.getenv("ORG_PROFILE_PATH",
                              Path(__file__).parent / "org_profile.yaml"))

# Single in-memory copy; protected by a lock so admin-page writes don't
# race against worker reads.
_lock = threading.RLock()
_profile: dict[str, Any] = {}


# ─── load / save ─────────────────────────────────────────────────────────
def load() -> dict[str, Any]:
    """Load the YAML from disk into the in-memory cache. Returns a dict."""
    global _profile
    with _lock:
        if not PROFILE_PATH.exists():
            log.warning("org_profile.yaml not found at %s — using empty profile",
                        PROFILE_PATH)
            _profile = _empty()
            return _profile
        try:
            with PROFILE_PATH.open("r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            _profile = _normalize(data)
            log.info("loaded org profile from %s — org=%r assets=%d users=%d",
                     PROFILE_PATH,
                     _profile.get("org", {}).get("name"),
                     len(_profile.get("assets") or []),
                     len(_profile.get("users")  or []))
        except Exception as e:
            log.error("failed to parse org_profile.yaml: %s — keeping previous", e)
        return _profile


def save(new_profile: dict[str, Any]) -> None:
    """Atomically replace the YAML on disk and refresh the cache.

    Uses a temp file + rename so a crash mid-write can't corrupt the YAML.
    """
    global _profile
    normalized = _normalize(new_profile)
    tmp = PROFILE_PATH.with_suffix(".yaml.tmp")
    with _lock:
        with tmp.open("w", encoding="utf-8") as f:
            yaml.safe_dump(normalized, f,
                           allow_unicode=True, sort_keys=False, indent=2)
        tmp.replace(PROFILE_PATH)
        _profile = normalized
    log.info("org profile saved to %s", PROFILE_PATH)


def current() -> dict[str, Any]:
    """Thread-safe snapshot of the in-memory profile."""
    with _lock:
        # Return a shallow copy so callers can't mutate our cache.
        return dict(_profile)


# ─── helpers ─────────────────────────────────────────────────────────────
def _empty() -> dict[str, Any]:
    return {
        "org": {"name": "", "industry": "",
                "primary_timezone": "UTC", "description": ""},
        "assets": [],
        "users": [],
        "risk_notes": [],
        "escalation_hints": [],
    }


def _normalize(d: dict[str, Any]) -> dict[str, Any]:
    """Fill in missing top-level keys + coerce list/string types so downstream
    code never has to defensively check for None."""
    out = _empty()
    if isinstance(d.get("org"), dict):
        out["org"].update({k: v for k, v in d["org"].items() if v is not None})
    for key in ("assets", "users"):
        if isinstance(d.get(key), list):
            out[key] = [a for a in d[key] if isinstance(a, dict)]
    for key in ("risk_notes", "escalation_hints"):
        if isinstance(d.get(key), list):
            out[key] = [str(s) for s in d[key] if s]
    return out


def is_profiled(agent_name: str) -> bool:
    """True iff an asset entry matches this agent. Used by the Slack message
    builder to decide between '⚠️ 設定' CTA and a subtle 'view settings' link."""
    return find_asset(agent_name) is not None


def upsert_asset(pattern: str, fields: dict[str, Any]) -> dict[str, Any]:
    """Quick-add path: ensure an asset entry exists for `pattern`, merging
    in any supplied fields (role, criticality, business_hours, pci_scope,
    notes). Persists the result. Thread-safe.

    Returns the resulting (new or merged) asset entry.
    """
    pattern = (pattern or "").strip()
    if not pattern:
        raise ValueError("pattern required")
    with _lock:
        snap = _profile if _profile else _empty()
        assets = list(snap.get("assets") or [])
        # Try to find existing entry by exact pattern match first.
        match_idx = next(
            (i for i, a in enumerate(assets) if a.get("pattern") == pattern),
            None,
        )
        if match_idx is None:
            new_entry = {"pattern": pattern}
            new_entry.update({k: v for k, v in fields.items() if v not in (None, "")})
            assets.append(new_entry)
            result = new_entry
        else:
            assets[match_idx].update(
                {k: v for k, v in fields.items() if v not in (None, "")}
            )
            result = assets[match_idx]
        new_profile = {**snap, "assets": assets}
    # save() takes its own lock; call outside the with-block to avoid re-entry.
    save(new_profile)
    return result


def find_asset(agent_name: str) -> Optional[dict[str, Any]]:
    """Return the first asset whose pattern matches the agent name, or None."""
    name = (agent_name or "").strip()
    if not name:
        return None
    with _lock:
        for a in _profile.get("assets") or []:
            pat = a.get("pattern") or ""
            if pat and fnmatch.fnmatch(name, pat):
                return a
    return None


def find_user(username: str) -> Optional[dict[str, Any]]:
    name = (username or "").strip().lower()
    if not name:
        return None
    with _lock:
        for u in _profile.get("users") or []:
            if (u.get("name") or "").strip().lower() == name:
                return u
    return None


# ─── time-of-day check ───────────────────────────────────────────────────
_HOURS_RE = re.compile(
    r"(?P<days>[A-Za-z\-,/ ]+?)\s+"
    r"(?P<start>\d{1,2}:\d{2})\s*[-–]\s*(?P<end>\d{1,2}:\d{2})"
    r"(?:\s+(?P<tz>[A-Za-z_/]+))?",
    re.IGNORECASE,
)
_DAY_ALIASES = {
    "mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6,
    "monday": 0, "tuesday": 1, "wednesday": 2, "thursday": 3,
    "friday": 4, "saturday": 5, "sunday": 6,
}


def _parse_days(spec: str) -> set[int]:
    """Turn 'Mon-Fri' / 'Daily' / 'Mon,Wed,Fri' into a set of weekday ints."""
    spec = spec.strip().lower()
    if spec in ("daily", "every day", "every-day", "all", "*"):
        return set(range(7))
    days: set[int] = set()
    for chunk in re.split(r"[,/]", spec):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            a, _, b = chunk.partition("-")
            if a.strip() in _DAY_ALIASES and b.strip() in _DAY_ALIASES:
                s, e = _DAY_ALIASES[a.strip()], _DAY_ALIASES[b.strip()]
                if s <= e:
                    days.update(range(s, e + 1))
                else:
                    days.update(list(range(s, 7)) + list(range(0, e + 1)))
        else:
            d = _DAY_ALIASES.get(chunk[:3])
            if d is not None:
                days.add(d)
    return days


@dataclass
class TimeStatus:
    label:        str           # "WITHIN business hours" / "OFF-HOURS"
    detail:       str           # eg "Sat 03:14 Asia/Taipei — 8h after Fri close"
    is_off_hours: bool


def _check_business_hours(spec: str,
                          when_utc: datetime,
                          fallback_tz: str) -> Optional[TimeStatus]:
    """Best-effort: is `when_utc` inside the spec like 'Mon-Fri 09:00-19:00 Asia/Taipei'?

    Returns None when the spec is empty or unparseable. The LLM still has the
    raw spec in the prompt and can reason about it as fallback.
    """
    if not spec or not spec.strip():
        return None
    m = _HOURS_RE.search(spec)
    if not m:
        return None

    tz_name = m.group("tz") or fallback_tz or "UTC"
    if ZoneInfo is None:
        return None
    try:
        tz = ZoneInfo(tz_name)
    except Exception:
        tz = ZoneInfo("UTC")

    local = when_utc.astimezone(tz)
    weekday = local.weekday()
    days = _parse_days(m.group("days"))

    sh, sm = (int(x) for x in m.group("start").split(":"))
    eh, em = (int(x) for x in m.group("end").split(":"))
    start_min = sh * 60 + sm
    end_min   = eh * 60 + em
    now_min   = local.hour * 60 + local.minute

    in_day  = weekday in days
    in_hour = start_min <= now_min < end_min if start_min < end_min \
              else (now_min >= start_min or now_min < end_min)   # overnight

    inside = in_day and in_hour
    return TimeStatus(
        label  = "WITHIN business hours" if inside else "OFF-HOURS",
        detail = f"{local.strftime('%a %H:%M')} {tz_name} "
                 f"(business hours: {spec})",
        is_off_hours = not inside,
    )


# ─── username extraction from raw_log ────────────────────────────────────
# Order matters — more specific patterns first so we extract the ACTOR
# (e.g. "bob" in "sudo: bob : ... USER=root") rather than the TARGET ("root").
_USER_PATTERNS = [
    re.compile(r"\bsudo:\s+([A-Za-z0-9_.\-]+)\s*:"),       # sudoer (actor)
    re.compile(r"\bsu(?:do)?\(pam_unix\)\[\d+\]:\s+session opened for user [^ ]+ by ([A-Za-z0-9_.\-]+)\("),
    re.compile(r"\bfor (?:\w+ )?user ['\"]?([A-Za-z0-9_.\-]+)"),  # sshd / pam: covers "for user X" + "for invalid user X" + "for unknown user X"
    re.compile(r"\b(?:Accepted|Failed) (?:password|publickey|keyboard-interactive(?:/pam)?) for ['\"]?([A-Za-z0-9_.\-]+)"),  # sshd success/fail with named user (rule 5715, 5716, …)
    re.compile(r"\buser=([A-Za-z0-9_.\-]+)"),              # auditd / sshd
    re.compile(r"\bUSER=([A-Za-z0-9_.\-]+)"),              # sudo target env (last)
]


# Win user fields we treat as "ignore" — machine accounts / anonymous markers,
# not interesting actors for triage.
_WIN_IGNORE_USERS = {"-", "", "SYSTEM", "ANONYMOUS LOGON", "LOCAL SERVICE",
                     "NETWORK SERVICE", "N/A"}


def _guess_user(alert: dict[str, Any]) -> Optional[str]:
    """Extract the most useful username from a Wazuh alert.

    Strategy (highest signal first):
      1. Windows Sysmon / EventLog structured fields (data.win.eventdata)
      2. FIM with auditd context (data.syscheck.audit.user.name)
      3. Plain auditd decoder (data.audit.user.name or .uid)
      4. SSH / sudo / PAM regex on full_log (fallback)

    Returns None when no actor can be identified (vuln alerts, SCA, etc).
    """
    data = alert.get("data") or {}

    # 1. Windows Sysmon / EventLog — structured field, highest fidelity.
    win = (data.get("win") or {}).get("eventdata") or {}
    for key in ("TargetUserName", "SubjectUserName", "User"):
        v = (win.get(key) or "").strip()
        if v and v not in _WIN_IGNORE_USERS:
            # Strip leading "DOMAIN\" for readability.
            return v.split("\\", 1)[-1]

    # 2. FIM file change with auditd attribution.
    sc_audit = ((data.get("syscheck") or {}).get("audit") or {})
    name = (sc_audit.get("user") or {}).get("name")
    if name:
        return str(name)

    # 3. Direct auditd execve / file-watch alerts.
    audit = data.get("audit") or {}
    name = (audit.get("user") or {}).get("name")
    if name:
        return str(name)
    uid = audit.get("uid")
    if uid is not None:
        return f"uid={uid}"  # numeric fallback when /etc/passwd not joined

    # 4. Fall back to regex on the raw log line (SSH / sudo / PAM).
    raw_log = alert.get("full_log") or ""
    if raw_log:
        for pat in _USER_PATTERNS:
            m = pat.search(raw_log)
            if m:
                return m.group(1)

    return None


# Back-compat shim — earlier signature took only raw_log.
def _guess_user_from_log(raw_log: str) -> Optional[str]:
    return _guess_user({"full_log": raw_log})


# ─── the function app.py calls ───────────────────────────────────────────
def context_for_alert(alert: dict[str, Any]) -> str:
    """Build the BUSINESS CONTEXT prompt block for one alert. Empty string
    when the profile has no relevant entry (no asset matched and no global
    risk_notes/escalation_hints) — so we don't waste tokens on noise.
    """
    snap = current()
    org      = snap.get("org") or {}
    agent    = (alert.get("agent") or {}).get("name") or ""
    raw_log  = alert.get("full_log") or ""
    asset    = find_asset(agent)
    username = _guess_user(alert)
    user     = find_user(username) if username else None
    risk     = snap.get("risk_notes") or []
    hints    = snap.get("escalation_hints") or []

    # Bail out if nothing applies — keep the prompt clean.
    if not (asset or user or risk or hints or org.get("description")):
        return ""

    # Determine alert timestamp (UTC). Most Wazuh alerts have a `timestamp`
    # field in ISO format; fall back to now() when missing.
    when_utc: Optional[datetime] = None
    ts = alert.get("timestamp")
    if isinstance(ts, str):
        try:
            when_utc = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            when_utc = None
    if when_utc is None:
        when_utc = datetime.now(timezone.utc)

    primary_tz = org.get("primary_timezone") or "UTC"
    time_status = _check_business_hours(
        asset.get("business_hours") if asset else "",
        when_utc, primary_tz,
    )

    lines: list[str] = ["BUSINESS CONTEXT (from organization profile):"]
    if org.get("name") or org.get("description"):
        lines.append(f"  Org:           {org.get('name', '?')} "
                     f"({org.get('industry', '?')})")
        if org.get("description"):
            desc = " ".join(org["description"].split())
            lines.append(f"  Org notes:     {desc[:300]}")

    lines.append(f"  Alert agent:   {agent or '?'}")
    lines.append(f"  Alert time:    {when_utc.isoformat(timespec='seconds')}")

    if asset:
        lines.append(f"  Asset role:    {asset.get('role', '?')}")
        lines.append(f"  Criticality:   {asset.get('criticality', '?')}")
        if asset.get("pci_scope"):
            lines.append("  PCI scope:     YES — cardholder data territory")
        if asset.get("notes"):
            lines.append(f"  Asset notes:   {asset['notes']}")
        if time_status:
            mark = "🔴" if time_status.is_off_hours else "🟢"
            lines.append(f"  Time status:   {mark} {time_status.label}  "
                         f"({time_status.detail})")
        elif asset.get("business_hours"):
            lines.append(f"  Business hrs:  {asset['business_hours']} "
                         "(LLM: judge yourself whether the alert time is inside)")
    else:
        lines.append(f"  Asset role:    UNREGISTERED — agent {agent!r} has no "
                     "matching pattern in org profile. Treat as unknown criticality "
                     "and recommend the admin add it.")

    if user:
        lines.append(f"  User in log:   {user.get('name')} — "
                     f"{user.get('role', '?')}. {user.get('notes', '')}")
    elif username:
        lines.append(f"  User in log:   {username} (not in profile)")

    if risk:
        lines.append("  Org risk notes (authoritative background):")
        for r in risk[:6]:
            lines.append(f"    • {r}")

    if hints:
        lines.append("  Org escalation hints (apply BEFORE the level-based rubric):")
        for h in hints[:6]:
            lines.append(f"    • {h}")

    lines.append(
        "Weigh this business context AT LEAST as heavily as the Wazuh level. "
        "A Wazuh level 3 event on a critical asset, off-hours, by an unexpected "
        "user can absolutely be high or critical — integrate all signals, "
        "do not defer to the static rule level."
    )
    return "\n".join(lines)


# ─── module init ─────────────────────────────────────────────────────────
load()
