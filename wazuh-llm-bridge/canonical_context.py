"""Shared helpers for reading EdgeSec-Pi canonical signals.

The project is still migrating away from the Wazuh-shaped compatibility
envelope. These helpers keep that migration explicit: callers should consume
canonical signal facts first, then fall back to raw source evidence only when a
field is genuinely sparse.
"""
from __future__ import annotations

import json
from typing import Any

import canonical_signal


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value in (None, "", [], {}):
        return []
    return [value]


def text(value: Any) -> str:
    return str(value or "").strip()


def json_obj(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if not isinstance(value, str) or not value.strip():
        return {}
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _signal_from_value(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    return json_obj(value)


def signal_from_alert(alert: dict[str, Any], *, received_at: float | int | None = None) -> dict[str, Any]:
    for key in ("_canonical_signal", "canonical_signal"):
        signal = _signal_from_value(alert.get(key))
        if signal:
            return signal
    return canonical_signal.safe_from_alert(alert, received_at=received_at)


def signal_from_row(row: dict[str, Any], raw_alert: dict[str, Any] | None = None) -> dict[str, Any]:
    signal = _signal_from_value(row.get("canonical_signal"))
    if signal:
        return signal
    alert = raw_alert if isinstance(raw_alert, dict) else json_obj(row.get("raw_alert"))
    received_at = row.get("received_at")
    return canonical_signal.safe_from_alert(alert, received_at=received_at)


def source_context(signal: dict[str, Any]) -> dict[str, Any]:
    return as_dict(signal.get("source_context"))


def asset(signal: dict[str, Any]) -> dict[str, Any]:
    return as_dict(signal.get("asset"))


def actor(signal: dict[str, Any]) -> dict[str, Any]:
    return as_dict(signal.get("actor"))


def target(signal: dict[str, Any]) -> dict[str, Any]:
    return as_dict(signal.get("target"))


def observables(signal: dict[str, Any]) -> dict[str, Any]:
    return as_dict(signal.get("observables"))


def first_observable(signal: dict[str, Any], key: str) -> str:
    values = as_list(observables(signal).get(key))
    return text(values[0]) if values else ""


def source_specific_keys(signal: dict[str, Any]) -> list[str]:
    keys: list[str] = []
    source_specific = as_dict(signal.get("source_specific"))
    for source, value in source_specific.items():
        if isinstance(value, dict):
            keys.extend(f"{source}.{key}" for key in sorted(value))
    return keys


def mitre_ids(signal: dict[str, Any]) -> list[str]:
    return [text(item) for item in as_list(source_context(signal).get("mitre")) if text(item)]


def rule_groups(signal: dict[str, Any]) -> list[str]:
    return [text(item) for item in as_list(source_context(signal).get("rule_groups")) if text(item)]
