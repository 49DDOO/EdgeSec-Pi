"""Priority queue for alert analysis work.

The bridge must return quickly to Wazuh, but the background queue should not
let noisy posture checks delay active attack signals. Lower priority numbers
are processed first; items with the same priority remain FIFO.
"""
from __future__ import annotations

import asyncio
import itertools
import re
from typing import Any


QueuedAlert = tuple[int, int, dict[str, Any]]

NOISY_RULE_IDS = {"19007", "19008"}
NOISY_GROUPS = {
    "sca",
    "compliance",
    "policy_monitoring",
}
URGENT_GROUPS = {
    "attack",
    "authentication_failed",
    "authentication_failures",
    "fim",
    "intrusion_detection",
    "malware",
    "rootcheck",
    "sshd",
    "syscheck",
    "virustotal",
    "yara",
}
URGENT_TEXT = re.compile(
    r"brute force|failed password|invalid user|rootkit|malware|trojan|backdoor|"
    r"intrusion|attack|credential|suspicious process|powershell|c2",
    re.IGNORECASE,
)


def _rule(alert: dict[str, Any]) -> dict[str, Any]:
    value = alert.get("rule")
    return value if isinstance(value, dict) else {}


def _level(alert: dict[str, Any]) -> int:
    try:
        return int(_rule(alert).get("level", 0) or 0)
    except (TypeError, ValueError):
        return 0


def _groups(alert: dict[str, Any]) -> set[str]:
    groups = _rule(alert).get("groups") or []
    if not isinstance(groups, list):
        return set()
    return {str(item).lower() for item in groups}


def _text(alert: dict[str, Any]) -> str:
    rule = _rule(alert)
    return " ".join(
        str(part or "")
        for part in (
            rule.get("id"),
            rule.get("description"),
            alert.get("full_log"),
        )
    )


def alert_priority(alert: dict[str, Any]) -> int:
    """Return the analysis priority for one alert."""
    rule = _rule(alert)
    rule_id = str(rule.get("id", ""))
    level = _level(alert)
    groups = _groups(alert)
    text = _text(alert)

    noisy = rule_id in NOISY_RULE_IDS or bool(groups & NOISY_GROUPS) or "cis" in text.lower()
    urgent = bool(groups & URGENT_GROUPS) or bool(URGENT_TEXT.search(text))

    if level >= 12:
        return 0
    if level >= 10 and urgent:
        return 1
    if level >= 10:
        return 2
    if urgent and level >= 7:
        return 3
    if noisy:
        return 80
    if level >= 7:
        return 20
    return 50


class AlertPriorityQueue(asyncio.PriorityQueue[QueuedAlert]):
    """asyncio priority queue that accepts and returns alert dictionaries."""

    def __init__(self, maxsize: int = 0) -> None:
        super().__init__(maxsize=maxsize)
        self._sequence = itertools.count()

    def _wrap(self, item: Any) -> QueuedAlert:
        if (
            isinstance(item, tuple)
            and len(item) == 3
            and isinstance(item[0], int)
            and isinstance(item[1], int)
            and isinstance(item[2], dict)
        ):
            return item
        if not isinstance(item, dict):
            raise TypeError("AlertPriorityQueue only accepts alert dictionaries")
        return (alert_priority(item), next(self._sequence), item)

    @staticmethod
    def _unwrap(item: QueuedAlert) -> dict[str, Any]:
        return item[2]

    async def put(self, item: dict[str, Any]) -> None:  # type: ignore[override]
        await super().put(self._wrap(item))

    def put_nowait(self, item: dict[str, Any]) -> None:  # type: ignore[override]
        super().put_nowait(self._wrap(item))

    async def get(self) -> dict[str, Any]:  # type: ignore[override]
        return await super().get()  # Queue.get() delegates to our get_nowait().

    def get_nowait(self) -> dict[str, Any]:  # type: ignore[override]
        return self._unwrap(super().get_nowait())
