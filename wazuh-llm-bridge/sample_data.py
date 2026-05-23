"""Wazuh Sample Data helpers.

Wazuh Dashboard can load sample alerts into indices such as
`wazuh-alerts-4.x-sample-security`. Those documents include
`@sampledata: true`; keep that flag as the source of truth so test alerts
never look like real company incidents.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

try:
    from dotenv import load_dotenv
    _shared_env_path = Path(__file__).resolve().parent.parent / "bridge.env"
    if _shared_env_path.exists():
        load_dotenv(_shared_env_path, override=False)
    _env_path = Path(__file__).parent / ".env"
    if _env_path.exists():
        load_dotenv(_env_path, override=False)
    # Lab fallback: the bundled Wazuh MCP setup file often carries Indexer
    # credentials. Explicit environment values still win because override=False.
    _mcp_env_path = Path(__file__).resolve().parent.parent / "wazuh-stack" / "wazuh-mcp" / ".env"
    if _mcp_env_path.exists():
        load_dotenv(_mcp_env_path, override=False)
except ImportError:
    pass


INDEXER_URL = os.getenv("WAZUH_INDEXER_URL", "https://localhost:9200").rstrip("/")
INDEXER_USER = os.getenv("WAZUH_INDEXER_USER", "admin")
INDEXER_PASS = os.getenv("WAZUH_INDEXER_PASS", "")
INDEXER_VERIFY_SSL = os.getenv("WAZUH_INDEXER_VERIFY_SSL", "false").strip().lower() == "true"

DEFAULT_INDEX_PATTERN = os.getenv("SAMPLE_INDEX_PATTERN", "wazuh-alerts-4.x-sample-*")

SAMPLE_CATEGORIES = {
    "all": DEFAULT_INDEX_PATTERN,
    "security": "wazuh-alerts-4.x-sample-security",
    "malware": "wazuh-alerts-4.x-sample-malware",
    "threat": "wazuh-alerts-4.x-sample-threat-*",
    "inventory": "wazuh-states-inventory-*",
    "vulnerability": "wazuh-states-vulnerabilities-*",
}


class SampleDataError(RuntimeError):
    """Raised when Wazuh sample data cannot be queried safely."""


def _auth() -> tuple[str, str]:
    if not INDEXER_PASS:
        raise SampleDataError("WAZUH_INDEXER_PASS is not set; cannot query Wazuh sample data")
    return INDEXER_USER, INDEXER_PASS


def _index_pattern(category: str | None) -> str:
    return SAMPLE_CATEGORIES.get((category or "security").strip().lower(), DEFAULT_INDEX_PATTERN)


async def _post_json(path: str, body: dict[str, Any]) -> dict[str, Any]:
    async with httpx.AsyncClient(auth=_auth(), verify=INDEXER_VERIFY_SSL, timeout=20.0) as client:
        response = await client.post(f"{INDEXER_URL}/{path.lstrip('/')}", json=body)
        response.raise_for_status()
        data = response.json()
        return data if isinstance(data, dict) else {}


def _total(payload: dict[str, Any]) -> int:
    total = ((payload.get("hits") or {}).get("total") or {})
    if isinstance(total, dict):
        return int(total.get("value") or 0)
    try:
        return int(total)
    except (TypeError, ValueError):
        return 0


async def sample_status(category: str = "security") -> dict[str, Any]:
    """Return sample-data availability without returning any alert body."""
    index_pattern = _index_pattern(category)
    total_payload = await _post_json(
        f"{index_pattern}/_search",
        {"size": 0, "track_total_hits": True, "query": {"match_all": {}}},
    )
    flagged_payload = await _post_json(
        f"{index_pattern}/_search",
        {"size": 0, "track_total_hits": True, "query": {"term": {"@sampledata": True}}},
    )
    return {
        "category": category,
        "index_pattern": index_pattern,
        "available": _total(flagged_payload) > 0,
        "total": _total(total_payload),
        "sampledata_total": _total(flagged_payload),
    }


async def load_sample_alerts(
    *,
    category: str = "security",
    limit: int = 3,
    min_level: int = 7,
) -> list[dict[str, Any]]:
    """Load a small, explicitly marked batch of Wazuh sample alerts."""
    limit = max(1, min(int(limit), 10))
    min_level = max(0, min(int(min_level), 15))
    index_pattern = _index_pattern(category)
    body = {
        "size": limit,
        "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
        "query": {
            "bool": {
                "filter": [
                    {"term": {"@sampledata": True}},
                    {"range": {"rule.level": {"gte": min_level}}},
                ]
            }
        },
    }
    payload = await _post_json(f"{index_pattern}/_search", body)
    hits = ((payload.get("hits") or {}).get("hits") or [])
    alerts: list[dict[str, Any]] = []
    now = datetime.now(timezone.utc).isoformat()
    for hit in hits:
        source = hit.get("_source")
        if not isinstance(source, dict) or source.get("@sampledata") is not True:
            continue
        alert = dict(source)
        edgesec = alert.get("_edgesec") if isinstance(alert.get("_edgesec"), dict) else {}
        alert["_edgesec"] = {
            **edgesec,
            "sampledata": True,
            "sample_source": hit.get("_index") or index_pattern,
            "sample_replayed_at": now,
        }
        alerts.append(alert)
    return alerts
