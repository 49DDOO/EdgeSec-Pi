"""Evidence formatting and query-normalization helpers for investigations."""
from __future__ import annotations

import json
import os
import re
from typing import Any

import prompt_safety


TOOL_RESULT_MAX_CHARS = int(os.getenv("INVESTIGATION_CHAT_TOOL_RESULT_MAX", "12000"))
HISTORY_SEARCH_LIMIT = int(os.getenv("INVESTIGATION_CHAT_HISTORY_LIMIT", "500"))
MODEL_EVENT_SAMPLE_LIMIT = int(os.getenv("INVESTIGATION_CHAT_MODEL_EVENT_SAMPLE_LIMIT", "30"))


def guess_search_args(question: str) -> dict[str, Any]:
    text = str(question or "")
    args: dict[str, Any] = {
        "query": "*",
        "time_range": "24h",
        "limit": 20,
        "compact": True,
    }
    if re.search(r"7\s*天|一週|最近\s*7", text):
        args["time_range"] = "7d"
        args["limit"] = HISTORY_SEARCH_LIMIT
    elif re.search(r"30\s*天|一個月", text):
        args["time_range"] = "30d"
        args["limit"] = HISTORY_SEARCH_LIMIT
    elif re.search(r"1\s*小時|一小時", text):
        args["time_range"] = "1h"
    elif re.search(r"24\s*小時|一天|1\s*天|最近", text):
        args["limit"] = HISTORY_SEARCH_LIMIT

    ip_match = extract_query_source_ip(text)
    if ip_match and not is_loopback_ip(ip_match):
        args["srcip"] = ip_match
        args["query"] = ip_match

    rule_match = re.search(r"(?:rule|規則)\s*(?:id)?\s*[:：#]?\s*([A-Za-z0-9_.-]+)", text, re.I)
    if rule_match:
        args["rule_id"] = rule_match.group(1)

    agent_match = re.search(r"(?:agent|端點|電腦)\s*(?:id)?\s*[:：#]?\s*([A-Za-z0-9_.-]+)", text, re.I)
    if agent_match:
        args["agent_id"] = agent_match.group(1)

    return normalize_tool_args("search_security_events", args)


def cap_text(text: str, max_chars: int) -> str:
    raw = str(text or "")
    if len(raw) <= max_chars:
        return raw
    return raw[:max_chars] + f"\n[truncated {len(raw) - max_chars} chars]"


def normalize_tool_args(tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(args or {})
    if tool_name not in {"search_security_events", "get_wazuh_alerts"}:
        return normalized

    srcip = str(normalized.get("srcip") or normalized.get("src_ip") or "").strip()
    rule_id = str(normalized.get("rule_id") or "").strip()
    if srcip and (is_loopback_ip(srcip) or rule_has_no_source_ip(rule_id)):
        normalized.pop("srcip", None)
        normalized.pop("src_ip", None)

    query = str(normalized.get("query") or "").strip()
    if query and (is_loopback_ip(query) or (rule_has_no_source_ip(rule_id) and looks_like_ip(query))):
        normalized["query"] = "*"
    elif not query and tool_name == "search_security_events":
        normalized["query"] = "*"

    time_range = str(normalized.get("time_range") or "").lower()
    history_query = (
        tool_name == "search_security_events"
        and (
            time_range in {"24h", "1d", "7d", "30d"}
            or normalized.get("rule_id")
            or normalized.get("agent_id")
        )
    )
    if history_query:
        try:
            current_limit = int(normalized.get("limit") or 0)
        except Exception:
            current_limit = 0
        if current_limit < HISTORY_SEARCH_LIMIT:
            normalized["limit"] = HISTORY_SEARCH_LIMIT

    return normalized


def extract_query_source_ip(text: str) -> str:
    """Extract only explicit source IP, not Agent/endpoint IP."""
    explicit = re.search(r"(?:來源\s*IP|source\s*ip|srcip|src_ip)\s*[:：=]\s*((?:\d{1,3}\.){3}\d{1,3})", text, re.I)
    if explicit:
        return explicit.group(1)
    for match in re.finditer(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
        prefix = text[max(0, match.start() - 24):match.start()].lower()
        if any(label in prefix for label in ("agent ip", "電腦 ip", "端點 ip")):
            continue
        return match.group(0)
    return ""


def looks_like_ip(value: str) -> bool:
    return bool(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", str(value or "").strip()))


def rule_has_no_source_ip(rule_id: str) -> bool:
    return str(rule_id or "").strip() in {"533"}


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


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


def text(value: Any) -> str:
    return str(value or "").strip()


def model_tool_result(tool_name: str, args: dict[str, Any], raw_result: str) -> str:
    if tool_name in {"search_security_events", "get_wazuh_alerts"}:
        structured = structured_wazuh_events_for_model(raw_result, args)
        if structured:
            return prompt_safety.untrusted_data_block(
                "structured Wazuh MCP tool result",
                structured,
                limit=TOOL_RESULT_MAX_CHARS,
            )
    return prompt_safety.untrusted_data_block(
        "raw MCP tool result",
        raw_result,
        limit=TOOL_RESULT_MAX_CHARS,
    )


def structured_wazuh_events_for_model(raw_result: str, args: dict[str, Any]) -> str:
    payload = extract_json_object(raw_result)
    if not payload:
        return ""
    data = payload.get("data") if isinstance(payload.get("data"), dict) else payload
    if not isinstance(data, dict):
        return ""
    items = data.get("affected_items")
    if not isinstance(items, list):
        return ""

    total = data.get("total_affected_items")
    failed = data.get("total_failed_items")
    timestamps = [
        str(item.get("timestamp") or "")
        for item in items
        if isinstance(item, dict) and item.get("timestamp")
    ]
    agents: dict[str, int] = {}
    rules: dict[str, int] = {}
    levels: dict[str, int] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        agent = as_dict(item.get("agent"))
        rule = as_dict(item.get("rule"))
        agent_name = text(agent.get("name") or agent.get("id") or "unknown")
        rule_key = text(rule.get("id") or "unknown")
        rule_desc = text(rule.get("description"))
        if rule_desc:
            rule_key = f"{rule_key} {rule_desc[:80]}"
        level = text(rule.get("level") or "unknown")
        agents[agent_name] = agents.get(agent_name, 0) + 1
        rules[rule_key] = rules.get(rule_key, 0) + 1
        levels[level] = levels.get(level, 0) + 1

    sorted_items = sorted(
        [item for item in items if isinstance(item, dict)],
        key=lambda item: str(item.get("timestamp") or ""),
        reverse=True,
    )
    sample_lines: list[str] = []
    for item in sorted_items[:MODEL_EVENT_SAMPLE_LIMIT]:
        agent = as_dict(item.get("agent"))
        rule = as_dict(item.get("rule"))
        full_log = text(item.get("full_log")).replace("\n", " ")
        sample_lines.append(
            "- "
            f"time={text(item.get('timestamp')) or '-'}; "
            f"agent={text(agent.get('name') or agent.get('id')) or '-'}; "
            f"rule={text(rule.get('id')) or '-'}; "
            f"level={text(rule.get('level')) or '-'}; "
            f"description={text(rule.get('description')) or '-'}; "
            f"log={full_log[:500] or '-'}"
        )

    query_limit = args.get("limit")
    header = [
        "Wazuh MCP structured evidence for LLM analysis.",
        f"Query args: {json.dumps(args, ensure_ascii=False, sort_keys=True)}",
        f"Total matched by Wazuh: {total if total is not None else 'unknown'}",
        f"Returned in this response: {len(items)}",
        f"Failed items: {failed if failed is not None else 'unknown'}",
        f"Query limit: {query_limit if query_limit is not None else 'unknown'}",
    ]
    if total is not None and query_limit is not None:
        try:
            if int(total) > int(query_limit):
                header.append(
                    "Important: total matched is greater than query limit; analyze as a sample, not complete history."
                )
        except Exception:
            pass
    if timestamps:
        header.append(f"Returned time range: {min(timestamps)} to {max(timestamps)}")
    header.extend([
        f"Counts by agent: {json.dumps(top_counts(agents), ensure_ascii=False)}",
        f"Counts by rule: {json.dumps(top_counts(rules), ensure_ascii=False)}",
        f"Counts by level: {json.dumps(top_counts(levels), ensure_ascii=False)}",
        f"Representative latest {len(sample_lines)} events:",
        *sample_lines,
    ])
    return "\n".join(header)


def extract_json_object(value: str) -> dict[str, Any] | None:
    raw = str(value or "").strip()
    candidates = [raw]
    first_brace = raw.find("{")
    last_brace = raw.rfind("}")
    if first_brace >= 0 and last_brace > first_brace:
        candidates.append(raw[first_brace:last_brace + 1])
    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
        except Exception:
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


def top_counts(counts: dict[str, int], limit: int = 10) -> dict[str, int]:
    return dict(sorted(counts.items(), key=lambda item: item[1], reverse=True)[:limit])


def is_loopback_ip(value: str) -> bool:
    normalized = str(value or "").strip().lower()
    return normalized in {"127.0.0.1", "::1", "localhost"} or normalized.startswith("127.")
