"""Deterministic response recommendations for alert action buttons.

The LLM may explain an alert, but destructive actions must be gated by
structured alert fields. In particular, do not offer "block source IP" from
LLM-generated IOC text alone.
"""
from __future__ import annotations

import ipaddress
from typing import Any

import active_response_safety


IP_KEYS_SOURCE = (
    "srcip",
    "src_ip",
    "source_ip",
    "source.ip",
    "client_ip",
    "client.ip",
)
IP_KEYS_DESTINATION = (
    "dstip",
    "dst_ip",
    "destination_ip",
    "destination.ip",
    "dest_ip",
    "dest.ip",
)

COMPROMISE_KEYWORDS = (
    "backdoor",
    "beacon",
    "c2",
    "command and control",
    "credential dumping",
    "exfiltration",
    "lateral movement",
    "login succeeded",
    "malware",
    "persistence",
    "reverse shell",
    "rootkit",
    "successful login",
    "trojan",
    "webshell",
    "已成功登入",
    "成功登入",
    "外洩",
    "木馬",
    "後門",
    "惡意程式",
    "橫向移動",
    "疑似中毒",
    "竊取憑證",
)


def recommend(alert: dict[str, Any], parsed: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return the allowed response actions for one alert.

    The result is intentionally plain dict data so Slack, Dashboard, and tests
    can share it without importing UI-specific types.
    """
    parsed = parsed or {}
    source_ip = _extract_ip(alert, IP_KEYS_SOURCE)
    destination_ip = _extract_ip(alert, IP_KEYS_DESTINATION)
    agent_ip = _agent_ip(alert)
    source = _parse_ip(source_ip)
    destination = _parse_ip(destination_ip)
    agent_addr = _parse_ip(agent_ip)

    direction = _direction(source, destination, agent_addr)
    source_is_external = bool(source and source.is_global)
    source_is_agent = bool(source and agent_addr and source == agent_addr)
    compromise_signal = _has_compromise_signal(alert, parsed)

    block_source_ips: list[str] = []
    if source_is_external and active_response_safety.is_blockable_ip_candidate(source_ip):
        block_source_ips.append(active_response_safety.normalize_ip(source_ip))

    allow_isolate = _should_offer_isolation(
        direction=direction,
        source_is_agent=source_is_agent,
        compromise_signal=compromise_signal,
        alert=alert,
        parsed=parsed,
    )

    return {
        "direction": direction,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "agent_ip": agent_ip,
        "block_source_ips": block_source_ips,
        "allow_isolate_endpoint": allow_isolate,
        "compromise_signal": compromise_signal,
        "reason_zh": _reason_zh(
            direction=direction,
            source_ip=source_ip,
            destination_ip=destination_ip,
            has_block=bool(block_source_ips),
            allow_isolate=allow_isolate,
            compromise_signal=compromise_signal,
        ),
    }


def _extract_ip(alert: dict[str, Any], keys: tuple[str, ...]) -> str:
    data = alert.get("data") if isinstance(alert.get("data"), dict) else {}
    for key in keys:
        for value in (_lookup(data, key), _lookup(alert, key)):
            text = str(value or "").strip()
            if _parse_ip(text):
                return str(ipaddress.ip_address(text))
    return ""


def _lookup(obj: dict[str, Any], dotted_key: str) -> Any:
    if dotted_key in obj:
        return obj.get(dotted_key)
    cur: Any = obj
    for part in dotted_key.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _agent_ip(alert: dict[str, Any]) -> str:
    agent = alert.get("agent") if isinstance(alert.get("agent"), dict) else {}
    for key in ("ip", "agent_ip"):
        text = str(agent.get(key) or "").strip()
        if _parse_ip(text):
            return str(ipaddress.ip_address(text))
    return ""


def _parse_ip(value: str) -> ipaddress._BaseAddress | None:
    try:
        return ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return None


def _direction(
    source: ipaddress._BaseAddress | None,
    destination: ipaddress._BaseAddress | None,
    agent_addr: ipaddress._BaseAddress | None,
) -> str:
    if source and source.is_global:
        return "external_to_endpoint"
    if source and not source.is_global and destination and destination.is_global:
        if agent_addr and source == agent_addr:
            return "endpoint_to_external"
        return "internal_to_external"
    if source and not source.is_global and destination and not destination.is_global:
        if agent_addr and source == agent_addr:
            return "endpoint_to_internal"
        return "internal_source"
    if source and not source.is_global:
        if agent_addr and source == agent_addr:
            return "endpoint_source"
        return "internal_source"
    return "unknown"


def _has_compromise_signal(alert: dict[str, Any], parsed: dict[str, Any]) -> bool:
    severity = str(parsed.get("severity") or "").strip().lower()
    if severity == "critical":
        return True

    text_parts: list[str] = []
    rule = alert.get("rule") if isinstance(alert.get("rule"), dict) else {}
    data = alert.get("data") if isinstance(alert.get("data"), dict) else {}
    text_parts.extend([
        str(rule.get("description") or ""),
        str(data.get("event") or ""),
        str(data.get("action") or ""),
        str(parsed.get("summary_zh") or ""),
        str(parsed.get("impact_zh") or ""),
        str(parsed.get("next_step_zh") or ""),
        str(parsed.get("root_cause") or ""),
        str(parsed.get("action") or ""),
    ])
    haystack = "\n".join(text_parts).lower()
    return any(keyword in haystack for keyword in COMPROMISE_KEYWORDS)


def _should_offer_isolation(
    *,
    direction: str,
    source_is_agent: bool,
    compromise_signal: bool,
    alert: dict[str, Any],
    parsed: dict[str, Any],
) -> bool:
    if compromise_signal:
        return True

    severity = str(parsed.get("severity") or "").strip().lower()
    rule = alert.get("rule") if isinstance(alert.get("rule"), dict) else {}
    try:
        rule_level = int(rule.get("level") or 0)
    except (TypeError, ValueError):
        rule_level = 0

    if direction in {"endpoint_to_external", "endpoint_to_internal"}:
        return severity in {"high", "critical"} or rule_level >= 10

    if direction == "endpoint_source":
        return severity in {"high", "critical"} or rule_level >= 12

    if source_is_agent and (severity in {"high", "critical"} or rule_level >= 10):
        return True

    return False


def _reason_zh(
    *,
    direction: str,
    source_ip: str,
    destination_ip: str,
    has_block: bool,
    allow_isolate: bool,
    compromise_signal: bool,
) -> str:
    if has_block and allow_isolate:
        return "來源是外部 IP，且內容出現疑似成功入侵或中毒跡象；可先封來源，必要時隔離端點。"
    if has_block:
        return "來源是可封鎖的外部 IP；先封來源 IP，避免它繼續嘗試。"
    if direction.startswith("endpoint_to") and allow_isolate:
        return "可疑流量看起來是這台端點主動往外或往內連線；不要封來源 IP，優先隔離端點。"
    if allow_isolate:
        return "告警內容有疑似中毒或成功入侵跡象；優先隔離端點，再請 IT 查主機。"
    if source_ip and not has_block:
        return "來源不是可安全自動封鎖的外部 IP；不要盲目封鎖，請先查來源與受影響主機。"
    if destination_ip and compromise_signal:
        return "沒有明確可封鎖來源，但有疑似入侵跡象；請 IT 優先查受影響主機。"
    return "沒有足夠結構化證據可執行破壞性處置；先查看 Dashboard 或請 IT 查證。"
