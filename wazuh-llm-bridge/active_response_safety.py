"""Safety guardrails for destructive Active Response."""
from __future__ import annotations

import fnmatch
import ipaddress
import os
import time
from typing import Any

from active_response_state import (
    DB_PATH,
    OPEN_BLOCK_STATUSES,
    OPEN_ISOLATION_STATUSES,
    _connect,
    block_ttl_s,
    claim_expired_block,
    claim_expired_isolation,
    expiring_stale_s,
    find_active_block,
    find_open_block,
    find_open_isolation,
    init_db_sync,
    isolation_ttl_s,
    list_active_blocks,
    list_active_isolations,
    list_blocks,
    list_expired_active_blocks,
    list_expired_active_isolations,
    list_isolations,
    mark_block_status,
    mark_isolation_status,
    record_block,
    record_isolation,
    record_release_isolation,
    record_unblock,
    release_max_attempts,
    release_retry_delay_s,
    unblock_max_attempts,
    unblock_retry_delay_s,
)

SUPPORTED_ISOLATION_PLATFORMS = ("linux", "macos", "windows")
ISOLATION_PLATFORM_ALIASES = {
    "darwin": "macos",
    "mac": "macos",
    "macos": "macos",
    "osx": "macos",
    "linux": "linux",
    "ubuntu": "linux",
    "debian": "linux",
    "rhel": "linux",
    "redhat": "linux",
    "centos": "linux",
    "rocky": "linux",
    "almalinux": "linux",
    "windows": "windows",
    "win": "windows",
    "win32": "windows",
    "win64": "windows",
}


class ActiveResponseDenied(RuntimeError):
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def normalize_ip(ip: str) -> str:
    try:
        parsed = ipaddress.ip_address(str(ip or "").strip())
    except ValueError as exc:
        raise ActiveResponseDenied("來源 IP 格式不正確，已拒絕執行封鎖。", 400) from exc
    if parsed.version != 4:
        raise ActiveResponseDenied("目前只允許封鎖 IPv4 來源；IPv6 請交由 IT 手動處理。", 400)
    return str(parsed)


def validate_block_request(agent_id: str, ip: str) -> dict[str, Any]:
    agent = str(agent_id or "").strip()
    validate_agent_id(agent)

    normalized_ip = normalize_ip(ip)
    parsed = ipaddress.ip_address(normalized_ip)

    allow_private = os.getenv("ACTIVE_RESPONSE_ALLOW_PRIVATE_TARGETS", "").strip() == "1"
    if not allow_private and not parsed.is_global:
        raise ActiveResponseDenied(
            "這不是可從網際網路路由的外部 IP，可能是公司內部、保留或測試位址；已拒絕自動封鎖。",
            409,
        )

    protected_network = _matching_protected_network(parsed)
    if protected_network:
        raise ActiveResponseDenied(
            f"來源 IP 落在受保護資產網段 {protected_network}，已拒絕自動封鎖。",
            409,
        )

    ttl = block_ttl_s()
    return {
        "agent_id": agent,
        "ip": normalized_ip,
        "ttl_s": ttl,
        "expires_at": time.time() + ttl,
    }


def validate_agent_id(agent_id: str) -> str:
    agent = str(agent_id or "").strip()
    if not agent.isdigit() or not (3 <= len(agent) <= 5):
        raise ActiveResponseDenied("Agent ID 不符合 Wazuh Active Response 格式，已拒絕執行。", 400)
    return agent


def normalize_isolation_platform(platform: str) -> str:
    value = str(platform or "").strip().lower()
    if not value:
        return ""
    return ISOLATION_PLATFORM_ALIASES.get(value, value)


def isolation_verified_platforms() -> set[str]:
    raw = os.getenv("ACTIVE_RESPONSE_ISOLATION_VERIFIED_PLATFORMS", "")
    platforms: set[str] = set()
    for item in raw.split(","):
        platform = normalize_isolation_platform(item)
        if platform in SUPPORTED_ISOLATION_PLATFORMS:
            platforms.add(platform)
    return platforms


def isolation_allow_unknown_platform() -> bool:
    return _truthy(os.getenv("ACTIVE_RESPONSE_ISOLATION_ALLOW_UNKNOWN_PLATFORM", ""))


def isolation_capability(
    platform: str = "",
    *,
    agent_id: str = "",
    agent_name: str = "",
) -> dict[str, Any]:
    raw_platform = str(platform or "").strip()
    normalized_platform = normalize_isolation_platform(raw_platform)
    verified_platforms = isolation_verified_platforms()
    allow_unknown = isolation_allow_unknown_platform()
    reasons: list[str] = []

    if not _isolate_command():
        reasons.append(
            "endpoint isolation is not enabled. Set WAZUH_ISOLATE_COMMAND after installing a tested isolation active-response script."
        )
    if not _release_isolate_command():
        reasons.append(
            "endpoint isolation release is not enabled. Set WAZUH_RELEASE_ISOLATE_COMMAND before showing isolation actions."
        )
    if not _isolation_preserve_ack():
        reasons.append(
            "endpoint isolation has no management-channel safety acknowledgement. Set ACTIVE_RESPONSE_ISOLATION_PRESERVE_CHANNELS_ACK=1 only after the script preserves Wazuh/management connectivity."
        )

    protected = _matching_never_isolate(agent_id, agent_name) if (agent_id or agent_name) else ""
    if protected:
        reasons.append(f"agent matches never-isolate rule {protected}.")

    platform_ready = False
    if raw_platform:
        if normalized_platform not in SUPPORTED_ISOLATION_PLATFORMS:
            reasons.append(
                f"agent platform {raw_platform} is not supported for endpoint isolation."
            )
        elif normalized_platform not in verified_platforms:
            reasons.append(
                f"agent platform {normalized_platform} has not passed real-machine isolate/release testing. Add it to ACTIVE_RESPONSE_ISOLATION_VERIFIED_PLATFORMS only after validation."
            )
        else:
            platform_ready = True
    elif allow_unknown:
        platform_ready = True
    else:
        reasons.append(
            "agent platform is unknown. Pass agent_platform/platform, or set ACTIVE_RESPONSE_ISOLATION_ALLOW_UNKNOWN_PLATFORM=1 only for lab use."
        )

    return {
        "enabled": not reasons,
        "reason": "; ".join(reasons),
        "platform": normalized_platform,
        "raw_platform": raw_platform,
        "platform_ready": platform_ready,
        "verified_platforms": sorted(verified_platforms),
        "supported_platforms": list(SUPPORTED_ISOLATION_PLATFORMS),
        "allow_unknown_platform": allow_unknown,
        "checks": {
            "isolate_command": bool(_isolate_command()),
            "release_command": bool(_release_isolate_command()),
            "management_channel_ack": _isolation_preserve_ack(),
            "never_isolate": bool(protected),
        },
    }


def isolation_actions_enabled(platform: str = "", *, agent_id: str = "", agent_name: str = "") -> bool:
    return bool(
        isolation_capability(platform, agent_id=agent_id, agent_name=agent_name).get("enabled")
    )


def isolation_disabled_reason(platform: str = "", *, agent_id: str = "", agent_name: str = "") -> str:
    return str(
        isolation_capability(platform, agent_id=agent_id, agent_name=agent_name).get("reason")
        or ""
    )


def validate_isolate_request(
    agent_id: str,
    *,
    agent_name: str = "",
    platform: str = "",
    ttl_s: int | None = None,
) -> dict[str, Any]:
    agent = validate_agent_id(agent_id)
    name = str(agent_name or "").strip()
    normalized_platform = normalize_isolation_platform(platform)

    if not _isolate_command():
        raise ActiveResponseDenied(
            "尚未啟用端點隔離命令；請先設定 WAZUH_ISOLATE_COMMAND。",
            501,
        )
    if not _release_isolate_command():
        raise ActiveResponseDenied(
            "尚未設定解除隔離命令；為避免單向隔離，請先設定 WAZUH_RELEASE_ISOLATE_COMMAND。",
            501,
        )
    if not _isolation_preserve_ack():
        raise ActiveResponseDenied(
            "尚未確認隔離腳本會保留 Wazuh/管理通道；請先測試腳本，並設定 ACTIVE_RESPONSE_ISOLATION_PRESERVE_CHANNELS_ACK=1。",
            409,
        )

    protected = _matching_never_isolate(agent, name)
    if protected:
        raise ActiveResponseDenied(
            f"端點符合永不隔離保護規則 {protected}，已拒絕自動隔離。",
            409,
        )

    capability = isolation_capability(platform, agent_id=agent, agent_name=name)
    if not capability.get("platform_ready"):
        reason = str(capability.get("reason") or "")
        if not str(platform or "").strip():
            raise ActiveResponseDenied(
                "無法確認這台 agent 的作業系統，已拒絕端點隔離；請從 Wazuh inventory 帶入 agent_platform，或只在實驗環境設定 ACTIVE_RESPONSE_ISOLATION_ALLOW_UNKNOWN_PLATFORM=1。",
                409,
            )
        if normalized_platform not in SUPPORTED_ISOLATION_PLATFORMS:
            raise ActiveResponseDenied(
                f"這台 agent 的作業系統 {platform} 尚未支援端點隔離，已拒絕執行。",
                409,
            )
        raise ActiveResponseDenied(
            f"這台 agent 的作業系統 {normalized_platform} 尚未通過真機隔離/解除測試，已拒絕執行；請完成測試後再加入 ACTIVE_RESPONSE_ISOLATION_VERIFIED_PLATFORMS。{(' ' + reason) if reason else ''}",
            409,
        )

    ttl = int(ttl_s or isolation_ttl_s())
    ttl = max(60, min(ttl, 86400))
    return {
        "agent_id": agent,
        "agent_name": name,
        "agent_platform": normalized_platform,
        "ttl_s": ttl,
        "expires_at": time.time() + ttl,
    }


def is_blockable_ip_candidate(ip: str) -> bool:
    try:
        normalized = normalize_ip(ip)
        parsed = ipaddress.ip_address(normalized)
    except ActiveResponseDenied:
        return False
    allow_private = os.getenv("ACTIVE_RESPONSE_ALLOW_PRIVATE_TARGETS", "").strip() == "1"
    return (allow_private or parsed.is_global) and not _matching_protected_network(parsed)


def _isolate_command() -> str:
    return os.getenv("WAZUH_ISOLATE_COMMAND", "").strip()


def _release_isolate_command() -> str:
    return os.getenv("WAZUH_RELEASE_ISOLATE_COMMAND", "").strip()


def _isolation_preserve_ack() -> bool:
    raw = os.getenv("ACTIVE_RESPONSE_ISOLATION_PRESERVE_CHANNELS_ACK", "").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _matching_protected_network(ip: ipaddress._BaseAddress) -> str:
    for network in _protected_networks():
        if ip in network:
            return str(network)
    return ""


def _protected_networks() -> list[ipaddress._BaseNetwork]:
    raw = ",".join([
        os.getenv("ACTIVE_RESPONSE_PROTECTED_CIDRS", ""),
        os.getenv("ACTIVE_RESPONSE_ASSET_CIDRS", ""),
    ])
    networks: list[ipaddress._BaseNetwork] = []
    for item in [*raw.split(","), *_org_profile_protected_network_values()]:
        text = item.strip()
        if not text:
            continue
        try:
            networks.append(ipaddress.ip_network(text, strict=False))
        except ValueError:
            continue
    return networks


def _matching_never_isolate(agent_id: str, agent_name: str = "") -> str:
    candidates = [str(agent_id or "").strip(), str(agent_name or "").strip()]
    candidates = [item for item in candidates if item]
    if not candidates:
        return ""
    for pattern in _never_isolate_patterns():
        needle = pattern.strip()
        if not needle:
            continue
        for candidate in candidates:
            if candidate == needle or fnmatch.fnmatchcase(candidate.lower(), needle.lower()):
                return needle
    return ""


def _never_isolate_patterns() -> list[str]:
    patterns: list[str] = []
    raw = os.getenv("ACTIVE_RESPONSE_NEVER_ISOLATE_AGENTS", "")
    patterns.extend(item.strip() for item in raw.split(",") if item.strip())
    patterns.extend(_org_profile_never_isolate_values())
    return patterns


def _org_profile_protected_network_values() -> list[str]:
    """Fold explicit org-profile asset IPs/CIDRs into the no-block list."""
    profile = _current_org_profile()

    values: list[str] = []

    def add_value(value: Any) -> None:
        if value is None:
            return
        if isinstance(value, str):
            for part in value.split(","):
                item = part.strip()
                if item:
                    values.append(item)
            return
        if isinstance(value, list):
            for item in value:
                add_value(item)

    org = profile.get("org") or {}
    for key in ("protected_cidrs", "asset_cidrs"):
        add_value(org.get(key))

    for asset in profile.get("assets") or []:
        if not isinstance(asset, dict):
            continue
        for key in (
            "ip",
            "ips",
            "ip_address",
            "ip_addresses",
            "cidr",
            "cidrs",
            "network",
            "networks",
            "protected_cidrs",
        ):
            add_value(asset.get(key))
    return values


def _org_profile_never_isolate_values() -> list[str]:
    profile = _current_org_profile()
    values: list[str] = []

    def add_value(value: Any) -> None:
        if value is None:
            return
        if isinstance(value, str):
            for part in value.split(","):
                item = part.strip()
                if item:
                    values.append(item)
            return
        if isinstance(value, list):
            for item in value:
                add_value(item)

    org = profile.get("org") or {}
    for key in ("never_isolate_agents", "isolation_protected_agents"):
        add_value(org.get(key))

    for asset in profile.get("assets") or []:
        if not isinstance(asset, dict):
            continue
        if not _truthy(asset.get("never_isolate")) and not _truthy(
            asset.get("isolation_protected")
        ) and not _truthy(asset.get("disable_isolation")):
            continue
        for key in ("pattern", "name", "hostname", "agent_id", "id"):
            add_value(asset.get(key))
    return values


def _current_org_profile() -> dict[str, Any]:
    try:
        import org_profile

        profile = org_profile.current()
        if not profile.get("assets") and not profile.get("org"):
            profile = org_profile.load()
        return profile
    except Exception:
        return {}


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}
