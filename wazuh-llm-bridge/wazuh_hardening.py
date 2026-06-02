"""Wazuh-side hardening package status checks.

The dashboard must not imply that endpoint detection is hardened just because
the EdgeSec-Pi repo contains optional agent-group recipes. This module checks
whether those recipes appear to be deployed in Wazuh Manager.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx

import wazuh
import wazuh_settings


ROOT = Path(__file__).resolve().parent.parent
AGENT_GROUPS_DIR = ROOT / "wazuh-stack" / "agent-groups"
EXPECTED_GROUPS = {"default", "macos", "linux", "windows"}
OS_GROUP_HINTS = {
    "macos": ("darwin", "mac", "macos"),
    "linux": ("linux", "ubuntu", "debian", "centos", "fedora", "rhel", "rocky", "alpine"),
    "windows": ("windows", "win32", "win64", "win"),
}


def _agent_group_recipe_files_present() -> bool:
    required = [
        AGENT_GROUPS_DIR / "setup-agent-groups.sh",
        AGENT_GROUPS_DIR / "default" / "agent.conf",
        AGENT_GROUPS_DIR / "macos" / "agent.conf",
        AGENT_GROUPS_DIR / "linux" / "agent.conf",
        AGENT_GROUPS_DIR / "windows" / "agent.conf",
    ]
    return all(path.exists() for path in required)


def _group_name(item: Any) -> str:
    if isinstance(item, str):
        return item.strip().lower()
    if isinstance(item, dict):
        return str(item.get("name") or item.get("group") or item.get("id") or "").strip().lower()
    return ""


def normalize_group_names(items: list[Any]) -> set[str]:
    return {name for name in (_group_name(item) for item in items) if name}


def agent_groups(agent: dict[str, Any]) -> set[str]:
    raw = agent.get("group", agent.get("groups", []))
    if isinstance(raw, str):
        return {part.strip().lower() for part in raw.split(",") if part.strip()}
    if isinstance(raw, list):
        return {str(part).strip().lower() for part in raw if str(part).strip()}
    return set()


def expected_group_for_agent(agent: dict[str, Any]) -> str:
    os_info = agent.get("os") if isinstance(agent.get("os"), dict) else {}
    text = " ".join([
        str(os_info.get("platform") or ""),
        str(os_info.get("name") or ""),
        str(agent.get("name") or ""),
    ]).lower()
    for group, hints in OS_GROUP_HINTS.items():
        if any(hint in text for hint in hints):
            return group
    return ""


def active_agents_with_known_os(agents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    known: list[dict[str, Any]] = []
    for agent in agents:
        status = str(agent.get("status") or "").lower()
        if status not in {"active", "online"}:
            continue
        agent_id = str(agent.get("id") or "").strip()
        agent_name = str(agent.get("name") or "").strip().lower()
        if agent_id == "000" or agent_name in {"wazuh.manager", "wazuh-manager"}:
            continue
        if expected_group_for_agent(agent):
            known.append(agent)
    return known


def evaluate_status(
    *,
    groups: list[Any],
    agents: list[dict[str, Any]],
    recipe_files_present: bool,
) -> dict[str, Any]:
    group_names = normalize_group_names(groups)
    missing_groups = sorted(EXPECTED_GROUPS - group_names)
    known_agents = active_agents_with_known_os(agents)
    agents_missing_group = []
    for agent in known_agents:
        expected = expected_group_for_agent(agent)
        if expected and expected not in agent_groups(agent):
            agents_missing_group.append({
                "id": str(agent.get("id") or ""),
                "name": str(agent.get("name") or ""),
                "expected_group": expected,
                "groups": sorted(agent_groups(agent)),
            })

    if not recipe_files_present:
        status = "warn"
        summary = "本機找不到 Wazuh agent-groups 強化包檔案。"
        next_step = "請確認 wazuh-stack/agent-groups 仍存在，或重新取得專案檔案。"
    elif missing_groups:
        status = "warn"
        summary = "Wazuh Manager 尚未完整建立 agent-groups 強化包。"
        next_step = "請 IT 執行：cd wazuh-stack/agent-groups && ./setup-agent-groups.sh。"
    elif agents_missing_group:
        status = "warn"
        summary = "部分在線端點尚未套用對應 OS 的 Wazuh 強化群組。"
        next_step = "請 IT 重新執行 setup-agent-groups.sh，或在 enroll 時指定 default + OS group。"
    elif not known_agents:
        status = "warn"
        summary = "強化群組已建立，但目前沒有可確認套用狀態的在線端點。"
        next_step = "等第一台端點 online 後，重新整理首次設定狀態。"
    else:
        status = "ok"
        summary = "Wazuh agent-groups 強化包已建立，且在線端點有套用對應 OS 群組。"
        next_step = ""

    return {
        "status": status,
        "summary_zh": summary,
        "next_step_zh": next_step,
        "groups_present": sorted(group_names & EXPECTED_GROUPS),
        "missing_groups": missing_groups,
        "agents_checked": len(known_agents),
        "agents_missing_group": agents_missing_group,
        "recipe_files_present": recipe_files_present,
    }


async def collect_status() -> dict[str, Any]:
    cfg = wazuh_settings.api_config()
    if not cfg.get("password"):
        return {
            "status": "skip",
            "summary_zh": "尚未設定 Wazuh API 密碼，暫時無法確認偵測強化包。",
            "next_step_zh": "先完成 Wazuh 連線設定，再確認 agent-groups 是否已套用。",
            "groups_present": [],
            "missing_groups": sorted(EXPECTED_GROUPS),
            "agents_checked": 0,
            "agents_missing_group": [],
            "recipe_files_present": _agent_group_recipe_files_present(),
        }

    try:
        groups = await wazuh.list_agent_groups()
        agents = await wazuh.list_agents_with_groups()
    except (httpx.HTTPError, RuntimeError, OSError, ValueError) as exc:
        return {
            "status": "warn",
            "summary_zh": "目前無法從 Wazuh Manager 確認 agent-groups 強化狀態。",
            "next_step_zh": "請 IT 確認 Wazuh API 權限，或手動檢查 /var/ossec/etc/shared/。 ",
            "detail_zh": repr(exc),
            "groups_present": [],
            "missing_groups": sorted(EXPECTED_GROUPS),
            "agents_checked": 0,
            "agents_missing_group": [],
            "recipe_files_present": _agent_group_recipe_files_present(),
        }

    return evaluate_status(
        groups=groups,
        agents=agents,
        recipe_files_present=_agent_group_recipe_files_present(),
    )
