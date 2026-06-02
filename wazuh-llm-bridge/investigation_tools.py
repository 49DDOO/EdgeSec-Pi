"""Tool definitions used by owner-facing Wazuh investigations."""
from __future__ import annotations

from typing import Any


def build_tools(history_search_limit: int) -> list[dict[str, Any]]:
    return [
        {
            "type": "function",
            "function": {
                "name": "get_wazuh_alerts",
                "description": "Retrieve recent Wazuh security alerts with optional filters.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 50},
                        "rule_id": {"type": "string"},
                        "level": {"type": "string", "description": "Alert level such as 10 or 10+"},
                        "agent_id": {"type": "string"},
                        "timestamp_start": {"type": "string"},
                        "timestamp_end": {"type": "string"},
                        "compact": {"type": "boolean", "default": True},
                    },
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "search_security_events",
                "description": (
                    "Search Wazuh historical events by free text, source IP, agent, rule, "
                    "severity level, or time range."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Use '*' when no keyword is needed."},
                        "time_range": {
                            "type": "string",
                            "enum": ["1h", "6h", "12h", "1d", "24h", "7d", "30d"],
                            "default": "24h",
                        },
                        "limit": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 1000,
                            "default": history_search_limit,
                        },
                        "rule_id": {"type": "string"},
                        "agent_id": {"type": "string"},
                        "level": {"type": "string"},
                        "srcip": {"type": "string"},
                        "dstip": {"type": "string"},
                        "compact": {"type": "boolean", "default": True},
                    },
                    "required": ["query"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "get_wazuh_agents",
                "description": "List Wazuh agents or inspect one agent by ID.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "agent_id": {"type": "string"},
                        "status": {
                            "type": "string",
                            "enum": ["active", "disconnected", "never_connected", "pending"],
                        },
                        "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 100},
                    },
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "get_wazuh_running_agents",
                "description": "List active Wazuh agents.",
                "parameters": {"type": "object", "properties": {}},
            },
        },
        {
            "type": "function",
            "function": {
                "name": "check_agent_health",
                "description": "Check whether a specific Wazuh agent is online and healthy.",
                "parameters": {
                    "type": "object",
                    "properties": {"agent_id": {"type": "string"}},
                    "required": ["agent_id"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "get_agent_processes",
                "description": "List running processes on a specific agent.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "agent_id": {"type": "string"},
                        "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 50},
                    },
                    "required": ["agent_id"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "get_agent_ports",
                "description": "List listening network ports on a specific agent.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "agent_id": {"type": "string"},
                        "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 50},
                    },
                    "required": ["agent_id"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "get_wazuh_rule_details",
                "description": (
                    "Fetch the current Wazuh rule metadata and XML rule block from "
                    "the Wazuh Manager API by rule ID."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {"rule_id": {"type": "string"}},
                    "required": ["rule_id"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "get_wazuh_cluster_health",
                "description": "Check Wazuh cluster health.",
                "parameters": {"type": "object", "properties": {}},
            },
        },
    ]


def tool_names(tools: list[dict[str, Any]]) -> set[str]:
    return {
        str(tool.get("function", {}).get("name") or "")
        for tool in tools
        if tool.get("function", {}).get("name")
    }
