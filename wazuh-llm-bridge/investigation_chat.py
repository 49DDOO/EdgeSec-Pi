"""Owner-facing MCP investigation chat.

This module exposes a small, bounded tool-use loop for the Dashboard. It is
separate from ``agent_loop.py`` because this flow starts from a human question,
not from a specific Wazuh alert already being processed by the bridge.
"""
from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime
from typing import Any

import httpx

import mcp_client

log = logging.getLogger("investigation-chat")

LM_STUDIO_URL = os.getenv("LM_STUDIO_URL", "http://localhost:1234/v1/chat/completions")
LM_MODEL = os.getenv("LM_MODEL", "local-model")
CHAT_TIMEOUT_S = float(os.getenv("INVESTIGATION_CHAT_TIMEOUT_S", "120"))
MAX_TOOL_ROUNDS = int(os.getenv("INVESTIGATION_CHAT_MAX_TOOL_ROUNDS", "4"))
TOOL_RESULT_MAX_CHARS = int(os.getenv("INVESTIGATION_CHAT_TOOL_RESULT_MAX", "1800"))


TOOLS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "get_wazuh_alerts",
            "description": "Retrieve recent Wazuh security alerts with optional filters.",
            "parameters": {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 20},
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
                    "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 20},
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
            "name": "get_wazuh_cluster_health",
            "description": "Check Wazuh cluster health.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
]


def is_enabled() -> bool:
    return bool(mcp_client.is_enabled())


async def answer(messages: list[dict[str, str]]) -> dict[str, Any]:
    if not is_enabled():
        raise RuntimeError("MCP 尚未啟用：請設定 MCP_SERVER_URL 與 MCP_API_KEY。")

    clean_messages = _sanitize_messages(messages)
    if not clean_messages:
        raise ValueError("請先輸入想調查的問題。")

    evidence: list[dict[str, Any]] = []
    start = time.time()
    now_local = datetime.now().astimezone().isoformat(timespec="seconds")
    conversation: list[dict[str, Any]] = [
        {
            "role": "system",
            "content": (
                "你是 EdgeSec-Pi 的資安調查助理。你可以用 Wazuh MCP 工具查告警、"
                "端點狀態、程序與網路埠。回答要用繁體中文台灣用語，先講結論，再列出"
                "查到的證據與下一步。不要假裝已經執行封鎖、隔離、刪檔或停用帳號；"
                "你現在只能調查與建議。若資料不足，清楚說還缺什麼。"
                "所有重大結論都必須由本次工具查詢結果支撐。若工具結果沒有明確出現"
                "某個 IP、連接埠、程序、檔名、漏洞或時間點，不可以把它寫成已確認事實；"
                "只能寫成需要 IT 進一步查證。"
                "回答給非技術使用者看，不要輸出 Markdown 標記、反引號、英文工具名稱、"
                "JSON、查詢語法或參數名稱。請把工具行為翻成白話，例如「我查了最近 24 小時"
                "的高風險告警」或「我確認了目前在線的設備」。"
                f"目前系統時間是 {now_local}；當使用者說今天、最近 24 小時、最近 7 天時，"
                "必須依這個時間換算，不要使用過去訓練資料中的年份。"
            ),
        },
        *clean_messages[-10:],
    ]

    timeout = httpx.Timeout(CHAT_TIMEOUT_S, connect=5)
    async with httpx.AsyncClient(timeout=timeout) as client:
        for round_index in range(MAX_TOOL_ROUNDS + 1):
            if time.time() - start > CHAT_TIMEOUT_S:
                raise TimeoutError("調查逾時，請縮小問題範圍後再試。")

            assistant = await _llm_chat(client, conversation)
            conversation.append(_strip_for_history(assistant))
            tool_calls = assistant.get("tool_calls") or []

            if not tool_calls:
                answer = _clean_answer(
                    assistant.get("content") or "沒有產生回覆，請換個方式再問一次。"
                )
                if not evidence:
                    answer = _mark_unverified_answer(answer)
                return {
                    "answer_zh": answer,
                    "evidence": evidence,
                }

            if round_index >= MAX_TOOL_ROUNDS:
                conversation.append({
                    "role": "user",
                    "content": "工具查詢次數已達上限。請根據目前證據用繁體中文給出結論。",
                })
                continue

            for tool_call in tool_calls:
                name, args = _parse_tool_call(tool_call)
                if not _is_allowed_tool(name):
                    result = f"(tool {name} is not allowed in owner investigation chat)"
                else:
                    result = await mcp_client.call_tool(name, args) or "(no data returned)"

                if len(result) > TOOL_RESULT_MAX_CHARS:
                    result = result[:TOOL_RESULT_MAX_CHARS] + (
                        f"\n[truncated {len(result) - TOOL_RESULT_MAX_CHARS} chars]"
                    )

                evidence.append({
                    "tool": name,
                    "args": args,
                    "result_preview": result[:240].replace("\n", " "),
                })
                conversation.append({
                    "role": "tool",
                    "tool_call_id": tool_call.get("id", ""),
                    "content": result,
                })

    raise RuntimeError("調查流程沒有完成，請稍後再試。")


async def _llm_chat(client: httpx.AsyncClient, messages: list[dict[str, Any]]) -> dict[str, Any]:
    response = await client.post(
        LM_STUDIO_URL,
        json={
            "model": LM_MODEL,
            "messages": messages,
            "tools": TOOLS,
            "tool_choice": "auto",
            "temperature": 0.1,
            "stream": False,
        },
    )
    response.raise_for_status()
    return response.json()["choices"][0]["message"]


def _sanitize_messages(messages: list[dict[str, str]]) -> list[dict[str, str]]:
    clean: list[dict[str, str]] = []
    for message in messages:
        role = str(message.get("role") or "").strip()
        content = str(message.get("content") or "").strip()
        if role not in {"user", "assistant"} or not content:
            continue
        clean.append({"role": role, "content": content[:4000]})
    return clean


def _strip_for_history(message: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {"role": "assistant"}
    if message.get("content") is not None:
        out["content"] = message["content"]
    if message.get("tool_calls"):
        out["tool_calls"] = message["tool_calls"]
    return out


def _parse_tool_call(tool_call: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    function = tool_call.get("function") or {}
    name = str(function.get("name") or "")
    raw_args = function.get("arguments") or "{}"
    try:
        args = json.loads(raw_args) if isinstance(raw_args, str) else dict(raw_args)
    except Exception:
        log.warning("invalid tool args for %s: %s", name, str(raw_args)[:200])
        args = {}
    return name, args


def _is_allowed_tool(name: str) -> bool:
    return name in {tool["function"]["name"] for tool in TOOLS}


def _clean_answer(content: str) -> str:
    text = str(content or "").strip()
    # Some local models leak harmony-style channel tags in the visible content.
    # Keep the useful answer text and remove the transport markers.
    for marker in ("<|channel>final\n<channel|>", "<|channel>final", "<channel|>"):
        text = text.replace(marker, "")
    if "<|channel>thought" in text:
        text = text.split("<|channel>thought", 1)[-1]
    text = text.replace("**", "")
    text = text.replace("`", "")
    return text.strip()


def _mark_unverified_answer(text: str) -> str:
    """Make no-tool answers visibly conservative.

    The investigation page is allowed to answer simple questions, but a
    security conclusion without MCP evidence must not read like confirmed
    Wazuh fact. This protects owner-facing UX from LLM overreach.
    """
    prefix = "目前沒有查到可引用的 Wazuh MCP 證據。"
    if text.startswith(prefix):
        return text
    return f"{prefix}以下只能當作初步判斷，請 IT 以 Wazuh 原始紀錄確認。\n\n{text}"
