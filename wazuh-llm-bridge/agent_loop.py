"""Tool-using agentic loop for deep alert investigation.

Architecture:
  1. We give the LLM a curated subset of Wazuh MCP tools (6 read tools +
     1 terminal `submit_final_verdict` tool).
  2. LLM autonomously decides which tools to call in what order.
  3. Each tool call → bridge executes via mcp_client → returns to LLM.
  4. LLM iterates until it calls `submit_final_verdict` (or hits MAX_ITERATIONS).
  5. We return (final_verdict_dict, evidence_log).

The `submit_final_verdict` tool is a structural trick: instead of asking
the model to free-form-emit JSON at the end (fragile), we make the JSON
output itself a tool call. LM Studio + Gemma's tool-calling parser
enforces the schema for us.

Safety bounds:
  - MAX_ITERATIONS prevents infinite loops
  - TOTAL_TIMEOUT_S bounds total wall time
  - Per-tool result is truncated to TOOL_RESULT_MAX_CHARS so context
    doesn't blow up
  - Tool errors are returned to the LLM as text (LLM recovers gracefully)
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from typing import Any, Awaitable, Callable, Optional

import httpx

import llm_client
import mcp_client

log = logging.getLogger("agent-loop")

MAX_ITERATIONS         = int(os.getenv("AGENTIC_MAX_ITERATIONS", "6"))
TOTAL_TIMEOUT_S        = float(os.getenv("AGENTIC_TIMEOUT_S", "120"))
TOOL_RESULT_MAX_CHARS  = int(os.getenv("AGENTIC_TOOL_RESULT_MAX", "1500"))

# Tool-call output stability. Gemma 4 31B occasionally regresses to Llama-style
# `<|tool_call|>` plain-text format at temp>=0.1, which our parser can't pick up
# as structured tool_calls (the bridge falls back to Stage-1 verdict). Greedy
# decoding (temp=0.0) is more deterministic and noticeably more stable.
# Stage-1 stays at 0.1 (set in app.py) — it doesn't use tools so the format
# risk is irrelevant there.
AGENTIC_TEMPERATURE = float(os.getenv("AGENTIC_TEMPERATURE", "0.0"))

LM_STUDIO_URL = os.getenv("LM_STUDIO_URL", "http://localhost:1234/v1/chat/completions")
LM_MODEL      = os.getenv("LM_MODEL",      "local-model")


# ── Tool catalog given to the LLM (OpenAI function-calling schema) ────
TOOLS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "search_security_events",
            "description": (
                "Search Wazuh historical events. Use to find related alerts from same "
                "IP, agent, rule, or matching a free-text query. Returns a list of "
                "events with timestamps, rule IDs, and key fields."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query":      {"type": "string",
                                   "description": "Lucene query — use '*' to match all"},
                    "srcip":      {"type": "string"},
                    "agent_id":   {"type": "string"},
                    "rule_id":    {"type": "string"},
                    "time_range": {"type": "string",
                                   "enum": ["1h", "6h", "12h", "24h", "7d", "30d"],
                                   "default": "7d"},
                    "limit":      {"type": "integer", "default": 20},
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_critical_vulnerabilities",
            "description": "List high-severity unpatched CVEs on a specific agent. "
                           "Useful when investigating an attack to know if the host has "
                           "exposed CVEs an attacker could chain.",
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
            "name": "check_agent_health",
            "description": "Check if a Wazuh agent is online, last seen, version. Use "
                           "to verify the host is still under management.",
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
            "description": "List running processes on an agent. Use when investigating "
                           "rootkit or FIM alerts to see what was active.",
            "parameters": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string"},
                    "limit":    {"type": "integer", "default": 50},
                },
                "required": ["agent_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_agent_ports",
            "description": "List listening TCP/UDP ports on an agent. Use when "
                           "investigating network anomalies or suspected backdoors.",
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
            "name": "submit_final_verdict",
            "description": (
                "Stop the investigation and submit your final classification. Call this "
                "as soon as you have enough evidence — typically after 2-4 read tools. "
                "DO NOT call any other tool after this."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "severity":     {"type": "string",
                                     "enum": ["critical", "high", "medium", "low", "info"]},
                    "summary_zh":   {"type": "string",
                                     "description": "白話繁體中文摘要，含本次調查發現的關鍵脈絡"},
                    "impact_zh":    {"type": "string",
                                     "description": "白話繁體中文：不處理會怎樣"},
                    "next_step_zh": {"type": "string",
                                     "description": "白話繁體中文：立即該做什麼"},
                    "investigation_summary_zh": {
                        "type": "string",
                        "description": (
                            "白話繁體中文 1–3 句，告訴非技術主管「你（AI）剛做了什麼調查、"
                            "發現了什麼、所以才下這個判斷」。禁止英文技術詞 (Lucene / query / "
                            "srcip / CVE / MITRE 等)；要把工具名翻成具體動作："
                            "search_security_events → 『查過去 N 天有沒有同 IP 的其他攻擊紀錄』；"
                            "get_critical_vulnerabilities → 『檢查這台主機有沒有未修補的高危漏洞』；"
                            "check_agent_health → 『確認主機目前是否在線』；"
                            "get_agent_processes → 『列出主機目前在跑的程式』；"
                            "get_agent_ports → 『檢查主機開了哪些網路埠』。"
                            "結尾解釋判斷邏輯（『因此我認為...』）。"
                            "範例：『我查了過去 7 天的紀錄，沒發現這個 IP 對其他主機下過手；"
                            "但本次以 admin 這種常見管理帳號嘗試登入失敗，仍屬高風險，建議立即封鎖。』"
                        ),
                    },
                    "root_cause":   {"type": "string",
                                     "description": "Technical English"},
                    "iocs":         {"type": "array", "items": {"type": "string"}},
                    "action":       {"type": "string", "description": "Technical English action"},
                    "mitre":        {"type": "string", "description": "MITRE technique like T1110"},
                },
                "required": ["severity", "summary_zh", "impact_zh", "next_step_zh",
                             "investigation_summary_zh"],
            },
        },
    },
]


# ── Core loop ──────────────────────────────────────────────────────────
async def run(alert: dict[str, Any],
              client: httpx.AsyncClient,
              base_user_prompt: str,
              reason_to_investigate: str = "",
              prior_stage1: Optional[dict] = None,
              ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Execute the agentic investigation loop.

    Args:
      alert:                  the raw Wazuh alert dict
      client:                 shared httpx.AsyncClient for the LM Studio call
      base_user_prompt:       the prompt body from build_prompt(alert)
                              (we wrap it with extra instructions about tools)
      reason_to_investigate:  if Stage-1 LLM escalated, the reason it cited
      prior_stage1:           parsed Stage-1 verdict (for context, not required)

    Returns:
      (final_verdict_dict, evidence_log)
        final_verdict_dict: the JSON shape from submit_final_verdict
        evidence_log:       list of {tool, args, result_preview} dicts
    """
    extra_instructions = []
    if reason_to_investigate:
        extra_instructions.append(
            f"Your Stage-1 quick triage said this needs deeper investigation:\n"
            f'  "{reason_to_investigate}"\n'
            "Use the tools to validate or refute that hypothesis."
        )
    if prior_stage1:
        extra_instructions.append(
            "Your Stage-1 initial verdict (subject to revision after tool calls):\n"
            f"  severity={prior_stage1.get('severity')}, "
            f"summary={prior_stage1.get('summary_zh', '')[:100]}"
        )
    extra_instructions.append(
        "Call 2-4 read tools to gather evidence, then call submit_final_verdict. "
        "Be specific in summary_zh — cite what you found, not generic boilerplate. "
        "CRITICAL: investigation_summary_zh must read like you are explaining your "
        "work to a non-technical Taiwanese business owner — no English tool names, "
        "no Lucene syntax, no jargon. Translate each tool call into a plain-Chinese "
        "verb phrase (see schema description for the mapping)."
    )

    messages: list[dict[str, Any]] = [
        {
            "role":    "system",
            "content": (
                "You are a SOC analyst investigating Wazuh alerts. You have read access "
                "to the SIEM through tools. Investigate efficiently — every tool call "
                "costs 5-10 seconds. Don't call the same tool twice with the same args. "
                "When you have enough evidence (usually after 2-4 calls), call "
                "submit_final_verdict to end."
            ),
        },
        {
            "role":    "user",
            "content": base_user_prompt + "\n\n" + "\n\n".join(extra_instructions),
        },
    ]

    evidence: list[dict[str, Any]] = []
    start    = time.time()

    for iteration in range(MAX_ITERATIONS):
        elapsed = time.time() - start
        if elapsed > TOTAL_TIMEOUT_S:
            raise TimeoutError(f"agentic loop exceeded {TOTAL_TIMEOUT_S}s "
                               f"({len(evidence)} tools called)")

        log.info("agent iter %d/%d  (elapsed %.1fs)",
                 iteration + 1, MAX_ITERATIONS, elapsed)
        assistant = await _llm_chat(messages, client)
        messages.append(_strip_for_history(assistant))

        tool_calls = assistant.get("tool_calls") or []
        if not tool_calls:
            # LLM gave up calling tools without ever submitting verdict.
            if iteration == 0:
                # First-round nudge: explicitly ask it to use tools.
                messages.append({
                    "role":    "user",
                    "content": "Please use the available tools to investigate, "
                               "then call submit_final_verdict.",
                })
                continue
            raise RuntimeError(
                f"agent stopped calling tools at iter {iteration} without verdict; "
                f"content was: {(assistant.get('content') or '')[:200]}"
            )

        for tc in tool_calls:
            fn_name, fn_args = _parse_tool_call(tc)
            log.info("  → %s(%s)", fn_name, str(fn_args)[:120])

            if fn_name == "submit_final_verdict":
                evidence.append({"tool": fn_name, "args": fn_args})
                log.info("agent submitted verdict after %d iteration(s), %d tool(s)",
                         iteration + 1, len(evidence))
                return fn_args, evidence

            # Execute the real MCP tool
            try:
                result = await mcp_client.call_tool(fn_name, fn_args)
                if not result:
                    result = "(no data returned)"
            except Exception as e:
                result = f"(tool error: {e})"
                log.warning("MCP tool %s failed: %s", fn_name, e)

            # Cap to avoid blowing up the context window
            if len(result) > TOOL_RESULT_MAX_CHARS:
                result = result[:TOOL_RESULT_MAX_CHARS] + (
                    f"\n[…truncated {len(result) - TOOL_RESULT_MAX_CHARS} chars]"
                )

            evidence.append({
                "tool":           fn_name,
                "args":           fn_args,
                "result_preview": result[:200].replace("\n", " "),
            })
            messages.append({
                "role":         "tool",
                "tool_call_id": tc.get("id", ""),
                "content":      result,
            })

    raise TimeoutError(
        f"agent exceeded {MAX_ITERATIONS} iterations without verdict "
        f"({len(evidence)} tools called)"
    )


# ── helpers ────────────────────────────────────────────────────────────
async def _llm_chat(messages: list[dict[str, Any]],
                    client: httpx.AsyncClient) -> dict[str, Any]:
    """Send one chat completion request to LM Studio with tools enabled.
    Returns the assistant message dict (OpenAI shape)."""
    payload = {
        "messages":    messages,
        "tools":       TOOLS,
        "tool_choice": "auto",
        "temperature": AGENTIC_TEMPERATURE,
        "stream":      False,
    }
    response = await llm_client.chat_completion(client, payload, timeout=90)
    return response["choices"][0]["message"]


def _strip_for_history(assistant_msg: dict) -> dict:
    """Some LM Studio responses include extra fields that break the
    next request when echoed back. Keep only what the protocol needs."""
    out: dict[str, Any] = {"role": "assistant"}
    if assistant_msg.get("content") is not None:
        out["content"] = assistant_msg["content"]
    if assistant_msg.get("tool_calls"):
        out["tool_calls"] = assistant_msg["tool_calls"]
    return out


def _parse_tool_call(tc: dict) -> tuple[str, dict]:
    """Extract (name, args_dict) from a tool_call object."""
    fn   = tc.get("function") or {}
    name = fn.get("name", "")
    raw  = fn.get("arguments", "{}")
    try:
        args = json.loads(raw) if isinstance(raw, str) else (raw or {})
    except json.JSONDecodeError:
        log.warning("agent: invalid JSON args for %s: %s", name, raw[:200])
        args = {}
    return name, args
