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
import logging
import os
import re
from typing import Any, Optional

import httpx

import investigation_prompting
import mcp_client
import prompt_safety
import tool_loop

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
    investigation_prompt = investigation_prompting.build_investigation_user_prompt(
        alert=alert,
        base_user_prompt=base_user_prompt,
        reason_to_investigate=reason_to_investigate,
        prior_stage1=prior_stage1,
    )

    messages: list[dict[str, Any]] = [
        {
            "role":    "system",
            "content": (
                "You are a SOC analyst investigating Wazuh alerts. You have read access "
                "to the SIEM through tools. Investigate efficiently — every tool call "
                "costs 5-10 seconds. Don't call the same tool twice with the same args. "
                "Every tool result is returned as an MDR evidence block with query "
                "boundary, historical trajectory, positive findings, negative findings, "
                "and unknown/not queried items. Use that structure in your reasoning. "
                f"{prompt_safety.UNTRUSTED_DATA_INSTRUCTIONS} "
                "When you have enough evidence (usually after 2-4 calls), call "
                "submit_final_verdict to end."
            ),
        },
        {
            "role":    "user",
            "content": investigation_prompt,
        },
    ]

    evidence: list[dict[str, Any]] = []

    async def on_no_tool_calls(
        assistant: dict[str, Any],
        iteration: int,
        _messages: list[dict[str, Any]],
    ) -> tool_loop.ToolLoopAction:
        # LLM gave up calling tools without ever submitting verdict.
        if iteration == 0:
            return tool_loop.ToolLoopAction.append({
                "role": "user",
                "content": (
                    "Please use the available tools to investigate, "
                    "then call submit_final_verdict."
                ),
            })
        raise RuntimeError(
            f"agent stopped calling tools at iter {iteration} without verdict; "
            f"content was: {(assistant.get('content') or '')[:200]}"
        )

    async def on_tool_call(invocation: tool_loop.ToolInvocation) -> tool_loop.ToolLoopAction:
        fn_name = invocation.name
        fn_args = invocation.args
        log.info("  → %s(%s)", fn_name, str(fn_args)[:120])

        if fn_name == "submit_final_verdict":
            fn_args = _apply_evidence_guardrails(fn_args, evidence)
            evidence.append({"tool": fn_name, "args": fn_args})
            log.info("agent submitted verdict after %d iteration(s), %d tool(s)",
                     invocation.round_index + 1, len(evidence))
            return tool_loop.ToolLoopAction.finish((fn_args, evidence))

        try:
            result = await mcp_client.call_tool(fn_name, fn_args)
            if not result:
                result = "(no data returned)"
        except Exception as e:
            result = f"(tool error: {e})"
            log.warning("MCP tool %s failed: %s", fn_name, e)

        if len(result) > TOOL_RESULT_MAX_CHARS:
            result = result[:TOOL_RESULT_MAX_CHARS] + (
                f"\n[…truncated {len(result) - TOOL_RESULT_MAX_CHARS} chars]"
            )

        evidence_block = investigation_prompting.format_tool_result_for_prompt(
            tool_name=fn_name,
            args=fn_args,
            result=result,
        )

        evidence.append({
            "tool": fn_name,
            "args": fn_args,
            "evidence_block": evidence_block[:1200],
            "result_preview": result[:200].replace("\n", " "),
        })
        return tool_loop.ToolLoopAction.append({
            "role": "tool",
            "tool_call_id": invocation.tool_call_id,
            "content": evidence_block,
        })

    return await tool_loop.run_tool_loop(
        client=client,
        messages=messages,
        tools=TOOLS,
        max_model_turns=MAX_ITERATIONS,
        on_tool_call=on_tool_call,
        on_no_tool_calls=on_no_tool_calls,
        total_timeout_s=TOTAL_TIMEOUT_S,
        temperature=AGENTIC_TEMPERATURE,
        completion_timeout_s=90,
        timeout_error_factory=lambda _elapsed: TimeoutError(
            f"agentic loop exceeded {TOTAL_TIMEOUT_S}s ({len(evidence)} tools called)"
        ),
        exhausted_error_factory=lambda _elapsed: TimeoutError(
            f"agent exceeded {MAX_ITERATIONS} iterations without verdict "
            f"({len(evidence)} tools called)"
        ),
        logger=log,
        log_label="agent",
    )


# ── guardrails ───────────────────────────────────────────────────────────
# 嚴重度排序，用來判斷是否需要強制升級（只升不降）。
_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_RANK_TO_SEVERITY = {v: k for k, v in _SEVERITY_RANK.items()}

# 失敗登入 / 成功登入的文字特徵（涵蓋 Linux PAM 與 Windows 事件用語）。
_FAILED_LOGIN_RE = re.compile(
    r"failed password|authentication failure|failed login|invalid user|"
    r"login failed|an account failed to log on|4625",
    re.IGNORECASE,
)
_SUCCESS_LOGIN_RE = re.compile(
    r"accepted password|session opened|successful login|login succeeded|"
    r"authentication success|an account was successfully logged on|4624",
    re.IGNORECASE,
)


def _evidence_text(evidence: list[dict[str, Any]]) -> str:
    """把已蒐集的證據文字併起來，供啟發式比對。"""
    parts: list[str] = []
    for item in evidence:
        for key in ("evidence_block", "result_preview"):
            value = item.get(key)
            if value:
                parts.append(str(value))
    return "\n".join(parts)


def _apply_evidence_guardrails(verdict: dict[str, Any],
                               evidence: list[dict[str, Any]]) -> dict[str, Any]:
    """證據後驗護欄：只升不降。

    目前規則：若蒐集到的歷史證據同時出現「同源失敗登入」與「成功登入」，
    代表可能已被猜中密碼（暴力破解成功），這是 evidence contract 明定要升級的
    情境。本地小模型常會漏判，因此在程式層強制把嚴重度拉到至少 high，並在
    調查說明前面標註原因，避免靜默改動。
    """
    text = _evidence_text(evidence)
    if not (_FAILED_LOGIN_RE.search(text) and _SUCCESS_LOGIN_RE.search(text)):
        return verdict

    current = str(verdict.get("severity") or "").lower()
    if _SEVERITY_RANK.get(current, 0) >= _SEVERITY_RANK["high"]:
        return verdict  # 模型已自行升級，不再變動

    verdict["severity"] = "high"
    note = "（系統護欄：證據顯示同源失敗登入後出現成功登入，已自動提升為高風險）"
    existing = str(verdict.get("investigation_summary_zh") or "").strip()
    verdict["investigation_summary_zh"] = f"{note}{existing}" if existing else note
    log.warning("guardrail: escalated severity %s→high (failed+success login pattern)",
                current or "unset")
    return verdict
