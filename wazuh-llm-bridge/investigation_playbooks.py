"""Deterministic fast playbooks for owner-facing alert investigations."""
from __future__ import annotations

import os
import re
from collections.abc import Awaitable, Callable
from typing import Any

import httpx

import investigation_context
import investigation_evidence
import llm_client
import mcp_client


CHAT_TIMEOUT_S = float(os.getenv("INVESTIGATION_CHAT_TIMEOUT_S", "45"))
TOOL_UI_RESULT_MAX_CHARS = int(os.getenv("INVESTIGATION_CHAT_UI_RESULT_MAX", "50000"))
FAST_PLAYBOOK_TOOL_RESULT_MAX_CHARS = int(os.getenv("INVESTIGATION_CHAT_FAST_TOOL_RESULT_MAX", "3500"))

PlainChat = Callable[[httpx.AsyncClient, list[dict[str, Any]]], Awaitable[str]]
GuardAnswer = Callable[[str, list[dict[str, Any]]], str]
DeterministicSuggestions = Callable[[str, list[dict[str, Any]]], list[dict[str, str]]]


async def try_fast_alert_playbook(
    row: dict[str, Any],
    question: str,
    *,
    plain_llm_chat: PlainChat | None = None,
    guard_owner_answer: GuardAnswer,
    deterministic_suggestions: DeterministicSuggestions,
) -> dict[str, Any] | None:
    plan = select_alert_playbook(row, question)
    if not plan:
        return None

    evidence: list[dict[str, Any]] = []
    result = await mcp_client.call_tool(plan["tool"], plan["args"]) or "(no data returned)"
    ui_result = investigation_evidence.cap_text(result, TOOL_UI_RESULT_MAX_CHARS)
    model_result = investigation_evidence.cap_text(
        investigation_evidence.model_tool_result(plan["tool"], plan["args"], result),
        FAST_PLAYBOOK_TOOL_RESULT_MAX_CHARS,
    )
    evidence.append({
        "tool": plan["tool"],
        "args": plan["args"],
        "result_preview": model_result[:240].replace("\n", " "),
        "result_log": ui_result,
    })

    facts = investigation_context.alert_facts(row)
    prompt = investigation_context.build_fast_playbook_prompt(facts, question, plan, model_result)
    timeout = httpx.Timeout(CHAT_TIMEOUT_S, connect=5)
    async with httpx.AsyncClient(timeout=timeout) as client:
        answer = await (plain_llm_chat or _plain_llm_chat)(
            client,
            [
                {"role": "system", "content": "請只用繁體中文回答資安查證結論。"},
                {"role": "user", "content": prompt},
            ],
        )

    clean_answer = guard_owner_answer(_clean_answer(answer), evidence)
    return {
        "answer_zh": clean_answer,
        "evidence": evidence,
        "suggestions": deterministic_suggestions(clean_answer, evidence),
    }


def select_alert_playbook(row: dict[str, Any], question: str) -> dict[str, Any] | None:
    facts = investigation_context.alert_facts(row)
    text = str(question or "").strip()

    asks_source = bool(re.search(r"(來源|source\s*ip|srcip|同\s*ip|這個\s*ip|攻擊其他|其他電腦|相關事件)", text, re.I))
    asks_agent = bool(re.search(r"(這台|此電腦|這部|端點|agent|主機|設備|電腦|24\s*小時|異常)", text, re.I))
    asks_rule = bool(re.search(r"(rule|規則|同規則|重複|再發生|幾次)", text, re.I))
    asks_decision = bool(re.search(r"(立刻|馬上|需要.*it|交給\s*it|處理嗎|調查摘要|it\s*調查|摘要)", text, re.I))

    if asks_source and facts["source_ip"] and not investigation_evidence.is_loopback_ip(facts["source_ip"]):
        return search_playbook(
            key="source_ip_history",
            label="來源 IP 歷史關聯",
            reason="確認同一來源 IP 是否在指定時間內打到其他電腦或規則。",
            args={
                "query": "*",
                "srcip": facts["source_ip"],
                "time_range": question_time_range(text, "7d"),
                "limit": investigation_evidence.HISTORY_SEARCH_LIMIT,
                "compact": True,
            },
        )

    if asks_rule and facts["rule_id"]:
        return search_playbook(
            key="rule_history",
            label="同規則歷史關聯",
            reason="確認同一 Wazuh 規則是否重複發生，以及影響哪些電腦。",
            args={
                "query": "*",
                "rule_id": facts["rule_id"],
                "time_range": question_time_range(text, "7d"),
                "limit": investigation_evidence.HISTORY_SEARCH_LIMIT,
                "compact": True,
            },
        )

    if asks_agent and facts["agent_id"]:
        return search_playbook(
            key="agent_recent_activity",
            label="端點近期事件",
            reason="確認這台受監控電腦近期是否還有其他異常事件。",
            args={
                "query": "*",
                "agent_id": facts["agent_id"],
                "time_range": question_time_range(text, "24h"),
                "limit": investigation_evidence.HISTORY_SEARCH_LIMIT,
                "compact": True,
            },
        )

    if asks_decision:
        if facts["source_ip"] and not investigation_evidence.is_loopback_ip(facts["source_ip"]):
            return search_playbook(
                key="source_ip_decision",
                label="來源 IP 處置判斷",
                reason="用同一來源 IP 的歷史關聯支撐是否需要交給 IT。",
                args={
                    "query": "*",
                    "srcip": facts["source_ip"],
                    "time_range": "7d",
                    "limit": investigation_evidence.HISTORY_SEARCH_LIMIT,
                    "compact": True,
                },
            )
        if facts["agent_id"]:
            return search_playbook(
                key="agent_decision",
                label="端點處置判斷",
                reason="用同一端點近期事件支撐是否需要交給 IT。",
                args={
                    "query": "*",
                    "agent_id": facts["agent_id"],
                    "time_range": "24h",
                    "limit": investigation_evidence.HISTORY_SEARCH_LIMIT,
                    "compact": True,
                },
            )
        if facts["rule_id"]:
            return search_playbook(
                key="rule_decision",
                label="規則處置判斷",
                reason="用同一規則近期重複程度支撐是否需要交給 IT。",
                args={
                    "query": "*",
                    "rule_id": facts["rule_id"],
                    "time_range": "7d",
                    "limit": investigation_evidence.HISTORY_SEARCH_LIMIT,
                    "compact": True,
                },
            )

    return None


def search_playbook(key: str, label: str, reason: str, args: dict[str, Any]) -> dict[str, Any]:
    return {
        "key": key,
        "label": label,
        "reason": reason,
        "tool": "search_security_events",
        "args": investigation_evidence.normalize_tool_args("search_security_events", args),
    }


def question_time_range(question: str, default: str) -> str:
    text = str(question or "")
    if re.search(r"30\s*天|一個月", text):
        return "30d"
    if re.search(r"7\s*天|一週|一星期|最近\s*7", text):
        return "7d"
    if re.search(r"12\s*小時", text):
        return "12h"
    if re.search(r"6\s*小時", text):
        return "6h"
    if re.search(r"1\s*小時|一小時", text):
        return "1h"
    if re.search(r"24\s*小時|一天|1\s*天|今天|最近", text):
        return "24h"
    return default


async def _plain_llm_chat(client: httpx.AsyncClient, messages: list[dict[str, Any]]) -> str:
    response = await llm_client.chat_completion(
        client,
        {
            "messages": messages,
            "temperature": 0.1,
            "stream": False,
        },
    )
    return str(response["choices"][0]["message"].get("content") or "")


def _clean_answer(content: str) -> str:
    text = str(content or "").strip()
    for marker in ("<|channel>final\n<channel|>", "<|channel>final", "<channel|>"):
        text = text.replace(marker, "")
    if "<|channel>thought" in text:
        text = text.split("<|channel>thought", 1)[-1]
    text = re.sub(r"(?m)^\s{0,3}#{1,6}\s*", "", text)
    text = re.sub(r"(?m)^\s*-{3,}\s*$", "", text)
    text = text.replace("**", "")
    text = text.replace("`", "")
    return text.strip()
