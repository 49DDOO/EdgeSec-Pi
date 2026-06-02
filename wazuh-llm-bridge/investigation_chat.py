"""Owner-facing MCP investigation chat.

This module exposes a small, bounded tool-use loop for the Dashboard. It is
separate from ``agent_loop.py`` because this flow starts from a human question,
not from a specific Wazuh alert already being processed by the bridge.
"""
from __future__ import annotations

import logging
import os
import re
from datetime import datetime
from typing import Any

import httpx

import db
import investigation_context
import investigation_evidence
import investigation_playbooks
import investigation_rules
import investigation_suggestions
import investigation_tools
import llm_client
import mcp_client
import prompt_safety
import tool_loop

log = logging.getLogger("investigation-chat")

CHAT_TIMEOUT_S = float(os.getenv("INVESTIGATION_CHAT_TIMEOUT_S", "45"))
MAX_TOOL_ROUNDS = int(os.getenv("INVESTIGATION_CHAT_MAX_TOOL_ROUNDS", "2"))
TOOL_UI_RESULT_MAX_CHARS = int(os.getenv("INVESTIGATION_CHAT_UI_RESULT_MAX", "50000"))
FAST_PLAYBOOK_TOOL_RESULT_MAX_CHARS = int(os.getenv("INVESTIGATION_CHAT_FAST_TOOL_RESULT_MAX", "3500"))
HISTORY_SEARCH_LIMIT = int(os.getenv("INVESTIGATION_CHAT_HISTORY_LIMIT", "500"))

_alert_facts = investigation_context.alert_facts
_build_alert_question_context = investigation_context.build_alert_question_context
_build_fast_playbook_prompt = investigation_context.build_fast_playbook_prompt
_cap_text = investigation_evidence.cap_text
_dict = investigation_evidence.as_dict
_extract_json_object = investigation_evidence.extract_json_object
_guess_search_args = investigation_evidence.guess_search_args
_is_loopback_ip = investigation_evidence.is_loopback_ip
_json_obj = investigation_evidence.json_obj
_looks_like_ip = investigation_evidence.looks_like_ip
_model_tool_result = investigation_evidence.model_tool_result
_normalize_tool_args = investigation_evidence.normalize_tool_args
_rule_has_no_source_ip = investigation_evidence.rule_has_no_source_ip
_search_playbook = investigation_playbooks.search_playbook
_select_alert_playbook = investigation_playbooks.select_alert_playbook
_structured_wazuh_events_for_model = investigation_evidence.structured_wazuh_events_for_model
_text = investigation_evidence.text
_top_counts = investigation_evidence.top_counts
_question_time_range = investigation_playbooks.question_time_range
_call_wazuh_rule_tool = investigation_rules.call_wazuh_rule_tool
_deterministic_suggestions = investigation_suggestions.deterministic_suggestions
_evidence_is_rule_533_only = investigation_suggestions.evidence_is_rule_533_only
_extract_rule_id_from_messages = investigation_rules.extract_rule_id_from_messages
_extract_json_array = investigation_suggestions.extract_json_array
_fallback_suggestions = investigation_suggestions.fallback_suggestions
_guard_owner_answer = investigation_suggestions.guard_owner_answer
_normalize_suggestions = investigation_suggestions.normalize_suggestions
_prefetch_rule_context = investigation_rules.prefetch_rule_context
_rule_details_preview = investigation_rules.rule_details_preview
_rule_533_suggestions = investigation_suggestions.rule_533_suggestions


async def _suggest_next_options(
    client: httpx.AsyncClient,
    clean_messages: list[dict[str, str]],
    answer_zh: str,
    evidence: list[dict[str, Any]],
) -> list[dict[str, str]]:
    return await investigation_suggestions.suggest_next_options(
        client,
        clean_messages,
        answer_zh,
        evidence,
        plain_llm_chat=_plain_llm_chat,
    )


TOOLS: list[dict[str, Any]] = investigation_tools.build_tools(HISTORY_SEARCH_LIMIT)
TOOL_NAMES = investigation_tools.tool_names(TOOLS)


def is_enabled() -> bool:
    return bool(mcp_client.is_enabled())


async def answer_for_alert(
    alert_id: int,
    question: str,
    history: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Answer a Dashboard investigation question for one stored alert.

    The Dashboard sends only alert_id + the user's question. The bridge owns
    the security context, MCP hints, and owner-facing guardrails.
    """
    row = await db.get_alert(alert_id)
    if not row:
        raise ValueError(f"找不到告警 ID：{alert_id}")

    clean_question = str(question or "").strip()
    if not clean_question:
        raise ValueError("請先輸入想調查的問題。")
    if not is_enabled():
        raise RuntimeError("MCP 尚未啟用：請設定 MCP_SERVER_URL 與 MCP_API_KEY。")

    fast_answer = await _try_fast_alert_playbook(row, clean_question)
    if fast_answer:
        return fast_answer

    messages = _sanitize_messages(history or [])[-8:]
    messages.append({
        "role": "user",
        "content": _build_alert_question_context(row, clean_question),
    })
    return await answer(messages)


async def answer(messages: list[dict[str, str]]) -> dict[str, Any]:
    if not is_enabled():
        raise RuntimeError("MCP 尚未啟用：請設定 MCP_SERVER_URL 與 MCP_API_KEY。")

    clean_messages = _sanitize_messages(messages)
    if not clean_messages:
        raise ValueError("請先輸入想調查的問題。")

    evidence: list[dict[str, Any]] = []
    rule_context = await _prefetch_rule_context(clean_messages, evidence)
    now_local = datetime.now().astimezone().isoformat(timespec="seconds")
    conversation: list[dict[str, Any]] = [
        {
            "role": "system",
            "content": (
                "你是 EdgeSec-Pi 的資安調查助理。Wazuh 告警已經先由系統翻成白話，"
                "你只在使用者明確要求查證時，用 Wazuh MCP 工具查告警、端點狀態、程序與網路埠。"
                "每次回答最多做必要的 1 到 2 個查詢，不要為了完整性展開過多工具呼叫。"
                "查歷史趨勢、重複發生或最近 7 天相關事件時，search_security_events 的 limit "
                f"請優先用 {HISTORY_SEARCH_LIMIT}，不要只查少量樣本；回答時要說明這是查詢上限內的結果。"
                "回答要用繁體中文台灣用語，先講結論，再列出"
                "查到的證據與下一步。不要假裝已經執行封鎖、隔離、刪檔或停用帳號；"
                "你現在只能調查與建議。若資料不足，清楚說還缺什麼。"
                "所有重大結論都必須由本次工具查詢結果支撐。若工具結果沒有明確出現"
                "某個 IP、連接埠、程序、檔名、漏洞或時間點，不可以把它寫成已確認事實；"
                "只能寫成需要 IT 進一步查證。"
                "若工具查詢成功但沒有查到資料，只能說「未查到相關 Wazuh 紀錄」，"
                "不要推論成 Wazuh 資料庫不完整、同步異常或資料遺失；只有工具明確回報錯誤時，"
                "才建議檢查 Wazuh 服務或資料完整性。"
                "MCP 查不到其他歷史事件時，只代表沒有查到額外關聯，不代表目前這筆告警本身正常；"
                "若目前告警已標示高風險或危急，回答仍應要求 IT 確認，不可直接說沒有異常。"
                "Rule 533 / netstat listening ports changed 代表端點監聽埠清單有變動；"
                "重複發生可判斷為需要 IT 確認，但不得直接寫成已確認攻擊。"
                "除非工具結果明確出現外部攻擊來源、惡意程序、未授權帳號、漏洞利用或已確認入侵，"
                "不要建議封鎖、隔離、停用帳號或修改防火牆；先建議比對該端點近期變更、"
                "開發/服務啟動、程序與端口用途。"
                "127.0.0.1、::1、localhost 屬於本機迴圈位址，不代表外部攻擊來源；"
                "遇到這類來源時，應優先改查該端點、規則與本機程序/連接埠變化。"
                "Agent IP、電腦 IP、端點 IP 是被監控主機的位址，不是來源 IP；"
                "不要把 Agent IP 當作 srcip 查詢。"
                "回答給非技術使用者看，不要輸出 Markdown 標記、反引號、英文工具名稱、"
                "JSON、查詢語法或參數名稱。請把工具行為翻成白話，例如「我查了最近 24 小時"
                "的高風險告警」或「我確認了目前在線的設備」。"
                f"目前系統時間是 {now_local}；當使用者說今天、最近 24 小時、最近 7 天時，"
                "必須依這個時間換算，不要使用過去訓練資料中的年份。"
            ),
        },
        *([{"role": "system", "content": rule_context}] if rule_context else []),
        *clean_messages[-10:],
    ]

    timeout = httpx.Timeout(CHAT_TIMEOUT_S, connect=5)
    async with httpx.AsyncClient(timeout=timeout) as client:
        async def on_no_tool_calls(
            assistant: dict[str, Any],
            _round_index: int,
            _messages: list[dict[str, Any]],
        ) -> tool_loop.ToolLoopAction:
            answer = _clean_answer(
                assistant.get("content") or "沒有產生回覆，請換個方式再問一次。"
            )
            answer = _guard_owner_answer(answer, evidence)
            if not evidence:
                answer = _mark_unverified_answer(answer)
            suggestions = await _suggest_next_options(client, clean_messages, answer, evidence)
            return tool_loop.ToolLoopAction.finish({
                "answer_zh": answer,
                "evidence": evidence,
                "suggestions": suggestions,
            })

        async def on_round_limit(
            _assistant: dict[str, Any],
            _round_index: int,
            _messages: list[dict[str, Any]],
        ) -> tool_loop.ToolLoopAction:
            return tool_loop.ToolLoopAction.append({
                "role": "user",
                "content": "工具查詢次數已達上限。請根據目前證據用繁體中文給出結論。",
            })

        async def on_tool_call(invocation: tool_loop.ToolInvocation) -> tool_loop.ToolLoopAction:
            name = invocation.name
            args = _normalize_tool_args(name, invocation.args)
            if not _is_allowed_tool(name):
                result = f"(tool {name} is not allowed in owner investigation chat)"
            elif name == "get_wazuh_rule_details":
                result = await _call_wazuh_rule_tool(args)
            else:
                result = await mcp_client.call_tool(name, args) or "(no data returned)"

            ui_result = _cap_text(result, TOOL_UI_RESULT_MAX_CHARS)
            model_result = _model_tool_result(name, args, result)

            evidence.append({
                "tool": name,
                "args": args,
                "result_preview": model_result[:240].replace("\n", " "),
                "result_log": ui_result,
            })
            return tool_loop.ToolLoopAction.append({
                "role": "tool",
                "tool_call_id": invocation.tool_call_id,
                "content": model_result,
            })

        try:
            return await tool_loop.run_tool_loop(
                client=client,
                messages=conversation,
                tools=TOOLS,
                max_model_turns=MAX_TOOL_ROUNDS + 1,
                max_tool_rounds=MAX_TOOL_ROUNDS,
                on_tool_call=on_tool_call,
                on_no_tool_calls=on_no_tool_calls,
                on_round_limit=on_round_limit,
                total_timeout_s=CHAT_TIMEOUT_S,
                temperature=0.1,
                timeout_error_factory=lambda _elapsed: TimeoutError(
                    "調查逾時，請縮小問題範圍後再試。"
                ),
                exhausted_error_factory=lambda _elapsed: RuntimeError(
                    "調查流程沒有完成，請稍後再試。"
                ),
                logger=log,
                log_label="investigation-chat",
            )
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code != 400:
                raise
            log.warning(
                "investigation tool-calling rejected by model API; falling back to direct MCP query"
            )
            return await _fallback_direct_mcp_answer(client, clean_messages, evidence, rule_context)


async def _try_fast_alert_playbook(row: dict[str, Any], question: str) -> dict[str, Any] | None:
    return await investigation_playbooks.try_fast_alert_playbook(
        row,
        question,
        plain_llm_chat=_plain_llm_chat,
        guard_owner_answer=_guard_owner_answer,
        deterministic_suggestions=_deterministic_suggestions,
    )


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


async def _fallback_direct_mcp_answer(
    client: httpx.AsyncClient,
    clean_messages: list[dict[str, str]],
    evidence: list[dict[str, Any]],
    rule_context: str = "",
) -> dict[str, Any]:
    """Fallback for local models that reject OpenAI `tools`.

    We still perform bounded read-only MCP queries, then ask the model to
    summarize those concrete results without tool-calling parameters.
    """
    question = clean_messages[-1]["content"]
    if not rule_context:
        rule_context = await _prefetch_rule_context(clean_messages, evidence)
    args = _guess_search_args(question)
    result = await mcp_client.call_tool("search_security_events", args) or "(no data returned)"
    ui_result = _cap_text(result, TOOL_UI_RESULT_MAX_CHARS)
    model_result = _cap_text(
        _model_tool_result("search_security_events", args, result),
        FAST_PLAYBOOK_TOOL_RESULT_MAX_CHARS,
    )
    evidence.append({
        "tool": "search_security_events",
        "args": args,
        "result_preview": model_result[:240].replace("\n", " "),
        "result_log": ui_result,
    })

    prompt = (
        "你是 EdgeSec-Pi 的資安調查助理。以下是使用者問題與一次 Wazuh MCP 查詢結果。"
        "請用繁體中文台灣用語回答，先講結論，再列證據與下一步。"
        f"\n{prompt_safety.UNTRUSTED_DATA_INSTRUCTIONS}\n"
        "只能根據查詢結果說已確認的事；資料不足就明確說需要 IT 進一步查證。"
        "如果查詢成功但沒有找到資料，只能說未查到相關 Wazuh 紀錄；不要說需要確認"
        "Wazuh 資料完整性或同步狀態，除非查詢結果明確包含錯誤。"
        "Rule 533 / netstat listening ports changed 代表端點監聽埠清單有變動；"
        "如果查到同一端點短時間內重複發生，結論應是需要 IT 確認端口變動是否為正常服務或開發測試，"
        "不要直接寫成已確認攻擊。除非查詢結果明確出現外部攻擊來源、惡意程序、未授權帳號、"
        "漏洞利用或已確認入侵，不要建議封鎖、隔離、停用帳號或修改防火牆。"
        "127.0.0.1、::1、localhost 是本機迴圈位址，不代表外部攻擊來源。"
        "不要輸出 JSON、Markdown 表格、工具名稱或參數名稱。\n\n"
        f"使用者問題：{question}\n\n"
        f"{rule_context + chr(10) + chr(10) if rule_context else ''}"
        "Wazuh 查詢結果：\n"
        f"{model_result}"
    )
    answer = await _plain_llm_chat(
        client,
        [
            {"role": "system", "content": "請只用繁體中文回答資安查證結論。"},
            {"role": "user", "content": prompt},
        ],
    )
    clean_answer = _guard_owner_answer(_clean_answer(answer), evidence)
    suggestions = await _suggest_next_options(client, clean_messages, clean_answer, evidence)
    return {
        "answer_zh": clean_answer,
        "evidence": evidence,
        "suggestions": suggestions,
    }


def _sanitize_messages(messages: list[dict[str, str]]) -> list[dict[str, str]]:
    clean: list[dict[str, str]] = []
    for message in messages:
        role = str(message.get("role") or "").strip()
        content = str(message.get("content") or "").strip()
        if role not in {"user", "assistant"} or not content:
            continue
        clean.append({"role": role, "content": content[:4000]})
    return clean


def _is_allowed_tool(name: str) -> bool:
    return name in TOOL_NAMES


def _clean_answer(content: str) -> str:
    text = str(content or "").strip()
    # Some local models leak harmony-style channel tags in the visible content.
    # Keep the useful answer text and remove the transport markers.
    for marker in ("<|channel>final\n<channel|>", "<|channel>final", "<channel|>"):
        text = text.replace(marker, "")
    if "<|channel>thought" in text:
        text = text.split("<|channel>thought", 1)[-1]
    text = re.sub(r"(?m)^\s{0,3}#{1,6}\s*", "", text)
    text = re.sub(r"(?m)^\s*-{3,}\s*$", "", text)
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
