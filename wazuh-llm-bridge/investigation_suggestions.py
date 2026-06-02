"""Owner-facing suggestion and answer guard policy for investigations."""
from __future__ import annotations

import json
import logging
import re
from collections.abc import Awaitable, Callable
from typing import Any

import httpx

import prompt_safety


log = logging.getLogger("investigation-suggestions")

PlainChat = Callable[[httpx.AsyncClient, list[dict[str, Any]]], Awaitable[str]]


async def suggest_next_options(
    client: httpx.AsyncClient,
    clean_messages: list[dict[str, str]],
    answer_zh: str,
    evidence: list[dict[str, Any]],
    *,
    plain_llm_chat: PlainChat,
) -> list[dict[str, str]]:
    """Ask the active model for owner-facing next action buttons."""
    if evidence_is_rule_533_only(evidence):
        return rule_533_suggestions()

    question = clean_messages[-1]["content"] if clean_messages else ""
    evidence_text = json.dumps(evidence[-4:], ensure_ascii=False)[:3000]
    prompt = (
        "你是資安產品的決策助理。根據 MCP 查證結果，產生 2 到 4 個下一步選項，"
        f"\n{prompt_safety.UNTRUSTED_DATA_INSTRUCTIONS}\n"
        "讓非技術主管可以點選。只回 JSON array，不要 Markdown。每個物件格式："
        "{\"label_zh\":\"短按鈕文字\", \"description_zh\":\"一句白話原因\", "
        "\"action\":\"handoff_it|mark_resolved|mark_false_positive|mark_normal|ask_followup\", "
        "\"followup_question\":\"若 action=ask_followup，填下一個要查證的問題，否則空字串\"}。"
        "若證據顯示仍有風險，優先建議 handoff_it 或 ask_followup；"
        "只有證據明確偏正常才給 mark_normal；只有明確是測試/誤判才給 mark_false_positive。\n\n"
        "除非證據明確指出外部攻擊來源、惡意程序、未授權帳號、漏洞利用或已確認入侵，"
        "不要產生封鎖、隔離、停用帳號、修改防火牆這類動作選項；"
        "Rule 533 重複發生時，應建議 IT 確認端口變動原因、比對近期維護/開發活動，"
        "或再查該端點程序與開放埠。\n\n"
        f"使用者問題：{question}\n\n"
        f"查證回答：{answer_zh[:2500]}\n\n"
        "MCP 證據：\n"
        f"{prompt_safety.untrusted_data_block('MCP evidence JSON for suggestion generation', evidence_text)}"
    )
    try:
        raw = await plain_llm_chat(
            client,
            [
                {"role": "system", "content": "你只輸出 JSON array。"},
                {"role": "user", "content": prompt},
            ],
        )
        parsed = extract_json_array(raw)
        suggestions = normalize_suggestions(parsed)
        if suggestions:
            return suggestions
    except Exception as exc:
        log.warning("investigation suggestion generation failed: %s", exc)
    return fallback_suggestions(answer_zh, evidence)


def deterministic_suggestions(answer_zh: str, evidence: list[dict[str, Any]]) -> list[dict[str, str]]:
    if evidence_is_rule_533_only(evidence):
        return rule_533_suggestions()
    return fallback_suggestions(answer_zh, evidence)


def rule_533_suggestions() -> list[dict[str, str]]:
    return [
        {
            "label_zh": "請 IT 確認端口變動",
            "description_zh": "Rule 533 重複出現，先確認是否為正常服務、開發測試或系統更新。",
            "action": "handoff_it",
            "followup_question": "",
        },
        {
            "label_zh": "查目前開放埠",
            "description_zh": "比對目前端點開放埠與 Wazuh 歷史紀錄，找出新增或消失的服務。",
            "action": "ask_followup",
            "followup_question": "請查這台電腦目前有哪些開放埠，並比對 Rule 533 的歷史變化。",
        },
        {
            "label_zh": "查近期程序",
            "description_zh": "確認端口變動是否由已知程序或開發工具造成。",
            "action": "ask_followup",
            "followup_question": "請查這台電腦近期程序與端口變動是否有關聯。",
        },
    ]


def extract_json_array(text: str) -> Any:
    raw = str(text or "").strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```(?:json)?\s*", "", raw)
        raw = re.sub(r"\s*```$", "", raw)
    try:
        return json.loads(raw)
    except Exception:
        match = re.search(r"\[[\s\S]*\]", raw)
        if not match:
            return None
        try:
            return json.loads(match.group(0))
        except Exception:
            return None


def normalize_suggestions(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list):
        return []
    allowed = {"handoff_it", "mark_resolved", "mark_false_positive", "mark_normal", "ask_followup"}
    out: list[dict[str, str]] = []
    for item in value[:4]:
        if not isinstance(item, dict):
            continue
        label = str(item.get("label_zh") or "").strip()
        description = str(item.get("description_zh") or "").strip()
        action = str(item.get("action") or "").strip()
        followup = str(item.get("followup_question") or "").strip()
        if not label or action not in allowed:
            continue
        out.append({
            "label_zh": label[:28],
            "description_zh": description[:120],
            "action": action,
            "followup_question": followup[:200],
        })
    return out


def fallback_suggestions(answer_zh: str, evidence: list[dict[str, Any]]) -> list[dict[str, str]]:
    text = answer_zh.lower()
    first_line = str(answer_zh or "").strip().splitlines()[0] if str(answer_zh or "").strip() else ""
    low_risk_conclusion = bool(re.search(
        r"(不需要|暫不需要|無需).{0,16}(立刻|馬上|立即)?.{0,16}(it|處理|升級)",
        first_line,
        re.I,
    ))
    risky = any(word in text for word in ("立即", "異常", "風險", "攻擊", "可疑", "需要"))
    if risky and not low_risk_conclusion:
        return [
            {
                "label_zh": "交給 IT 處理",
                "description_zh": "查證結果仍有風險或需要技術人員確認。",
                "action": "handoff_it",
                "followup_question": "",
            },
            {
                "label_zh": "再查最近 7 天",
                "description_zh": "確認這是否只是單次事件，或已經重複發生。",
                "action": "ask_followup",
                "followup_question": "請查最近 7 天是否有相同來源、相同電腦或相同規則重複發生。",
            },
        ]
    return [
        {
            "label_zh": "標記正常",
            "description_zh": "目前沒有查到明確異常證據。",
            "action": "mark_normal",
            "followup_question": "",
        },
        {
            "label_zh": "再查更多紀錄",
            "description_zh": "若仍不放心，可擴大時間範圍再確認一次。",
            "action": "ask_followup",
            "followup_question": "請擴大查詢最近 7 天，確認是否還有相關異常。",
        },
    ]


def guard_owner_answer(answer_zh: str, evidence: list[dict[str, Any]]) -> str:
    """Keep owner-facing MCP answers from recommending unproven response actions."""
    text = str(answer_zh or "").strip()
    if not text:
        return text
    if not evidence_is_rule_533_only(evidence):
        return text

    blocked_action = re.search(r"(封鎖|隔離|停用帳號|修改防火牆|封鎖可疑端口|封鎖端口)", text)
    if not blocked_action:
        return text

    replacement = (
        "不要先封鎖或隔離。請 IT 先確認這些端口變動是否來自正常服務、開發測試、"
        "系統更新或近期安裝的程式；只有確認為未授權行為後，才評估封鎖、隔離或調整防火牆。"
    )
    lines: list[str] = []
    inserted = False
    for line in text.splitlines():
        if re.search(r"(封鎖|隔離|停用帳號|修改防火牆|封鎖可疑端口|封鎖端口)", line):
            if not inserted:
                lines.append(replacement)
                inserted = True
            continue
        lines.append(line)
    return "\n".join(lines).strip()


def evidence_is_rule_533_only(evidence: list[dict[str, Any]]) -> bool:
    saw_rule_533 = False
    for item in evidence:
        args = item.get("args") if isinstance(item, dict) else {}
        result_text = " ".join([
            str(item.get("result_preview") or ""),
            str(item.get("result_log") or "")[:2000],
        ]) if isinstance(item, dict) else ""
        rule_id = str((args or {}).get("rule_id") or "").strip()
        if rule_id == "533" or "Rule ID: 533" in result_text or '"id": "533"' in result_text:
            saw_rule_533 = True
        strong_terms = (
            "External SSH brute force",
            "authentication failed",
            "malware",
            "rootkit",
            "vulnerability",
            "CVE-",
            "攻擊來源",
            "惡意",
            "未授權帳號",
            "漏洞利用",
            "已確認入侵",
        )
        if any(term in result_text for term in strong_terms):
            return False
    return saw_rule_533
