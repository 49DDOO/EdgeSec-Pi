"""Plain-language explanations for Wazuh SCA failed checks.

The source of truth is Wazuh. This module does not invent compliance checks;
it converts Wazuh's title/rationale/remediation into short Traditional Chinese
copy for the management dashboard, caches the result, and falls back to the raw
Wazuh item when the local LLM is unavailable.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

import httpx

import llm_client
import prompt_safety

LM_STUDIO_URL = os.getenv("LM_STUDIO_URL", "http://localhost:1234/v1/chat/completions")
LM_MODEL = os.getenv("LM_MODEL", "local-model")
TIMEOUT_S = float(os.getenv("SCA_EXPLAIN_TIMEOUT_S", "12"))
LIVE_EXPLAIN = os.getenv("SCA_EXPLAIN_LIVE", "false").strip().lower() == "true"
CACHE_PATH = Path(__file__).resolve().parent / "data" / "sca_explanations.json"

_cache_lock: asyncio.Lock | None = None

TITLE_FALLBACKS = (
    (("Install Application Updates", "App Store"), "啟用 App Store 自動更新"),
    (("Firewall Stealth Mode",), "啟用防火牆隱身模式"),
    (("FileVault", "Enabled"), "啟用磁碟加密"),
    (("Mail Summarization",), "關閉郵件摘要功能"),
    (("Notes Summarization",), "關閉備忘錄摘要功能"),
    (("Help Apple Improve Search",), "關閉搜尋資料分享"),
    (("Power Nap",), "關閉睡眠背景連線"),
    (("/tmp", "separate partition"), "隔離暫存目錄"),
    (("nodev option", "/tmp"), "限制暫存目錄裝置檔"),
    (("noexec option", "/tmp"), "禁止暫存目錄執行程式"),
    (("nosuid option", "/tmp"), "禁止暫存目錄提權檔案"),
    (("gpgcheck",), "啟用軟體簽章驗證"),
    (("AIDE", "installed"), "安裝檔案完整性檢查"),
    (("bootloader config",), "限制開機設定權限"),
    (("login warning banner",), "設定登入警告訊息"),
)


def _lock() -> asyncio.Lock:
    global _cache_lock
    if _cache_lock is None:
        _cache_lock = asyncio.Lock()
    return _cache_lock


def _cache_key(check: dict[str, Any]) -> str:
    raw = "|".join([
        str(check.get("id") or ""),
        str(check.get("title") or ""),
        str(check.get("rationale") or ""),
        str(check.get("remediation") or ""),
    ])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _load_cache() -> dict[str, Any]:
    try:
        return json.loads(CACHE_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_cache(cache: dict[str, Any]) -> None:
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    CACHE_PATH.write_text(
        json.dumps(cache, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def _extract_json(text: str) -> dict[str, Any]:
    text = text.strip()
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    if fenced:
        text = fenced.group(1)
    else:
        match = re.search(r"\{.*\}", text, re.S)
        if match:
            text = match.group(0)
    data = json.loads(text)
    return data if isinstance(data, dict) else {}


def _fallback(check: dict[str, Any]) -> dict[str, str]:
    title = str(check.get("title") or "Wazuh 安全設定檢查未通過").strip()
    remediation = str(check.get("remediation") or "").strip()
    rationale = str(check.get("rationale") or "").strip()
    description = str(check.get("description") or "").strip()
    title_zh = next(
        (zh for needles, zh in TITLE_FALLBACKS if all(needle.lower() in title.lower() for needle in needles)),
        "安全設定需要補強",
    )
    return {
        "title_zh": title_zh,
        "action_zh": (
            "請 IT 依下方 Wazuh 補強步驟處理；若是公司允許的例外，請留下紀錄。"
            if remediation
            else "請 IT 查看 Wazuh 原始檢查項目；若是公司允許的例外，請留下紀錄。"
        ),
        "source_title": title,
        "source_rationale": rationale,
        "source_description": description,
        "source_remediation": remediation,
        "source": "wazuh_raw_fallback",
    }


async def _llm_explain(check: dict[str, Any], client: httpx.AsyncClient) -> dict[str, str]:
    title = str(check.get("title") or "").strip()
    rationale = str(check.get("rationale") or "").strip()
    remediation = str(check.get("remediation") or "").strip()
    prompt = f"""
你是給中小企業管理者看的資安系統文案編輯。請把 Wazuh SCA 檢查項目改寫成繁體中文短句。

限制：
- 不要提 Wazuh、CIS、benchmark、rule、policy。
- 不要恐嚇，不要說已經被入侵。
- title_zh 最多 18 個中文字。
- action_zh 最多 42 個中文字。
- action_zh 要是「請 IT ...」開頭，讓管理者可以直接轉給 IT 或外包廠商。
- 只根據下方原始資料，不要編造。
- {prompt_safety.UNTRUSTED_DATA_INSTRUCTIONS}
- 只輸出 JSON，不要 markdown。

原始檢查名稱：
{prompt_safety.untrusted_data_block("SCA title", title, limit=500)}

原始原因：
{prompt_safety.untrusted_data_block("SCA rationale", rationale, limit=700)}

原始修正方式：
{prompt_safety.untrusted_data_block("SCA remediation", remediation, limit=900)}

JSON schema:
{{"title_zh":"...", "action_zh":"..."}}
""".strip()
    response = await llm_client.chat_completion(
        client,
        {
            "messages": [
                {"role": "system", "content": "你只輸出有效 JSON。"},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.1,
        },
        timeout=TIMEOUT_S,
    )
    content = response["choices"][0]["message"]["content"]
    parsed = _extract_json(content)
    title_zh = str(parsed.get("title_zh") or "").strip()
    action_zh = str(parsed.get("action_zh") or "").strip()
    if not title_zh or not action_zh:
        raise ValueError("LLM explanation missing title_zh/action_zh")
    return {
        "title_zh": title_zh[:40],
        "action_zh": action_zh[:120],
        "source_title": title,
        "source_rationale": rationale,
        "source_description": str(check.get("description") or "").strip(),
        "source_remediation": remediation,
        "source": "llm_from_wazuh_sca",
    }


async def explain_failed_checks(checks: list[dict[str, Any]], limit: int = 3) -> list[dict[str, str]]:
    """Return short management-facing explanations for failed checks."""
    selected = checks[: max(0, min(int(limit), 5))]
    if not selected:
        return []

    async with _lock():
        cache = _load_cache()
        changed = False
        results: list[dict[str, str]] = []
        async with httpx.AsyncClient() as client:
            for check in selected:
                key = _cache_key(check)
                cached = cache.get(key)
                if isinstance(cached, dict):
                    results.append(cached)
                    continue
                if not LIVE_EXPLAIN:
                    results.append(_fallback(check))
                    continue
                try:
                    item = await _llm_explain(check, client)
                except Exception:
                    item = _fallback(check)
                cache[key] = item
                changed = True
                results.append(item)
        if changed:
            _save_cache(cache)
        return results
