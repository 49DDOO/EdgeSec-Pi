"""Dashboard decision and scoring helpers.

This module contains display-independent rules used by the owner dashboard:
headline severity, endpoint scoring, and setup/health decisions. Keeping these
rules outside dashboard_ui.py makes UI changes less likely to alter product
semantics by accident.
"""
from __future__ import annotations

from typing import Any


SEVERITY_WEIGHT = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}

SEVERITY_SCORE_PENALTY = {
    "critical": 45,
    "high": 30,
    "medium": 16,
    "low": 5,
    "info": 0,
    "unclassified": 0,
}


def severity_label(severity: str | None) -> str:
    labels = {
        "critical": "危急",
        "high": "高",
        "medium": "中",
        "low": "低",
        "info": "資訊",
    }
    return labels.get((severity or "").lower(), "未分類")


def headline_from_stats(stats: dict[str, Any]) -> tuple[str, str, str]:
    severities = {
        str(k).lower(): int(v)
        for k, v in (
            stats.get("open_by_severity_24h")
            or stats.get("by_severity_24h")
            or {}
        ).items()
    }
    if severities.get("critical", 0) > 0:
        return "危急", "critical", "今天有重大資安事件，需要立刻請 IT 處理。"
    if severities.get("high", 0) > 0:
        return "高風險", "high", "今天有高風險事件，建議立即確認處理進度。"
    if severities.get("medium", 0) > 0:
        return "注意", "medium", "今天有需要追蹤的事件，請確認 IT 是否已知悉。"
    if int(stats.get("errors_last_24h") or 0) > 0:
        return "需檢查", "medium", "偵測服務有部分分析失敗，請 IT 確認依賴服務狀態。"
    return "正常", "ok", "目前沒有需要立即介入的資安事件。"


def endpoint_risk_map(events: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    risks: dict[str, dict[str, Any]] = {}
    for row in events:
        agent_name = str(row.get("agent_name") or "").strip()
        if not agent_name:
            continue
        severity = str(row.get("llm_severity") or "unclassified").lower()
        current = risks.get(agent_name)
        if not current:
            risks[agent_name] = {"severity": severity, "count": 1}
            continue
        current["count"] = int(current.get("count") or 0) + 1
        if SEVERITY_WEIGHT.get(severity, 0) > SEVERITY_WEIGHT.get(str(current.get("severity") or ""), 0):
            current["severity"] = severity
    return risks


def agent_state(status_text: str) -> tuple[str, str]:
    raw = (status_text or "").strip()
    lowered = raw.lower()
    if lowered == "active" or lowered.startswith("active/"):
        return "ok", "在線"
    if "disconnect" in lowered or "never" in lowered:
        return "warn", "離線"
    if raw:
        return "warn", raw
    return "warn", "未知"


def is_manager_agent(agent: dict[str, Any]) -> bool:
    name = str(agent.get("name") or "").lower()
    return name in {"wazuh.manager", "manager"} or name.endswith(".manager")


def score_label(score: int) -> tuple[str, str]:
    score = max(0, min(100, score))
    if score >= 90:
        return "良好", "score-ok"
    if score >= 75:
        return "注意", "score-warn"
    if score >= 60:
        return "需處理", "score-warn"
    return "高風險", "score-high"


def endpoint_item_score(
    agent: dict[str, Any],
    asset: dict[str, Any],
    risk: dict[str, Any] | None = None,
) -> tuple[int, str, str, str]:
    is_active = str(agent.get("status") or "").strip().lower() == "active"
    has_profile = bool(asset)
    has_sync = bool(agent.get("lastKeepAlive") or agent.get("last_keep_alive"))
    has_version = bool(agent.get("version") or agent.get("agent_version"))
    score = 0
    score += 50 if is_active else 0
    score += 30 if has_profile else 0
    score += 10 if has_sync else 0
    score += 10 if has_version else 0
    risk_severity = str((risk or {}).get("severity") or "").lower()
    score -= SEVERITY_SCORE_PENALTY.get(risk_severity, 0)
    score = max(0, min(100, score))
    label, score_class = score_label(score)
    if risk_severity and risk_severity not in {"info", "unclassified"}:
        count = int((risk or {}).get("count") or 0)
        suffix = f"（{count} 件）" if count > 1 else ""
        reason = f"今日{severity_label(risk_severity)}風險{suffix}"
    elif not is_active:
        reason = "離線"
    elif not has_profile:
        reason = "缺背景"
    elif not has_sync:
        reason = "缺同步"
    elif not has_version:
        reason = "缺版本"
    else:
        reason = "完整"
    return score, label, score_class, reason


def endpoint_score_breakdown(
    agent: dict[str, Any],
    asset: dict[str, Any],
    risk: dict[str, Any] | None = None,
) -> list[tuple[str, str]]:
    is_active = str(agent.get("status") or "").strip().lower() == "active"
    has_profile = bool(asset)
    has_sync = bool(agent.get("lastKeepAlive") or agent.get("last_keep_alive"))
    has_version = bool(agent.get("version") or agent.get("agent_version"))
    risk_severity = str((risk or {}).get("severity") or "").lower()
    risk_penalty = SEVERITY_SCORE_PENALTY.get(risk_severity, 0)
    rows = [
        ("端點在線", "+50" if is_active else "+0"),
        ("已設定業務用途", "+30" if has_profile else "+0"),
        ("有同步時間", "+10" if has_sync else "+0"),
        ("Agent 有版本", "+10" if has_version else "+0"),
    ]
    if risk_penalty:
        count = int((risk or {}).get("count") or 0)
        count_label = f"，{count} 件" if count > 1 else ""
        rows.append((f"今日最高風險：{severity_label(risk_severity)}{count_label}", f"-{risk_penalty}"))
    else:
        rows.append(("今日中高風險", "0"))
    return rows


def endpoint_score(item_scores: list[int]) -> tuple[int, str, str, str]:
    if not item_scores:
        return 0, "無資料", "score-high", "端點清單沒有回傳，請先確認 SIEM 連線。"
    score = round(sum(item_scores) / len(item_scores))
    label, score_class = score_label(score)
    if score >= 90:
        note = "端點平均狀態良好。"
    elif score >= 75:
        note = "少數端點需要補資料或確認狀態。"
    elif score >= 60:
        note = "有端點離線或缺少重要背景。"
    else:
        note = "端點監控資料不足，可能影響告警判斷。"
    return score, label, score_class, note


def decision_from_stats(stats: dict[str, Any], status: dict[str, Any]) -> tuple[str, str, str, str]:
    severities = {
        str(k).lower(): int(v)
        for k, v in (
            stats.get("open_by_severity_24h")
            or stats.get("by_severity_24h")
            or {}
        ).items()
    }
    high_or_above = severities.get("critical", 0) + severities.get("high", 0)
    medium = severities.get("medium", 0)
    errors = int(stats.get("errors_last_24h") or 0)
    agents = status.get("agents") or {}
    disconnected = int(agents.get("disconnected") or 0)

    if severities.get("critical", 0) > 0:
        return (
            "需要立刻處理",
            "critical",
            "今天有危急事件，可能影響公司系統或資料安全。",
            "請立即確認負責人已接手，必要時同意暫停受影響服務或封鎖來源。",
        )
    if high_or_above > 0:
        return (
            "今天需要處理",
            "high",
            "今天有高風險事件，不需要查技術細節，但要確認處理進度。",
            "請確認是否為公司操作；若不是，請技術窗口封鎖來源並在通知中回覆結果。",
        )
    if medium > 0:
        return (
            "需要追蹤",
            "medium",
            "今天有需要確認的事件，目前還不到需要立即決策。",
            "請負責人在今天內確認是否為誤報，並更新處理結果。",
        )
    if disconnected > 0:
        return (
            "監控有缺口",
            "medium",
            "有受監控主機離線，可能會漏掉該主機的資安事件。",
            "請技術窗口先恢復離線設備，再確認是否有漏收告警。",
        )
    if errors > 0:
        return (
            "系統需檢查",
            "medium",
            "資安告警有部分分析失敗，可能是 AI、Slack 或相依服務不穩。",
            "請技術窗口執行系統自我檢查，修復黃色或紅色項目。",
        )
    return (
        "目前不用介入",
        "ok",
        "目前沒有需要立即處理的資安事件。",
        "維持監控即可。若收到高風險通知，再回到今日待辦更新處理結果。",
    )


def overall_score(
    endpoint_scores: list[int],
    queue_size: int,
    errors: int,
) -> tuple[int, str, str]:
    if endpoint_scores:
        score = round(sum(endpoint_scores) / len(endpoint_scores))
    else:
        score = 0
    if errors or queue_size:
        score -= 12
    score = max(0, min(100, score))
    label, score_class = score_label(score)
    return score, label, score_class
