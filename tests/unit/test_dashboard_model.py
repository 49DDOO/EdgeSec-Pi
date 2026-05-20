from __future__ import annotations

import pytest

import dashboard_model


@pytest.mark.unit
def test_endpoint_score_rewards_complete_online_endpoint() -> None:
    agent = {
        "status": "active",
        "lastKeepAlive": "2026-05-20T12:00:00Z",
        "version": "Wazuh v4.14.5",
    }
    asset = {"role": "收銀主機"}

    score, label, css_class, reason = dashboard_model.endpoint_item_score(agent, asset)

    assert score == 100
    assert label == "良好"
    assert css_class == "score-ok"
    assert reason == "完整"


@pytest.mark.unit
def test_endpoint_score_penalizes_highest_daily_risk_once_per_endpoint() -> None:
    agent = {
        "status": "active",
        "lastKeepAlive": "2026-05-20T12:00:00Z",
        "version": "Wazuh v4.14.5",
    }
    asset = {"role": "設計師"}
    risk = {"severity": "high", "count": 4}

    score, label, css_class, reason = dashboard_model.endpoint_item_score(agent, asset, risk)
    breakdown = dashboard_model.endpoint_score_breakdown(agent, asset, risk)

    assert score == 70
    assert label == "需處理"
    assert css_class == "score-warn"
    assert reason == "今日高風險（4 件）"
    assert ("今日最高風險：高，4 件", "-30") in breakdown


@pytest.mark.unit
def test_endpoint_risk_map_groups_events_by_endpoint_highest_risk() -> None:
    risks = dashboard_model.endpoint_risk_map(
        [
            {"agent_name": "PC001", "llm_severity": "medium"},
            {"agent_name": "PC001", "llm_severity": "high"},
            {"agent_name": "PC001", "llm_severity": "low"},
            {"agent_name": "PC002", "llm_severity": "critical"},
        ]
    )

    assert risks["PC001"] == {"severity": "high", "count": 3}
    assert risks["PC002"] == {"severity": "critical", "count": 1}


@pytest.mark.unit
def test_overall_score_uses_endpoint_average_and_system_penalty() -> None:
    score, label, css_class = dashboard_model.overall_score([100, 70], queue_size=1, errors=0)

    assert score == 73
    assert label == "需處理"
    assert css_class == "score-warn"


@pytest.mark.unit
def test_decision_has_clear_default_when_no_action_needed() -> None:
    title, css_class, description, action = dashboard_model.decision_from_stats(
        {"open_by_severity_24h": {}, "errors_last_24h": 0},
        {"agents": {"disconnected": 0}},
    )

    assert title == "目前不用介入"
    assert css_class == "ok"
    assert description == "目前沒有需要立即處理的資安事件。"
    assert action == "維持監控即可。若收到高風險通知，再回到今日待辦更新處理結果。"
