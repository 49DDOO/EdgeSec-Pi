from __future__ import annotations

import json

import pytest

from support import fresh_bridge_import


@pytest.mark.unit
def test_management_title_uses_endpoint_name_not_business_role() -> None:
    dashboard_ui = fresh_bridge_import(["dashboard_ui"])["dashboard_ui"]

    title = dashboard_ui._management_item_title(
        {
            "rule_id": "5712",
            "agent_name": "wazuh-agent-01",
            "raw_alert": json.dumps({"data": {"dstuser": "admin"}}),
        },
        "wazuh-agent-01",
    )

    assert title == "wazuh-agent-01 出現多次登入嘗試，請確認帳號「admin」是否為正常操作。"
    assert "設計師 出現" not in title


@pytest.mark.unit
def test_management_steps_tell_owner_what_to_do() -> None:
    dashboard_ui = fresh_bridge_import(["dashboard_ui"])["dashboard_ui"]

    steps = dashboard_ui._management_steps(
        {
            "rule_id": "5712",
            "raw_alert": json.dumps({"data": {"dstuser": "admin"}}),
        },
        "",
        "198.51.100.42",
    )

    assert steps == [
        "確認：請實際使用這台電腦的人確認帳號「admin」是否有人成功登入。",
        "處理：若不是公司操作，封鎖來源 IP 198.51.100.42。",
        "結案：在右側按「正常操作」、「已處理」或「誤報」。",
    ]


@pytest.mark.unit
def test_today_tasks_collapse_repeated_alerts_by_endpoint_rule_and_ioc() -> None:
    dashboard_ui = fresh_bridge_import(["dashboard_ui"])["dashboard_ui"]

    rows = [
        {
            "id": 1,
            "received_at": 1_779_200_100,
            "agent_name": "PC001",
            "rule_id": "5712",
            "llm_severity": "high",
            "case_status": "open",
            "raw_alert": json.dumps({"data": {"srcip": "198.51.100.42", "dstuser": "admin"}}),
        },
        {
            "id": 2,
            "received_at": 1_779_200_200,
            "agent_name": "PC001",
            "rule_id": "5712",
            "llm_severity": "high",
            "case_status": "open",
            "raw_alert": json.dumps({"data": {"srcip": "198.51.100.42", "dstuser": "admin"}}),
        },
    ]

    grouped = dashboard_ui._collapse_event_groups(rows)

    assert len(grouped) == 1
    assert grouped[0]["_group_count"] == 2
    assert grouped[0]["_group_ids"] == [2, 1]


@pytest.mark.unit
def test_today_task_buttons_submit_the_whole_group() -> None:
    dashboard_ui = fresh_bridge_import(["dashboard_ui"])["dashboard_ui"]

    html = dashboard_ui._case_action_button(2, "resolved", "已處理", [2, 1])

    assert 'name="group_ids" value="2,1"' in html
