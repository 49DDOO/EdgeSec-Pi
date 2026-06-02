import sys
from pathlib import Path
import asyncio

import pytest

BRIDGE_DIR = Path(__file__).resolve().parents[2] / "wazuh-llm-bridge"
sys.path.insert(0, str(BRIDGE_DIR))


@pytest.mark.unit
def test_extract_rule_xml_returns_current_rule_block(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WAZUH_API_PASS", "test")
    import wazuh  # noqa: WPS433

    xml = """
    <group name="ossec,">
      <rule id="532" level="3">
        <description>Previous rule</description>
      </rule>
      <rule id="533" level="7">
        <if_sid>530</if_sid>
        <description>Listened ports status changed.</description>
        <group>pci_dss_10.6.1,gpg13_4.13,</group>
      </rule>
    </group>
    """

    block = wazuh.extract_rule_xml(xml, "533")

    assert '<rule id="533" level="7">' in block
    assert "Listened ports status changed." in block
    assert '<rule id="532"' not in block


@pytest.mark.unit
def test_investigation_extracts_rule_id_from_alert_context(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WAZUH_API_PASS", "test")
    import investigation_chat  # noqa: WPS433

    rule_id = investigation_chat._extract_rule_id_from_messages([
        {
            "role": "user",
            "content": "請針對這筆 Wazuh 事件調查：\nRule ID：19007\n電腦名稱：macbook",
        }
    ])

    assert rule_id == "19007"


@pytest.mark.unit
def test_investigation_search_args_ignore_loopback_source(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WAZUH_API_PASS", "test")
    import investigation_chat  # noqa: WPS433

    args = investigation_chat._guess_search_args(
        "問題：查 titandeacStudio 最近 24 小時異常。\n"
        "來源 IP：127.0.0.1（本機迴圈位址，不代表外部來源）\n"
        "Rule ID：533"
    )

    assert "srcip" not in args
    assert args["query"] == "*"
    assert args["rule_id"] == "533"
    assert args["limit"] >= 500


@pytest.mark.unit
def test_investigation_normalizes_llm_loopback_tool_args(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WAZUH_API_PASS", "test")
    import investigation_chat  # noqa: WPS433

    args = investigation_chat._normalize_tool_args(
        "search_security_events",
        {
            "query": "127.0.0.1",
            "time_range": "7d",
            "limit": 20,
            "compact": True,
            "srcip": "127.0.0.1",
            "rule_id": "533",
            "agent_id": "002",
        },
    )

    assert args["query"] == "*"
    assert "srcip" not in args
    assert args["rule_id"] == "533"
    assert args["agent_id"] == "002"
    assert args["limit"] >= 500


@pytest.mark.unit
def test_rule_533_does_not_query_agent_ip_as_source(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WAZUH_API_PASS", "test")
    import investigation_chat  # noqa: WPS433

    guessed = investigation_chat._guess_search_args(
        "問題：查 MB-TitanCheng 最近 24 小時異常。\n"
        "Agent ID：003\n"
        "Agent IP：192.168.50.106（端點 IP，不可當作來源 IP / srcip 查詢）\n"
        "Rule ID：533"
    )
    normalized = investigation_chat._normalize_tool_args(
        "search_security_events",
        {
            "query": "192.168.50.106",
            "time_range": "24h",
            "limit": 20,
            "srcip": "192.168.50.106",
            "rule_id": "533",
            "agent_id": "003",
        },
    )

    assert "srcip" not in guessed
    assert guessed["query"] == "*"
    assert "srcip" not in normalized
    assert normalized["query"] == "*"
    assert normalized["agent_id"] == "003"
    assert normalized["rule_id"] == "533"
    assert normalized["limit"] >= 500


@pytest.mark.unit
def test_syscollector_netstat_does_not_extract_loopback_as_source_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WAZUH_API_PASS", "test")
    import technical_evidence  # noqa: WPS433

    evidence = technical_evidence.build_technical_evidence(
        row={
            "rule_id": "533",
            "rule_level": 7,
            "siem_source": "wazuh",
            "agent_name": "macbook",
            "agent_ip": "192.168.50.106",
            "full_log": "ossec: output: 'netstat listening ports':\ntcp4 127.0.0.1.3000 *.*",
        },
        raw_alert={
            "rule": {
                "id": "533",
                "level": 7,
                "description": "Listened ports status (netstat) changed (new port opened or closed).",
                "groups": ["ossec"],
            },
            "agent": {"id": "002", "name": "macbook", "ip": "192.168.50.106"},
            "full_log": "ossec: output: 'netstat listening ports':\ntcp4 127.0.0.1.3000 *.*",
        },
        llm={},
    )

    assert evidence["module"] == "syscollector"
    assert evidence["indicators"]["source_ip"] == ""


@pytest.mark.unit
def test_model_tool_result_summarizes_wazuh_history_without_prefix_truncation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WAZUH_API_PASS", "test")
    import investigation_chat  # noqa: WPS433

    result = investigation_chat._model_tool_result(
        "search_security_events",
        {"query": "*", "time_range": "7d", "limit": 500, "rule_id": "533"},
        "Security Events: " + __import__("json").dumps({
            "data": {
                "affected_items": [
                    {
                        "timestamp": "2026-05-26T15:09:43+0000",
                        "agent": {"name": "titandeacStudio"},
                        "rule": {"id": "533", "level": 7, "description": "Listened ports status changed."},
                        "full_log": "newest important event",
                    },
                    {
                        "timestamp": "2026-05-26T14:51:43+0000",
                        "agent": {"name": "MB-TitanCheng"},
                        "rule": {"id": "533", "level": 7, "description": "Listened ports status changed."},
                        "full_log": "older event",
                    },
                ],
                "total_affected_items": 3366,
                "total_failed_items": 0,
            }
        }),
    )

    assert "Total matched by Wazuh: 3366" in result
    assert "Counts by agent" in result
    assert "titandeacStudio" in result
    assert "newest important event" in result
    assert "greater than query limit" in result


@pytest.mark.unit
def test_rule_533_owner_answer_does_not_recommend_unproven_blocking(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WAZUH_API_PASS", "test")
    import investigation_chat  # noqa: WPS433

    guarded = investigation_chat._guard_owner_answer(
        "結論：需要 IT 確認。\n"
        "下一步：如果無法確認這些端口變化是正常的，建議暫時封鎖可疑端口。",
        [
            {
                "tool": "search_security_events",
                "args": {"query": "*", "time_range": "7d", "limit": 500, "rule_id": "533", "agent_id": "003"},
                "result_preview": "Total matched by Wazuh: 281 Counts by rule: {\"533 Listened ports status changed.\": 281}",
                "result_log": "Security Events: {\"data\":{\"affected_items\":[],\"total_affected_items\":281}}",
            }
        ],
    )

    assert "封鎖可疑端口" not in guarded
    assert "先確認這些端口變動" in guarded
    assert "只有確認為未授權行為後" in guarded


@pytest.mark.unit
def test_rule_533_suggestions_are_deterministic_without_extra_llm(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WAZUH_API_PASS", "test")
    import investigation_chat  # noqa: WPS433

    class BrokenClient:
        pass

    suggestions = asyncio.run(
        investigation_chat._suggest_next_options(
            BrokenClient(),
            [{"role": "user", "content": "查 Rule 533 最近 7 天是否重複發生。"}],
            "結論：需要 IT 確認。",
            [
                {
                    "tool": "search_security_events",
                    "args": {"query": "*", "time_range": "7d", "limit": 500, "rule_id": "533", "agent_id": "003"},
                    "result_preview": "Total matched by Wazuh: 281 Counts by rule: {\"533 Listened ports status changed.\": 281}",
                    "result_log": "Security Events: {\"data\":{\"affected_items\":[],\"total_affected_items\":281}}",
                }
            ],
        )
    )

    assert suggestions[0]["label_zh"] == "請 IT 確認端口變動"
    assert all("封鎖" not in item["label_zh"] + item["description_zh"] for item in suggestions)
