from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
BRIDGE = ROOT / "wazuh-llm-bridge"
if str(BRIDGE) not in sys.path:
    sys.path.insert(0, str(BRIDGE))

import investigation_chat  # noqa: E402


def test_alert_investigation_context_is_built_in_bridge(monkeypatch) -> None:
    captured: dict[str, Any] = {}

    async def fake_get_alert(alert_id: int) -> dict[str, Any]:
        assert alert_id == 42
        return {
            "id": 42,
            "received_at": 1780060000.0,
            "rule_id": "5712",
            "rule_level": 10,
            "rule_description": "SSH brute force",
            "agent_name": "web-prod",
            "agent_ip": "10.0.0.8",
            "llm_severity": "medium",
            "full_log": "Failed password for admin from 203.0.113.45 port 55501 ssh2",
            "raw_alert": (
                '{"timestamp":"2026-05-29T10:14:22+08:00",'
                '"agent":{"id":"001","name":"web-prod","ip":"10.0.0.8"},'
                '"rule":{"id":"5712","level":10,"description":"SSH brute force"},'
                '"data":{"srcip":"203.0.113.45","srcuser":"admin"}}'
            ),
        }

    async def fake_answer(messages: list[dict[str, str]]) -> dict[str, Any]:
        captured["messages"] = messages
        return {"answer_zh": "ok", "evidence": [], "suggestions": []}

    async def no_fast_playbook(row: dict[str, Any], question: str) -> None:
        return None

    monkeypatch.setattr(investigation_chat.db, "get_alert", fake_get_alert)
    monkeypatch.setattr(investigation_chat, "answer", fake_answer)
    monkeypatch.setattr(investigation_chat, "_try_fast_alert_playbook", no_fast_playbook)
    monkeypatch.setattr(investigation_chat.mcp_client, "is_enabled", lambda: True)

    result = asyncio.run(
        investigation_chat.answer_for_alert(
            42,
            "來源 IP 最近 7 天是否攻擊其他電腦？",
            history=[{"role": "assistant", "content": "前一次回覆"}],
        )
    )

    assert result["answer_zh"] == "ok"
    messages = captured["messages"]
    assert messages[0]["content"] == "前一次回覆"
    prompt = messages[-1]["content"]
    assert "Dashboard 沒有組 LLM prompt" in prompt
    assert "來源 IP 最近 7 天是否攻擊其他電腦？" in prompt
    assert "來源 IP: 203.0.113.45" in prompt
    assert "Agent IP: 10.0.0.8（端點 IP，不可當作來源 IP / srcip 查詢）" in prompt
    assert "Failed password for admin" in prompt


def test_alert_investigation_uses_source_ip_fast_playbook(monkeypatch) -> None:
    captured: dict[str, Any] = {}

    async def fake_get_alert(alert_id: int) -> dict[str, Any]:
        return {
            "id": alert_id,
            "received_at": 1780060000.0,
            "rule_id": "5712",
            "rule_level": 10,
            "rule_description": "SSH brute force",
            "agent_id": "001",
            "agent_name": "web-prod",
            "agent_ip": "10.0.0.8",
            "llm_severity": "medium",
            "full_log": "Failed password for admin from 203.0.113.45 port 55501 ssh2",
            "raw_alert": (
                '{"timestamp":"2026-05-29T10:14:22+08:00",'
                '"agent":{"id":"001","name":"web-prod","ip":"10.0.0.8"},'
                '"rule":{"id":"5712","level":10,"description":"SSH brute force"},'
                '"data":{"srcip":"203.0.113.45","srcuser":"admin"}}'
            ),
        }

    async def fake_call_tool(name: str, args: dict[str, Any]) -> str:
        captured["tool"] = name
        captured["args"] = args
        return (
            'Security Events: {"data":{"affected_items":['
            '{"timestamp":"2026-05-29T10:14:22+0000",'
            '"agent":{"name":"web-prod"},"rule":{"id":"5712","level":10,'
            '"description":"SSH brute force"},"full_log":"failed login"},'
            '{"timestamp":"2026-05-28T09:00:00+0000",'
            '"agent":{"name":"db-prod"},"rule":{"id":"5712","level":10,'
            '"description":"SSH brute force"},"full_log":"failed login"}],'
            '"total_affected_items":2,"total_failed_items":0}}'
        )

    async def fake_plain_llm_chat(client: Any, messages: list[dict[str, Any]]) -> str:
        captured["summary_prompt"] = messages[-1]["content"]
        return "結論：需要請 IT 優先確認。\n證據：同一來源 IP 命中兩台電腦。\n下一步：持續監控並檢查帳號。"

    async def fail_answer(messages: list[dict[str, str]]) -> dict[str, Any]:
        raise AssertionError("fast playbook should avoid agentic answer()")

    monkeypatch.setattr(investigation_chat.db, "get_alert", fake_get_alert)
    monkeypatch.setattr(investigation_chat.mcp_client, "is_enabled", lambda: True)
    monkeypatch.setattr(investigation_chat.mcp_client, "call_tool", fake_call_tool)
    monkeypatch.setattr(investigation_chat, "_plain_llm_chat", fake_plain_llm_chat)
    monkeypatch.setattr(investigation_chat, "answer", fail_answer)

    result = asyncio.run(
        investigation_chat.answer_for_alert(
            42,
            "來源 203.0.113.45 最近 7 天是否攻擊其他電腦？",
            history=[],
        )
    )

    assert result["answer_zh"].startswith("結論：需要")
    assert captured["tool"] == "search_security_events"
    assert captured["args"]["srcip"] == "203.0.113.45"
    assert captured["args"]["time_range"] == "7d"
    assert captured["args"]["limit"] >= 500
    assert result["evidence"][0]["tool"] == "search_security_events"
    assert "後端 playbook" in captured["summary_prompt"]
    assert "Agent IP: 10.0.0.8（端點 IP，不是來源 IP）" in captured["summary_prompt"]


def test_alert_investigation_fast_playbook_prefers_canonical_signal(monkeypatch) -> None:
    captured: dict[str, Any] = {}

    canonical = {
        "schema_version": "1.0",
        "source": "wazuh",
        "source_product": "Wazuh",
        "source_event_id": "canonical-1",
        "event_time": "2026-05-29T10:14:22+08:00",
        "received_time": "2026-05-29T10:14:23+08:00",
        "signal_type": "authentication.bruteforce",
        "title": "SSH brute force",
        "native_severity": "10",
        "asset": {"id": "001", "name": "web-prod", "ip": "10.0.0.8", "os": "linux"},
        "actor": {"user": "admin", "source_ip": "203.0.113.45"},
        "target": {"user": "admin", "destination_ip": "10.0.0.8", "service": "ssh"},
        "observables": {"ips": ["203.0.113.45"], "domains": [], "hashes": [], "files": [], "processes": [], "commands": []},
        "source_context": {"rule_id": "5712", "rule_groups": ["sshd"], "mitre": ["T1110"], "native_level": "10"},
        "raw_ref": {"kind": "raw_alert", "id": "canonical-1"},
        "source_specific": {"wazuh": {"rule": {"id": "5712"}}},
    }

    async def fake_get_alert(alert_id: int) -> dict[str, Any]:
        return {
            "id": alert_id,
            "received_at": 1780060000.0,
            "rule_id": "5712",
            "rule_level": 10,
            "rule_description": "SSH brute force",
            "agent_id": "001",
            "agent_name": "web-prod",
            "agent_ip": "10.0.0.8",
            "llm_severity": "medium",
            "full_log": "raw alert has no parsed srcip",
            "raw_alert": '{"rule":{"id":"5712","level":10,"description":"SSH brute force"},"data":{}}',
            "canonical_signal": json.dumps(canonical),
        }

    async def fake_call_tool(name: str, args: dict[str, Any]) -> str:
        captured["tool"] = name
        captured["args"] = args
        return '{"data":{"affected_items":[],"total_affected_items":0,"total_failed_items":0}}'

    async def fake_plain_llm_chat(client: Any, messages: list[dict[str, Any]]) -> str:
        captured["summary_prompt"] = messages[-1]["content"]
        return "結論：需要 IT 確認。\n證據：已依 canonical 來源 IP 查詢。\n下一步：持續監控。"

    monkeypatch.setattr(investigation_chat.db, "get_alert", fake_get_alert)
    monkeypatch.setattr(investigation_chat.mcp_client, "is_enabled", lambda: True)
    monkeypatch.setattr(investigation_chat.mcp_client, "call_tool", fake_call_tool)
    monkeypatch.setattr(investigation_chat, "_plain_llm_chat", fake_plain_llm_chat)

    result = asyncio.run(
        investigation_chat.answer_for_alert(
            42,
            "來源 IP 最近 7 天是否攻擊其他電腦？",
            history=[],
        )
    )

    assert result["answer_zh"].startswith("結論：需要")
    assert captured["tool"] == "search_security_events"
    assert captured["args"]["srcip"] == "203.0.113.45"
    assert "Signal type: authentication.bruteforce" in captured["summary_prompt"]
    assert "DATA> - 來源 IP: 203.0.113.45" in captured["summary_prompt"]


def test_alert_investigation_falls_back_to_agentic_for_unclear_question(monkeypatch) -> None:
    captured: dict[str, Any] = {}

    async def fake_get_alert(alert_id: int) -> dict[str, Any]:
        return {
            "id": alert_id,
            "received_at": 1780060000.0,
            "rule_id": "5712",
            "rule_level": 10,
            "rule_description": "SSH brute force",
            "agent_id": "001",
            "agent_name": "web-prod",
            "agent_ip": "10.0.0.8",
            "full_log": "Failed password for admin from 203.0.113.45 port 55501 ssh2",
            "raw_alert": (
                '{"agent":{"id":"001","name":"web-prod","ip":"10.0.0.8"},'
                '"rule":{"id":"5712","level":10,"description":"SSH brute force"},'
                '"data":{"srcip":"203.0.113.45"}}'
            ),
        }

    async def fake_answer(messages: list[dict[str, str]]) -> dict[str, Any]:
        captured["messages"] = messages
        return {"answer_zh": "agentic", "evidence": [], "suggestions": []}

    monkeypatch.setattr(investigation_chat.db, "get_alert", fake_get_alert)
    monkeypatch.setattr(investigation_chat.mcp_client, "is_enabled", lambda: True)
    monkeypatch.setattr(investigation_chat, "answer", fake_answer)

    result = asyncio.run(
        investigation_chat.answer_for_alert(
            42,
            "請解釋 MITRE 技術代碼的意思。",
            history=[],
        )
    )

    assert result["answer_zh"] == "agentic"
    assert "Dashboard 沒有組 LLM prompt" in captured["messages"][-1]["content"]


def test_fast_playbook_suggestions_follow_low_risk_conclusion() -> None:
    suggestions = investigation_chat._deterministic_suggestions(
        "結論：不需要立刻請 IT 處理。\n證據：未查到額外 Wazuh 歷史紀錄。\n下一步：持續監控。",
        [
            {
                "tool": "search_security_events",
                "args": {"srcip": "203.0.113.10", "time_range": "7d", "limit": 500},
                "result_preview": "Total matched by Wazuh: 0",
                "result_log": "Security Events: empty",
            }
        ],
    )

    assert suggestions[0]["action"] == "mark_normal"
    assert suggestions[0]["label_zh"] == "標記正常"


def test_fast_playbook_caps_large_mcp_result_before_llm(monkeypatch) -> None:
    captured: dict[str, Any] = {}

    async def fake_get_alert(alert_id: int) -> dict[str, Any]:
        return {
            "id": alert_id,
            "received_at": 1780060000.0,
            "rule_id": "533",
            "rule_level": 7,
            "rule_description": "Listened ports status changed.",
            "agent_id": "002",
            "agent_name": "titandeacStudio",
            "agent_ip": "192.168.50.20",
            "full_log": "netstat listening ports changed " * 200,
            "raw_alert": (
                '{"agent":{"id":"002","name":"titandeacStudio","ip":"192.168.50.20"},'
                '"rule":{"id":"533","level":7,"description":"Listened ports status changed."},'
                '"data":{}}'
            ),
        }

    async def fake_call_tool(name: str, args: dict[str, Any]) -> str:
        return "Security Events:\n" + ("very large event history\n" * 2000)

    async def fake_plain_llm_chat(client: Any, messages: list[dict[str, Any]]) -> str:
        prompt = messages[-1]["content"]
        captured["prompt"] = prompt
        assert len(prompt) < 6500
        assert "[truncated" in prompt
        return "結論：需要 IT 確認。\n證據：Rule 533 重複發生。\n下一步：查程序與端口。"

    monkeypatch.setattr(investigation_chat.db, "get_alert", fake_get_alert)
    monkeypatch.setattr(investigation_chat.mcp_client, "is_enabled", lambda: True)
    monkeypatch.setattr(investigation_chat.mcp_client, "call_tool", fake_call_tool)
    monkeypatch.setattr(investigation_chat, "_plain_llm_chat", fake_plain_llm_chat)

    result = asyncio.run(
        investigation_chat.answer_for_alert(
            4525,
            "查 titandeacStudio 最近 24 小時異常。",
            history=[],
        )
    )

    assert result["answer_zh"].startswith("結論：需要")
    assert "very large event history" in captured["prompt"]
