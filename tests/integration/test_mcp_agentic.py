from __future__ import annotations

import asyncio
import json
import time
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import httpx
import pytest

from support import fresh_bridge_import


FAKE_TOOLS = [
    {"name": "search_security_events", "description": "Search events"},
    {"name": "get_critical_vulnerabilities", "description": "CVEs"},
    {"name": "check_agent_health", "description": "Agent health"},
    {"name": "get_agent_processes", "description": "Processes"},
    {"name": "get_agent_ports", "description": "Ports"},
]

FAKE_SEARCH_RESULT = (
    "Found 3 events from 10.0.1.45 in the past 7 days: "
    "2x rule 5712 on agent-01 and 1x rule 5710 on agent-02."
)

SUBMIT_VERDICT = {
    "severity": "high",
    "summary_zh": "有人持續從外部 IP 嘗試闖入伺服器",
    "impact_zh": "若成功登入可能導致資料外洩",
    "next_step_zh": "請 IT 立即封鎖來源 IP",
    "investigation_summary_zh": "過去 7 天同一 IP 曾攻擊多台主機，因此判斷為高風險。",
    "root_cause": "SSH brute force from 10.0.1.45 targeting multiple agents",
    "iocs": ["10.0.1.45"],
    "action": "Block 10.0.1.45 and review auth logs on both agents.",
    "mitre": "T1110",
}

SAMPLE_ALERT = {
    "rule": {"id": "5712", "level": 10, "description": "SSH brute force", "groups": ["syslog"]},
    "agent": {"id": "001", "name": "wazuh-agent-01", "ip": "172.18.0.5"},
    "full_log": "Failed password for root from 10.0.1.45 port 55501 ssh2",
    "data": {"srcip": "10.0.1.45"},
}

SAMPLE_ALERT_NO_IP = {
    "rule": {"id": "5710", "level": 5, "description": "Auth failure", "groups": ["syslog"]},
    "agent": {"id": "001", "name": "wazuh-agent-01"},
    "full_log": "su: authentication failure",
    "data": {},
}

SCA_ALERT = {
    "rule": {"id": "19006", "level": 3, "description": "SCA policy check failed", "groups": ["sca"]},
    "agent": {"id": "001", "name": "wazuh-agent-01"},
    "full_log": "CIS check 1.1.1 failed",
    "data": {},
}


class FakeMCPAsyncClient:
    def __init__(self, state: SimpleNamespace, *args: Any, **kwargs: Any) -> None:
        self.state = state

    async def __aenter__(self) -> "FakeMCPAsyncClient":
        return self

    async def __aexit__(self, *args: Any) -> None:
        return None

    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        request = httpx.Request("POST", url)
        if url.endswith("/auth/token"):
            self.state.jwt_refresh_count += 1
            return httpx.Response(200, json={"access_token": "fake-jwt-token"}, request=request)

        if url.endswith("/mcp"):
            headers = kwargs.get("headers") or {}
            if self.state.force_401:
                self.state.force_401 = False
                return httpx.Response(401, json={"detail": "token expired"}, request=request)
            if headers.get("Authorization") != "Bearer fake-jwt-token":
                return httpx.Response(401, json={"detail": "unauthorized"}, request=request)

            body = kwargs.get("json") or {}
            method = body.get("method")
            if method == "tools/list":
                return httpx.Response(200, json={"result": {"tools": FAKE_TOOLS}}, request=request)
            if method == "tools/call":
                params = body.get("params", {})
                self.state.call_log.append(params)
                name = params.get("name")
                if name == "search_security_events":
                    text = FAKE_SEARCH_RESULT
                elif name == "check_agent_health":
                    text = "Agent 001 is online, last seen 5s ago."
                elif name == "get_critical_vulnerabilities":
                    text = "No critical CVEs found on agent 001."
                elif name == "get_agent_processes":
                    text = "sshd, nginx, python3, cron"
                elif name == "get_agent_ports":
                    text = "TCP 22 (sshd), TCP 80 (nginx)"
                else:
                    text = f"(no fake data for tool {name})"
                return httpx.Response(
                    200,
                    json={"result": {"content": [{"type": "text", "text": text}], "isError": False}},
                    request=request,
                )

        return httpx.Response(404, json={"detail": "not found"}, request=request)


class FakeLLMClient:
    def __init__(self, state: SimpleNamespace) -> None:
        self.state = state

    async def post(self, url: str, json: dict[str, Any], timeout: float, **kwargs: Any) -> httpx.Response:
        self.state.llm_call_count += 1
        self.state.tool_turn += 1
        if self.state.tool_turn % 2 == 1:
            tool_call = {
                "id": f"call_{self.state.tool_turn}",
                "type": "function",
                "function": {
                    "name": "search_security_events",
                    "arguments": __import__("json").dumps(
                        {"query": "*", "srcip": "10.0.1.45", "time_range": "7d"}
                    ),
                },
            }
        else:
            tool_call = {
                "id": f"call_{self.state.tool_turn}",
                "type": "function",
                "function": {
                    "name": "submit_final_verdict",
                    "arguments": __import__("json").dumps(SUBMIT_VERDICT, ensure_ascii=False),
                },
            }
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {"role": "assistant", "content": None, "tool_calls": [tool_call]},
                        "finish_reason": "tool_calls",
                    }
                ]
            },
            request=httpx.Request("POST", url),
        )


@pytest.mark.integration
def test_mcp_client_token_refresh_enrichment_and_agentic_loop(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    state = SimpleNamespace(
        call_log=[],
        jwt_refresh_count=0,
        force_401=False,
        llm_call_count=0,
        tool_turn=0,
    )

    monkeypatch.setenv("MCP_SERVER_URL", "http://mcp.local")
    monkeypatch.setenv("MCP_API_KEY", "wazuh_test_key")
    monkeypatch.setenv("MCP_CONNECT_TIMEOUT_S", "3")
    monkeypatch.setenv("MCP_HTTP_TIMEOUT_S", "10")
    monkeypatch.setenv("LM_STUDIO_URL", "http://lm.local/v1/chat/completions")
    monkeypatch.setenv("LM_MODEL", "test-model")
    monkeypatch.setenv("AGENTIC_MAX_ITERATIONS", "6")
    monkeypatch.setenv("AGENTIC_TIMEOUT_S", "60")
    monkeypatch.setenv("AGENTIC_TOOL_RESULT_MAX", "2000")
    monkeypatch.setenv("AGENTIC_TEMPERATURE", "0.0")
    monkeypatch.setenv("AGENTIC_NEVER_GROUPS", "sca,ossec")
    monkeypatch.setenv("AGENTIC_FORCE_LEVEL_GTE", "12")
    monkeypatch.setenv("AGENTIC_BUSINESS_CONTEXT", "false")
    monkeypatch.setenv("DB_PATH", str(tmp_path / "alerts.db"))

    modules = fresh_bridge_import(["mcp_client", "agent_loop", "triage_router", "prompting"])
    mcp_client = modules["mcp_client"]
    agent_loop = modules["agent_loop"]
    triage_router = modules["triage_router"]
    prompting = modules["prompting"]

    def fake_async_client_factory(*args: Any, **kwargs: Any) -> FakeMCPAsyncClient:
        return FakeMCPAsyncClient(state, *args, **kwargs)

    monkeypatch.setattr(mcp_client.httpx, "AsyncClient", fake_async_client_factory)

    async def scenario() -> None:
        assert mcp_client.is_enabled()

        before = state.jwt_refresh_count
        tools = await mcp_client.list_tools()
        assert state.jwt_refresh_count > before
        assert {tool["name"] for tool in tools} >= {"search_security_events", "check_agent_health"}

        state.call_log.clear()
        result = await mcp_client.call_tool(
            "search_security_events",
            {"query": "*", "srcip": "10.0.1.45", "time_range": "7d"},
        )
        assert result is not None
        assert "10.0.1.45" in result
        assert state.call_log[-1]["name"] == "search_security_events"

        mcp_client._jwt_cache["token"] = "stale-token"
        mcp_client._jwt_cache["expires_at"] = time.time() + 9999
        state.force_401 = True
        refresh_before = state.jwt_refresh_count
        refreshed_result = await mcp_client.call_tool("check_agent_health", {"agent_id": "001"})
        assert refreshed_result is not None
        assert "online" in refreshed_result
        assert state.jwt_refresh_count >= refresh_before + 1

        state.call_log.clear()
        enrichment = await mcp_client.enrich_alert(SAMPLE_ALERT)
        assert "MCP RELATED CONTEXT" in enrichment
        assert "10.0.1.45" in enrichment
        assert any(call["name"] == "search_security_events" for call in state.call_log)

        state.call_log.clear()
        assert await mcp_client.enrich_alert(SAMPLE_ALERT_NO_IP) == ""
        assert state.call_log == []

        state.call_log.clear()
        state.tool_turn = 0
        prompt, _, _ = prompting.build_prompt(SAMPLE_ALERT)
        verdict, evidence = await agent_loop.run(
            SAMPLE_ALERT,
            FakeLLMClient(state),
            prompt,
            reason_to_investigate="Check if this IP attacked other agents too",
        )

        assert verdict["severity"] == "high"
        assert verdict["summary_zh"]
        assert verdict["investigation_summary_zh"]
        assert [entry["tool"] for entry in evidence] == [
            "search_security_events",
            "submit_final_verdict",
        ]

        state.tool_turn = 0

        async def broken_mcp(name, args=None):
            raise ConnectionRefusedError("simulated MCP outage")

        with patch.object(mcp_client, "call_tool", broken_mcp):
            prompt, _, _ = prompting.build_prompt(SAMPLE_ALERT)
            verdict2, evidence2 = await agent_loop.run(
                SAMPLE_ALERT,
                FakeLLMClient(state),
                prompt,
                reason_to_investigate="Test MCP failure path",
            )

        assert verdict2["severity"] == "high"
        assert [entry["tool"] for entry in evidence2] == [
            "search_security_events",
            "submit_final_verdict",
        ]

        assert triage_router.decide(SCA_ALERT) == "quick"
        assert triage_router.decide(SAMPLE_ALERT) == "llm_decides"

    asyncio.run(scenario())
