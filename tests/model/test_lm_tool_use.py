from __future__ import annotations

import asyncio
import json
import os

import httpx
import pytest


TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "get_wazuh_alerts_by_ip",
            "description": "Search Wazuh SIEM events from a source IP in a time range.",
            "parameters": {
                "type": "object",
                "properties": {
                    "src_ip": {"type": "string"},
                    "time_range": {"type": "string", "enum": ["1h", "24h", "7d", "30d"]},
                    "limit": {"type": "integer", "default": 20},
                },
                "required": ["src_ip", "time_range"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_agent_processes",
            "description": "List running processes on a Wazuh agent.",
            "parameters": {
                "type": "object",
                "properties": {"agent_id": {"type": "string"}},
                "required": ["agent_id"],
            },
        },
    },
]


PROMPT = (
    "I received this Wazuh alert:\n"
    "  rule.id = 5712 'sshd brute force'\n"
    "  rule.level = 10\n"
    "  data.srcip = 192.0.2.88\n"
    "  agent.id = 002\n"
    "  full_log = 'Failed password for invalid user admin from 192.0.2.88 port 55501 ssh2'\n\n"
    "Before classifying severity, call the most relevant tool to gather context."
)


@pytest.mark.model
def test_real_lm_studio_model_emits_structured_tool_calls() -> None:
    if os.getenv("RUN_MODEL_TESTS") != "1":
        pytest.skip("set RUN_MODEL_TESTS=1 to run real LM Studio model tests")

    lm_url = os.getenv("LM_STUDIO_URL", "http://localhost:1234/v1/chat/completions")
    model = os.getenv("LM_MODEL", "local-model")

    async def scenario() -> None:
        body = {
            "model": model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a SOC analyst with Wazuh investigation tools. "
                        "When given an alert, call the most relevant tool before concluding."
                    ),
                },
                {"role": "user", "content": PROMPT},
            ],
            "tools": TOOLS,
            "tool_choice": "auto",
            "temperature": 0.1,
        }
        async with httpx.AsyncClient(timeout=120) as client:
            response = await client.post(lm_url, json=body)
        assert response.status_code == 200, response.text[:800]

        data = response.json()
        message = data["choices"][0]["message"]
        tool_calls = message.get("tool_calls") or []
        assert tool_calls, json.dumps(data, ensure_ascii=False)[:1200]

        first = tool_calls[0]
        assert first["type"] == "function"
        assert first["function"]["name"] in {
            "get_wazuh_alerts_by_ip",
            "get_agent_processes",
        }
        json.loads(first["function"]["arguments"])

    asyncio.run(scenario())
