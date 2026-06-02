from __future__ import annotations

import asyncio
from pathlib import Path
import sys
from typing import Any

import pytest


ROOT = Path(__file__).resolve().parents[2]
BRIDGE = ROOT / "wazuh-llm-bridge"
if str(BRIDGE) not in sys.path:
    sys.path.insert(0, str(BRIDGE))

import tool_loop  # noqa: E402


def _tool_call(name: str, args: dict[str, Any], call_id: str = "call-1") -> dict[str, Any]:
    import json

    return {
        "id": call_id,
        "type": "function",
        "function": {
            "name": name,
            "arguments": json.dumps(args),
        },
    }


def test_run_tool_loop_calls_tool_callback_and_continues(monkeypatch) -> None:
    calls = [
        {"role": "assistant", "content": None, "tool_calls": [_tool_call("lookup", {"ip": "203.0.113.8"})]},
        {"role": "assistant", "content": "final answer"},
    ]
    seen: list[tool_loop.ToolInvocation] = []

    async def fake_chat_with_tools(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        return calls.pop(0)

    async def on_tool_call(invocation: tool_loop.ToolInvocation) -> tool_loop.ToolLoopAction:
        seen.append(invocation)
        return tool_loop.ToolLoopAction.append({
            "role": "tool",
            "tool_call_id": invocation.tool_call_id,
            "content": "tool result",
        })

    async def on_no_tool_calls(
        assistant: dict[str, Any],
        _round_index: int,
        messages: list[dict[str, Any]],
    ) -> tool_loop.ToolLoopAction:
        return tool_loop.ToolLoopAction.finish({
            "content": assistant["content"],
            "messages": messages,
        })

    monkeypatch.setattr(tool_loop, "chat_with_tools", fake_chat_with_tools)

    messages: list[dict[str, Any]] = [{"role": "user", "content": "check ip"}]
    result = asyncio.run(
        tool_loop.run_tool_loop(
            client=object(),
            messages=messages,
            tools=[],
            max_model_turns=2,
            on_tool_call=on_tool_call,
            on_no_tool_calls=on_no_tool_calls,
        )
    )

    assert result["content"] == "final answer"
    assert len(seen) == 1
    assert seen[0].name == "lookup"
    assert seen[0].args == {"ip": "203.0.113.8"}
    assert seen[0].tool_call_id == "call-1"
    assert seen[0].round_index == 0
    assert seen[0].call_index == 0
    assert {"role": "tool", "tool_call_id": "call-1", "content": "tool result"} in result["messages"]


def test_run_tool_loop_finish_returns_callback_value(monkeypatch) -> None:
    async def fake_chat_with_tools(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        return {"role": "assistant", "content": "done"}

    async def on_tool_call(_invocation: tool_loop.ToolInvocation) -> tool_loop.ToolLoopAction:
        raise AssertionError("no tool call expected")

    async def on_no_tool_calls(
        assistant: dict[str, Any],
        round_index: int,
        _messages: list[dict[str, Any]],
    ) -> tool_loop.ToolLoopAction:
        return tool_loop.ToolLoopAction.finish({
            "answer": assistant["content"],
            "round_index": round_index,
        })

    monkeypatch.setattr(tool_loop, "chat_with_tools", fake_chat_with_tools)

    result = asyncio.run(
        tool_loop.run_tool_loop(
            client=object(),
            messages=[],
            tools=[],
            max_model_turns=1,
            on_tool_call=on_tool_call,
            on_no_tool_calls=on_no_tool_calls,
        )
    )

    assert result == {"answer": "done", "round_index": 0}


def test_run_tool_loop_raises_exhausted_error_when_not_finished(monkeypatch) -> None:
    async def fake_chat_with_tools(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        return {"role": "assistant", "content": "continue"}

    async def on_tool_call(_invocation: tool_loop.ToolInvocation) -> tool_loop.ToolLoopAction:
        raise AssertionError("no tool call expected")

    async def on_no_tool_calls(
        _assistant: dict[str, Any],
        _round_index: int,
        _messages: list[dict[str, Any]],
    ) -> tool_loop.ToolLoopAction:
        return tool_loop.ToolLoopAction.append({"role": "user", "content": "try again"})

    monkeypatch.setattr(tool_loop, "chat_with_tools", fake_chat_with_tools)

    with pytest.raises(RuntimeError, match="custom exhausted"):
        asyncio.run(
            tool_loop.run_tool_loop(
                client=object(),
                messages=[],
                tools=[],
                max_model_turns=1,
                on_tool_call=on_tool_call,
                on_no_tool_calls=on_no_tool_calls,
                exhausted_error_factory=lambda _elapsed: RuntimeError("custom exhausted"),
            )
        )


def test_run_tool_loop_raises_timeout_before_model_call(monkeypatch) -> None:
    async def fake_chat_with_tools(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        raise AssertionError("model should not be called after timeout")

    times = iter([100.0, 102.0])

    monkeypatch.setattr(tool_loop, "chat_with_tools", fake_chat_with_tools)
    monkeypatch.setattr(tool_loop.time, "time", lambda: next(times))

    with pytest.raises(TimeoutError, match="custom timeout"):
        asyncio.run(
            tool_loop.run_tool_loop(
                client=object(),
                messages=[],
                tools=[],
                max_model_turns=1,
                on_tool_call=lambda _invocation: None,
                on_no_tool_calls=lambda _assistant, _round_index, _messages: None,
                total_timeout_s=1,
                timeout_error_factory=lambda _elapsed: TimeoutError("custom timeout"),
            )
        )


def test_parse_tool_call_tolerates_invalid_json_args() -> None:
    invocation = tool_loop.parse_tool_call(
        {
            "id": "bad-json",
            "function": {
                "name": "lookup",
                "arguments": "{not-json",
            },
        }
    )

    assert invocation.name == "lookup"
    assert invocation.args == {}
    assert invocation.tool_call_id == "bad-json"
