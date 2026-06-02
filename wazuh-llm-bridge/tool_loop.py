"""Shared OpenAI-style tool-calling loop utilities."""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional

import httpx

import llm_client


@dataclass(frozen=True)
class ToolInvocation:
    raw: dict[str, Any]
    name: str
    args: dict[str, Any]
    tool_call_id: str
    round_index: int
    call_index: int


@dataclass
class ToolLoopAction:
    done: bool = False
    value: Any = None
    messages: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def finish(cls, value: Any) -> "ToolLoopAction":
        return cls(done=True, value=value)

    @classmethod
    def append(cls, *messages: dict[str, Any]) -> "ToolLoopAction":
        return cls(messages=list(messages))


ToolCallback = Callable[[ToolInvocation], Awaitable[Optional[ToolLoopAction]]]
NoToolCallback = Callable[
    [dict[str, Any], int, list[dict[str, Any]]],
    Awaitable[Optional[ToolLoopAction]],
]
ErrorFactory = Callable[[float], BaseException]


def allowed_tool_names(tools: list[dict[str, Any]]) -> set[str]:
    names: set[str] = set()
    for tool in tools:
        function = tool.get("function") if isinstance(tool, dict) else None
        if isinstance(function, dict):
            name = str(function.get("name") or "").strip()
            if name:
                names.add(name)
    return names


def strip_for_history(message: dict[str, Any]) -> dict[str, Any]:
    """Keep only fields accepted when echoing assistant messages back."""
    out: dict[str, Any] = {"role": "assistant"}
    if message.get("content") is not None:
        out["content"] = message["content"]
    if message.get("tool_calls"):
        out["tool_calls"] = message["tool_calls"]
    return out


def parse_tool_call(
    tool_call: dict[str, Any],
    *,
    round_index: int = 0,
    call_index: int = 0,
    logger: logging.Logger | None = None,
) -> ToolInvocation:
    function = tool_call.get("function") or {}
    name = str(function.get("name") or "")
    raw_args = function.get("arguments") or "{}"
    try:
        args = json.loads(raw_args) if isinstance(raw_args, str) else dict(raw_args or {})
    except Exception:
        if logger:
            logger.warning("invalid tool args for %s: %s", name, str(raw_args)[:200])
        args = {}
    return ToolInvocation(
        raw=tool_call,
        name=name,
        args=args,
        tool_call_id=str(tool_call.get("id") or ""),
        round_index=round_index,
        call_index=call_index,
    )


async def chat_with_tools(
    client: httpx.AsyncClient,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    *,
    temperature: float = 0.1,
    timeout_s: float | None = None,
) -> dict[str, Any]:
    payload = {
        "messages": messages,
        "tools": tools,
        "tool_choice": "auto",
        "temperature": temperature,
        "stream": False,
    }
    response = await llm_client.chat_completion(client, payload, timeout=timeout_s)
    return response["choices"][0]["message"]


async def run_tool_loop(
    *,
    client: httpx.AsyncClient,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    max_model_turns: int,
    on_tool_call: ToolCallback,
    on_no_tool_calls: NoToolCallback,
    max_tool_rounds: int | None = None,
    on_round_limit: NoToolCallback | None = None,
    total_timeout_s: float | None = None,
    temperature: float = 0.1,
    completion_timeout_s: float | None = None,
    timeout_error_factory: ErrorFactory | None = None,
    exhausted_error_factory: ErrorFactory | None = None,
    logger: logging.Logger | None = None,
    log_label: str = "tool-loop",
) -> Any:
    start = time.time()
    for round_index in range(max(0, int(max_model_turns))):
        elapsed = time.time() - start
        if total_timeout_s is not None and elapsed > total_timeout_s:
            if timeout_error_factory:
                raise timeout_error_factory(elapsed)
            raise TimeoutError(f"{log_label} exceeded {total_timeout_s}s")

        if logger:
            logger.info("%s iter %d/%d (elapsed %.1fs)",
                        log_label, round_index + 1, max_model_turns, elapsed)

        assistant = await chat_with_tools(
            client,
            messages,
            tools,
            temperature=temperature,
            timeout_s=completion_timeout_s,
        )
        messages.append(strip_for_history(assistant))

        raw_calls = assistant.get("tool_calls") or []
        if not raw_calls:
            action = await on_no_tool_calls(assistant, round_index, messages)
            if action:
                if action.done:
                    return action.value
                messages.extend(action.messages)
            continue

        if max_tool_rounds is not None and round_index >= max_tool_rounds:
            if on_round_limit is None:
                raise RuntimeError(f"{log_label} reached tool round limit")
            action = await on_round_limit(assistant, round_index, messages)
            if action:
                if action.done:
                    return action.value
                messages.extend(action.messages)
            continue

        for call_index, raw_call in enumerate(raw_calls):
            invocation = parse_tool_call(
                raw_call,
                round_index=round_index,
                call_index=call_index,
                logger=logger,
            )
            action = await on_tool_call(invocation)
            if action:
                if action.done:
                    return action.value
                messages.extend(action.messages)

    elapsed = time.time() - start
    if exhausted_error_factory:
        raise exhausted_error_factory(elapsed)
    raise RuntimeError(f"{log_label} did not finish after {max_model_turns} model turn(s)")
