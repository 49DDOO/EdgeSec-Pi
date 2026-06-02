from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BRIDGE = ROOT / "wazuh-llm-bridge"
if str(BRIDGE) not in sys.path:
    sys.path.insert(0, str(BRIDGE))

import investigation_prompting  # noqa: E402


def test_tool_result_is_wrapped_as_mdr_evidence_block() -> None:
    block = investigation_prompting.format_tool_result_for_prompt(
        tool_name="search_security_events",
        args={"query": "*", "srcip": "203.0.113.45", "time_range": "7d", "limit": 20},
        result=(
            "Found 3 events from 203.0.113.45 in the past 7 days: "
            "2 failed logins on web-prod and 1 failed login on db-prod."
        ),
    )

    assert "MCP INVESTIGATION EVIDENCE BLOCK" in block
    assert "QUERY BOUNDARY" in block
    assert "lookback: 7d" in block
    assert "srcip: 203.0.113.45" in block
    assert "HISTORICAL TRAJECTORY / TOOL RESULT" in block
    assert "POSITIVE FINDINGS" in block
    assert "NEGATIVE FINDINGS" in block
    assert "UNKNOWN / NOT QUERIED" in block
    assert "Endpoint process state" in block


def test_initial_investigation_prompt_contains_current_alert_and_contract() -> None:
    prompt = investigation_prompting.build_investigation_user_prompt(
        alert={
            "timestamp": "2026-05-29T10:14:22+08:00",
            "rule": {"id": "5712", "level": 10, "description": "SSH brute force"},
            "agent": {"id": "001", "name": "web-prod", "ip": "10.0.0.5"},
            "data": {"srcip": "203.0.113.45", "srcuser": "admin"},
            "full_log": "Failed password for admin from 203.0.113.45",
        },
        base_user_prompt="STAGE 1 PROMPT HERE",
        reason_to_investigate="Check whether the source IP hit other agents.",
        prior_stage1={"severity": "medium", "summary_zh": "有人嘗試登入 web-prod"},
    )

    assert "MDR INVESTIGATION MODE" in prompt
    assert "CURRENT CANONICAL SIGNAL" in prompt
    assert "event_time: 2026-05-29T10:14:22+08:00" in prompt
    assert "source_ip: 203.0.113.45" in prompt
    assert "signal_type: authentication.bruteforce" in prompt
    assert "MDR EVIDENCE CONTRACT" in prompt
    assert "Separate positive findings, negative findings, and unknown/not queried items." in prompt
    assert "STAGE-1 PROMPT CONTEXT" in prompt
    assert "STAGE 1 PROMPT HERE" in prompt
