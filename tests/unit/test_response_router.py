from __future__ import annotations

import pytest

from support import fresh_bridge_import


@pytest.mark.unit
def test_public_source_ip_is_the_only_block_candidate(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("DB_PATH", str(tmp_path / "alerts.db"))
    response_router = fresh_bridge_import(["response_router"])["response_router"]

    decision = response_router.recommend(
        {
            "agent": {"id": "003", "name": "web-prod", "ip": "10.0.0.10"},
            "data": {"srcip": "8.8.8.8"},
            "rule": {"description": "SSH brute force"},
        },
        {
            "severity": "high",
            "iocs": ["1.1.1.1"],
        },
    )

    assert decision["direction"] == "external_to_endpoint"
    assert decision["block_source_ips"] == ["8.8.8.8"]
    assert decision["allow_isolate_endpoint"] is False


@pytest.mark.unit
def test_llm_ioc_does_not_create_block_action_without_structured_source(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("DB_PATH", str(tmp_path / "alerts.db"))
    response_router = fresh_bridge_import(["response_router"])["response_router"]

    decision = response_router.recommend(
        {
            "agent": {"id": "003", "name": "web-prod", "ip": "192.168.50.20"},
            "data": {"srcip": "192.168.50.10"},
            "rule": {"description": "Internal SSH failures"},
        },
        {
            "severity": "high",
            "iocs": ["8.8.8.8"],
        },
    )

    assert decision["direction"] == "internal_source"
    assert decision["block_source_ips"] == []
    assert decision["allow_isolate_endpoint"] is False


@pytest.mark.unit
def test_endpoint_outbound_high_alert_recommends_isolation_not_source_block(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("DB_PATH", str(tmp_path / "alerts.db"))
    response_router = fresh_bridge_import(["response_router"])["response_router"]

    decision = response_router.recommend(
        {
            "agent": {"id": "003", "name": "employee-pc", "ip": "192.168.50.20"},
            "data": {"srcip": "192.168.50.20", "dstip": "8.8.8.8"},
            "rule": {"level": 10, "description": "Suspicious outbound connection"},
        },
        {"severity": "high", "summary_zh": "這台電腦主動連到可疑外部位址。"},
    )

    assert decision["direction"] == "endpoint_to_external"
    assert decision["block_source_ips"] == []
    assert decision["allow_isolate_endpoint"] is True


@pytest.mark.unit
def test_successful_login_from_external_allows_block_and_isolation(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("DB_PATH", str(tmp_path / "alerts.db"))
    response_router = fresh_bridge_import(["response_router"])["response_router"]

    decision = response_router.recommend(
        {
            "agent": {"id": "003", "name": "web-prod", "ip": "10.0.0.10"},
            "data": {"srcip": "8.8.8.8"},
            "rule": {"description": "SSH brute force followed by successful login"},
        },
        {"severity": "high", "root_cause": "successful login after brute force"},
    )

    assert decision["direction"] == "external_to_endpoint"
    assert decision["block_source_ips"] == ["8.8.8.8"]
    assert decision["allow_isolate_endpoint"] is True
