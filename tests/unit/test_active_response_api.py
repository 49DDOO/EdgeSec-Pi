from __future__ import annotations

import asyncio
import json
import time
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

from support import fresh_bridge_import


def _test_app(router) -> FastAPI:
    app = FastAPI()
    app.include_router(router)
    return app


@pytest.mark.unit
def test_active_response_requires_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WAZUH_API_PASS", "test-pass")
    monkeypatch.setenv("ACTIVE_RESPONSE_TOKEN", "")
    active_response_api = fresh_bridge_import(["active_response_api"])["active_response_api"]

    async def scenario() -> None:
        transport = httpx.ASGITransport(app=_test_app(active_response_api.router))
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.post(
                "/active-response/block-ip",
                json={"agent_id": "002", "ip": "198.51.100.42"},
            )

        assert response.status_code == 503
        assert "ACTIVE_RESPONSE_TOKEN is not set" in response.text

    asyncio.run(scenario())


@pytest.mark.unit
def test_active_response_blocks_ip_with_authorized_request(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WAZUH_API_PASS", "test-pass")
    monkeypatch.setenv("ACTIVE_RESPONSE_TOKEN", "secret")
    monkeypatch.setenv("ACTIVE_RESPONSE_PROTECTED_CIDRS", "")
    active_response_api = fresh_bridge_import(["active_response_api"])["active_response_api"]
    calls: list[tuple[str, str]] = []

    async def fake_block_ip(agent_id: str, ip: str) -> dict[str, Any]:
        calls.append((agent_id, ip))
        return {"data": {"total_failed_items": 0}}

    monkeypatch.setattr(active_response_api.wazuh, "block_ip", fake_block_ip)

    async def scenario() -> None:
        transport = httpx.ASGITransport(app=_test_app(active_response_api.router))
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.post(
                "/active-response/block-ip",
                headers={"Authorization": "Bearer secret"},
                json={"agent_id": "002", "ip": "8.8.8.8"},
            )

        assert response.status_code == 200
        assert response.json()["ok"] is True

    asyncio.run(scenario())
    assert calls == [("002", "8.8.8.8")]


@pytest.mark.unit
def test_active_response_rejects_private_ip_before_wazuh_call(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WAZUH_API_PASS", "test-pass")
    monkeypatch.setenv("ACTIVE_RESPONSE_TOKEN", "secret")
    active_response_api = fresh_bridge_import(["active_response_api"])["active_response_api"]

    async def fake_block_ip(agent_id: str, ip: str) -> dict[str, Any]:
        raise AssertionError("private IP should be rejected before Wazuh is called")

    monkeypatch.setattr(active_response_api.wazuh, "block_ip", fake_block_ip)

    async def scenario() -> None:
        transport = httpx.ASGITransport(app=_test_app(active_response_api.router))
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.post(
                "/active-response/block-ip",
                headers={"Authorization": "Bearer secret"},
                json={"agent_id": "002", "ip": "192.168.1.10"},
            )

        assert response.status_code == 409
        assert "公司內部" in response.json()["detail"]

    asyncio.run(scenario())


@pytest.mark.unit
def test_active_response_rejects_protected_asset_cidr(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ACTIVE_RESPONSE_PROTECTED_CIDRS", "8.8.8.0/24")
    active_response_safety = fresh_bridge_import(["active_response_safety"])["active_response_safety"]

    with pytest.raises(active_response_safety.ActiveResponseDenied, match="受保護資產網段"):
        active_response_safety.validate_block_request("002", "8.8.8.8")


@pytest.mark.unit
def test_active_response_rejects_org_profile_asset_ip(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    profile = tmp_path / "org_profile.yaml"
    profile.write_text(
        """
org:
  name: Example
assets:
  - pattern: dns-*
    role: DNS resolver
    ip: 8.8.8.8
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("ORG_PROFILE_PATH", str(profile))
    monkeypatch.setenv("ACTIVE_RESPONSE_PROTECTED_CIDRS", "")
    active_response_safety = fresh_bridge_import(["active_response_safety"])["active_response_safety"]

    with pytest.raises(active_response_safety.ActiveResponseDenied, match="受保護資產網段"):
        active_response_safety.validate_block_request("002", "8.8.8.8")


@pytest.mark.unit
def test_unblock_endpoint_requires_tracked_active_block(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.setenv("WAZUH_API_PASS", "test-pass")
    monkeypatch.setenv("ACTIVE_RESPONSE_TOKEN", "secret")
    monkeypatch.setenv("DB_PATH", str(tmp_path / "alerts.db"))
    active_response_api = fresh_bridge_import(["active_response_api"])["active_response_api"]

    async def scenario() -> None:
        transport = httpx.ASGITransport(app=_test_app(active_response_api.router))
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.post(
                "/active-response/unblock-ip",
                headers={"Authorization": "Bearer secret"},
                json={"agent_id": "002", "ip": "8.8.8.8"},
            )

        assert response.status_code == 409
        assert "找不到 EdgeSec-Pi" in response.json()["detail"]

    asyncio.run(scenario())


@pytest.mark.unit
def test_ttl_sweeper_marks_unsupported_agent_manual_required(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("DB_PATH", str(tmp_path / "alerts.db"))
    monkeypatch.delenv("WAZUH_UNBLOCK_COMMAND", raising=False)
    mods = fresh_bridge_import(["active_response_safety", "active_response_lifecycle"])
    active_response_safety = mods["active_response_safety"]
    active_response_lifecycle = mods["active_response_lifecycle"]

    active_response_safety.record_block(
        "003",
        "8.8.8.8",
        ttl_s=60,
        expires_at=time.time() - 1,
        details={"source": "test"},
    )

    summary = asyncio.run(active_response_lifecycle.sweep_expired_blocks())

    assert summary["processed"] == 1
    blocks = active_response_safety.list_blocks(include_inactive=True)
    assert blocks[0]["status"] == "manual_unblock_required"
    details = json.loads(blocks[0]["details"])
    assert details["ttl_lifecycle"]["result"]["manual_required"] is True


@pytest.mark.unit
def test_ttl_sweeper_unblocks_expired_local_block(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("DB_PATH", str(tmp_path / "alerts.db"))
    mods = fresh_bridge_import(["active_response_safety", "active_response_lifecycle"])
    active_response_safety = mods["active_response_safety"]
    active_response_lifecycle = mods["active_response_lifecycle"]
    calls: list[tuple[str, str, bool, bool]] = []

    async def fake_unblock_ip(
        agent_id: str,
        ip: str,
        *,
        require_tracked: bool = True,
        record_state: bool = True,
    ) -> dict[str, Any]:
        calls.append((agent_id, ip, require_tracked, record_state))
        return {"ok": True, "agent_id": agent_id, "ip": ip, "method": "test"}

    monkeypatch.setattr(active_response_lifecycle.wazuh, "unblock_ip", fake_unblock_ip)
    active_response_safety.record_block(
        "002",
        "8.8.8.8",
        ttl_s=60,
        expires_at=time.time() - 1,
        details={"source": "test"},
    )

    summary = asyncio.run(active_response_lifecycle.sweep_expired_blocks())

    assert summary["processed"] == 1
    assert calls == [("002", "8.8.8.8", False, False)]
    blocks = active_response_safety.list_blocks(include_inactive=True)
    assert blocks[0]["status"] == "unblocked"
    details = json.loads(blocks[0]["details"])
    assert details["unblock"]["result"]["method"] == "test"


@pytest.mark.unit
def test_ttl_claim_is_guarded_against_duplicate_in_progress_work(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("DB_PATH", str(tmp_path / "alerts.db"))
    active_response_safety = fresh_bridge_import(["active_response_safety"])["active_response_safety"]
    record = active_response_safety.record_block(
        "002",
        "8.8.8.8",
        ttl_s=60,
        expires_at=time.time() - 1,
        details={"source": "test"},
    )

    first = active_response_safety.claim_expired_block(record["id"])
    second = active_response_safety.claim_expired_block(record["id"])

    assert first is not None
    assert first["status"] == "expiring"
    assert first["attempt_count"] == 1
    assert second is None


@pytest.mark.unit
def test_ttl_sweeper_retries_unblock_failed_with_backoff(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("DB_PATH", str(tmp_path / "alerts.db"))
    monkeypatch.setenv("ACTIVE_RESPONSE_TTL_UNBLOCK_MAX_ATTEMPTS", "3")
    monkeypatch.setenv("ACTIVE_RESPONSE_TTL_UNBLOCK_RETRY_BASE_S", "60")
    monkeypatch.setenv("ACTIVE_RESPONSE_TTL_UNBLOCK_RETRY_MAX_S", "60")
    mods = fresh_bridge_import(["active_response_safety", "active_response_lifecycle"])
    active_response_safety = mods["active_response_safety"]
    active_response_lifecycle = mods["active_response_lifecycle"]
    calls: list[tuple[str, str]] = []

    async def fake_unblock_ip(
        agent_id: str,
        ip: str,
        *,
        require_tracked: bool = True,
        record_state: bool = True,
    ) -> dict[str, Any]:
        calls.append((agent_id, ip))
        return {"ok": False, "error": "temporary Wazuh API failure"}

    monkeypatch.setattr(active_response_lifecycle.wazuh, "unblock_ip", fake_unblock_ip)
    record = active_response_safety.record_block(
        "002",
        "8.8.8.8",
        ttl_s=60,
        expires_at=time.time() - 1,
        details={"source": "test"},
    )

    first = asyncio.run(active_response_lifecycle.sweep_expired_blocks())
    second = asyncio.run(active_response_lifecycle.sweep_expired_blocks())
    with active_response_safety._connect() as conn:
        conn.execute(
            "UPDATE active_response_actions SET next_retry_at = ? WHERE id = ?",
            (time.time() - 1, record["id"]),
        )
    third = asyncio.run(active_response_lifecycle.sweep_expired_blocks())

    assert first["processed"] == 1
    assert second["processed"] == 0
    assert third["processed"] == 1
    assert calls == [("002", "8.8.8.8"), ("002", "8.8.8.8")]
    blocks = active_response_safety.list_blocks(include_inactive=True)
    assert blocks[0]["status"] == "unblock_failed"
    assert blocks[0]["attempt_count"] == 2
    assert blocks[0]["next_retry_at"] > time.time()


@pytest.mark.unit
def test_ttl_sweeper_escalates_failed_retries_to_manual_required(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("DB_PATH", str(tmp_path / "alerts.db"))
    monkeypatch.setenv("ACTIVE_RESPONSE_TTL_UNBLOCK_MAX_ATTEMPTS", "1")
    mods = fresh_bridge_import(["active_response_safety", "active_response_lifecycle"])
    active_response_safety = mods["active_response_safety"]
    active_response_lifecycle = mods["active_response_lifecycle"]

    async def fake_unblock_ip(
        agent_id: str,
        ip: str,
        *,
        require_tracked: bool = True,
        record_state: bool = True,
    ) -> dict[str, Any]:
        return {"ok": False, "error": "temporary Wazuh API failure"}

    monkeypatch.setattr(active_response_lifecycle.wazuh, "unblock_ip", fake_unblock_ip)
    active_response_safety.record_block(
        "002",
        "8.8.8.8",
        ttl_s=60,
        expires_at=time.time() - 1,
        details={"source": "test"},
    )

    summary = asyncio.run(active_response_lifecycle.sweep_expired_blocks())

    assert summary["processed"] == 1
    blocks = active_response_safety.list_blocks(include_inactive=True)
    assert blocks[0]["status"] == "manual_unblock_required"
    details = json.loads(blocks[0]["details"])
    assert details["ttl_lifecycle"]["attempts_exhausted"] is True


@pytest.mark.unit
def test_active_response_reports_disabled_isolation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WAZUH_API_PASS", "test-pass")
    monkeypatch.setenv("ACTIVE_RESPONSE_TOKEN", "secret")
    active_response_api = fresh_bridge_import(["active_response_api"])["active_response_api"]

    async def fake_isolate_agent(
        agent_id: str,
        reason: str = "",
        *,
        agent_name: str = "",
        platform: str = "",
    ) -> dict[str, Any]:
        return {"ok": False, "error": "endpoint isolation is not enabled"}

    monkeypatch.setattr(active_response_api.wazuh, "isolate_agent", fake_isolate_agent)

    async def scenario() -> None:
        transport = httpx.ASGITransport(app=_test_app(active_response_api.router))
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.post(
                "/active-response/isolate-endpoint",
                headers={"Authorization": "Bearer secret"},
                json={"agent_id": "003", "reason": "suspected compromise"},
            )

        assert response.status_code == 501
        assert response.json()["detail"] == "endpoint isolation is not enabled"

    asyncio.run(scenario())


@pytest.mark.unit
def test_isolation_requires_release_command_and_management_ack(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("DB_PATH", str(tmp_path / "alerts.db"))
    monkeypatch.setenv("WAZUH_ISOLATE_COMMAND", "edgesec-isolate0")
    monkeypatch.delenv("WAZUH_RELEASE_ISOLATE_COMMAND", raising=False)
    monkeypatch.setenv("ACTIVE_RESPONSE_ISOLATION_PRESERVE_CHANNELS_ACK", "1")
    active_response_safety = fresh_bridge_import(["active_response_safety"])["active_response_safety"]

    with pytest.raises(active_response_safety.ActiveResponseDenied, match="解除隔離命令"):
        active_response_safety.validate_isolate_request("003", agent_name="employee-pc")

    monkeypatch.setenv("WAZUH_RELEASE_ISOLATE_COMMAND", "edgesec-release-isolate0")
    monkeypatch.setenv("ACTIVE_RESPONSE_ISOLATION_PRESERVE_CHANNELS_ACK", "0")

    with pytest.raises(active_response_safety.ActiveResponseDenied, match="管理通道"):
        active_response_safety.validate_isolate_request("003", agent_name="employee-pc")


@pytest.mark.unit
def test_isolation_rejects_never_isolate_agent(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.setenv("DB_PATH", str(tmp_path / "alerts.db"))
    monkeypatch.setenv("WAZUH_ISOLATE_COMMAND", "edgesec-isolate0")
    monkeypatch.setenv("WAZUH_RELEASE_ISOLATE_COMMAND", "edgesec-release-isolate0")
    monkeypatch.setenv("ACTIVE_RESPONSE_ISOLATION_PRESERVE_CHANNELS_ACK", "1")
    monkeypatch.setenv("ACTIVE_RESPONSE_NEVER_ISOLATE_AGENTS", "dc-*,004")
    active_response_safety = fresh_bridge_import(["active_response_safety"])["active_response_safety"]

    with pytest.raises(active_response_safety.ActiveResponseDenied, match="永不隔離"):
        active_response_safety.validate_isolate_request("003", agent_name="dc-primary")

    with pytest.raises(active_response_safety.ActiveResponseDenied, match="永不隔離"):
        active_response_safety.validate_isolate_request("004", agent_name="worker")


@pytest.mark.unit
def test_isolation_requires_verified_platform(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.setenv("DB_PATH", str(tmp_path / "alerts.db"))
    monkeypatch.setenv("WAZUH_ISOLATE_COMMAND", "edgesec-isolate0")
    monkeypatch.setenv("WAZUH_RELEASE_ISOLATE_COMMAND", "edgesec-release-isolate0")
    monkeypatch.setenv("ACTIVE_RESPONSE_ISOLATION_PRESERVE_CHANNELS_ACK", "1")
    monkeypatch.delenv("ACTIVE_RESPONSE_ISOLATION_VERIFIED_PLATFORMS", raising=False)
    active_response_safety = fresh_bridge_import(["active_response_safety"])["active_response_safety"]

    capability = active_response_safety.isolation_capability(
        "linux",
        agent_id="003",
        agent_name="employee-pc",
    )
    assert capability["enabled"] is False
    assert capability["platform_ready"] is False
    assert "real-machine" in capability["reason"]

    with pytest.raises(active_response_safety.ActiveResponseDenied, match="尚未通過真機"):
        active_response_safety.validate_isolate_request(
            "003",
            agent_name="employee-pc",
            platform="linux",
        )

    monkeypatch.setenv("ACTIVE_RESPONSE_ISOLATION_VERIFIED_PLATFORMS", "linux,darwin")
    guard = active_response_safety.validate_isolate_request(
        "003",
        agent_name="employee-pc",
        platform="ubuntu",
    )
    assert guard["agent_platform"] == "linux"
    assert "linux" in active_response_safety.isolation_verified_platforms()
    assert "macos" in active_response_safety.isolation_verified_platforms()


@pytest.mark.unit
def test_isolation_capability_endpoint_reports_platform_gate(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("WAZUH_API_PASS", "test-pass")
    monkeypatch.setenv("ACTIVE_RESPONSE_TOKEN", "secret")
    monkeypatch.setenv("DB_PATH", str(tmp_path / "alerts.db"))
    monkeypatch.setenv("WAZUH_ISOLATE_COMMAND", "edgesec-isolate0")
    monkeypatch.setenv("WAZUH_RELEASE_ISOLATE_COMMAND", "edgesec-release-isolate0")
    monkeypatch.setenv("ACTIVE_RESPONSE_ISOLATION_PRESERVE_CHANNELS_ACK", "1")
    monkeypatch.setenv("ACTIVE_RESPONSE_ISOLATION_VERIFIED_PLATFORMS", "linux")
    active_response_api = fresh_bridge_import(["active_response_api"])["active_response_api"]

    async def scenario() -> None:
        transport = httpx.ASGITransport(app=_test_app(active_response_api.router))
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.get(
                "/active-response/isolation-capability?platform=darwin&agent_id=003",
                headers={"Authorization": "Bearer secret"},
            )

        assert response.status_code == 200
        payload = response.json()
        assert payload["enabled"] is False
        assert payload["platform"] == "macos"
        assert payload["verified_platforms"] == ["linux"]

    asyncio.run(scenario())


@pytest.mark.unit
def test_release_isolation_endpoint_requires_tracked_isolation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("WAZUH_API_PASS", "test-pass")
    monkeypatch.setenv("ACTIVE_RESPONSE_TOKEN", "secret")
    monkeypatch.setenv("DB_PATH", str(tmp_path / "alerts.db"))
    monkeypatch.setenv("WAZUH_RELEASE_ISOLATE_COMMAND", "edgesec-release-isolate0")
    active_response_api = fresh_bridge_import(["active_response_api"])["active_response_api"]

    async def scenario() -> None:
        transport = httpx.ASGITransport(app=_test_app(active_response_api.router))
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.post(
                "/active-response/release-isolation",
                headers={"Authorization": "Bearer secret"},
                json={"agent_id": "003", "reason": "handled"},
            )

        assert response.status_code == 409
        assert "找不到 EdgeSec-Pi" in response.json()["detail"]

    asyncio.run(scenario())


@pytest.mark.unit
def test_ttl_sweeper_releases_expired_isolation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("DB_PATH", str(tmp_path / "alerts.db"))
    mods = fresh_bridge_import(["active_response_safety", "active_response_lifecycle"])
    active_response_safety = mods["active_response_safety"]
    active_response_lifecycle = mods["active_response_lifecycle"]
    calls: list[tuple[str, bool, bool, str]] = []

    async def fake_release_isolation(
        agent_id: str,
        *,
        reason: str = "",
        require_tracked: bool = True,
        record_state: bool = True,
    ) -> dict[str, Any]:
        calls.append((agent_id, require_tracked, record_state, reason))
        return {"ok": True, "agent_id": agent_id, "method": "test"}

    monkeypatch.setattr(active_response_lifecycle.wazuh, "release_isolation", fake_release_isolation)
    active_response_safety.record_isolation(
        "003",
        agent_name="employee-pc",
        ttl_s=60,
        expires_at=time.time() - 1,
        details={"source": "test"},
    )

    summary = asyncio.run(active_response_lifecycle.sweep_expired_isolations())

    assert summary["processed"] == 1
    assert calls == [("003", False, False, "isolation TTL expired")]
    isolations = active_response_safety.list_isolations(include_inactive=True)
    assert isolations[0]["action"] == "release_isolation"
    assert isolations[1]["status"] == "released"
    details = json.loads(isolations[1]["details"])
    assert details["release_isolation"]["result"]["method"] == "test"


@pytest.mark.unit
def test_ttl_sweeper_marks_reboot_fail_open_isolation_released(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("DB_PATH", str(tmp_path / "alerts.db"))
    mods = fresh_bridge_import(["active_response_safety", "active_response_lifecycle"])
    active_response_safety = mods["active_response_safety"]
    active_response_lifecycle = mods["active_response_lifecycle"]

    async def fake_release_isolation(
        agent_id: str,
        *,
        reason: str = "",
        require_tracked: bool = True,
        record_state: bool = True,
    ) -> dict[str, Any]:
        return {
            "ok": True,
            "agent_id": agent_id,
            "already_released": True,
            "method": "test-reboot-fail-open",
        }

    monkeypatch.setattr(active_response_lifecycle.wazuh, "release_isolation", fake_release_isolation)
    active_response_safety.record_isolation(
        "003",
        agent_name="employee-pc",
        ttl_s=60,
        expires_at=time.time() - 1,
        details={"source": "test"},
    )

    summary = asyncio.run(active_response_lifecycle.sweep_expired_isolations())

    assert summary["processed"] == 1
    assert summary["results"][0]["status"] == "released"
    isolations = active_response_safety.list_isolations(include_inactive=True)
    assert isolations[1]["status"] == "released"
    details = json.loads(isolations[1]["details"])
    assert details["release_isolation"]["result"]["already_released"] is True
