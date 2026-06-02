from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "wazuh-stack" / "active-response" / "edgesec-ar.py"


@pytest.mark.unit
def test_edgesec_ar_dry_run_isolate_preserves_manager_and_ttl(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("EDGESEC_AR_METHOD", "linux-iptables")
    payload = {
        "parameters": {
            "alert": {"data": {"ttl_s": 120}},
            "extra_args": ["Slack requested isolation", "120"],
        }
    }

    proc = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "isolate",
            "--dry-run",
            "--manager",
            "127.0.0.1",
            "--state-dir",
            str(tmp_path),
            "--no-schedule",
        ],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        check=False,
    )

    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout)
    assert result["ok"] is True
    assert result["action"] == "isolate"
    assert result["ttl_s"] == 120
    assert "127.0.0.1/32" in result["allow_networks"]
    assert any("EDGESEC_AR_OUT" in command for command in result["commands"])
    assert not any("ESTABLISHED,RELATED" in command for command in result["commands"])


@pytest.mark.unit
def test_edgesec_ar_linux_dry_run_adds_ipv6_chain(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("EDGESEC_AR_METHOD", "linux-iptables")

    proc = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "isolate",
            "--dry-run",
            "--allow-cidr",
            "::1/128",
            "--state-dir",
            str(tmp_path),
            "--no-schedule",
        ],
        text=True,
        capture_output=True,
        check=False,
    )

    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout)
    assert "::1/128" in result["allow_networks"]
    assert any("ip6tables" in command and "EDGESEC_AR6_OUT" in command for command in result["commands"])


@pytest.mark.unit
def test_edgesec_ar_macos_uses_pf_not_route_quarantine(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("EDGESEC_AR_METHOD", raising=False)
    monkeypatch.setenv("EDGESEC_AR_PLATFORM", "darwin")

    proc = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "isolate",
            "--dry-run",
            "--manager",
            "127.0.0.1",
            "--allow-cidr",
            "::1/128",
            "--state-dir",
            str(tmp_path),
            "--no-schedule",
        ],
        text=True,
        capture_output=True,
        check=False,
    )

    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout)
    assert result["method"] == "macos-pf"
    assert any("pfctl -a com.apple/edgesec-ar -f" in command for command in result["commands"])
    assert any("pfctl -k 0.0.0.0/0" in command for command in result["commands"])
    assert not any("route -n delete default" in command for command in result["commands"])


@pytest.mark.unit
def test_edgesec_ar_windows_uses_firewall_not_route_quarantine(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("EDGESEC_AR_METHOD", raising=False)
    monkeypatch.setenv("EDGESEC_AR_PLATFORM", "windows")

    proc = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "isolate",
            "--dry-run",
            "--manager",
            "127.0.0.1",
            "--allow-cidr",
            "::1/128",
            "--state-dir",
            str(tmp_path),
            "--no-schedule",
        ],
        text=True,
        capture_output=True,
        check=False,
    )

    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout)
    assert result["method"] == "windows-firewall"
    assert any("New-NetFirewallRule" in command for command in result["commands"])
    assert any("Set-NetFirewallProfile" in command for command in result["commands"])
    assert not any("Remove-NetRoute" in command for command in result["commands"])


@pytest.mark.unit
def test_edgesec_ar_dry_run_scheduler_does_not_use_sleep_delay(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("EDGESEC_AR_METHOD", "linux-iptables")

    proc = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "isolate",
            "--dry-run",
            "--manager",
            "127.0.0.1",
            "--state-dir",
            str(tmp_path),
        ],
        text=True,
        capture_output=True,
        check=False,
    )

    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout)
    schedule_commands = [
        command for command in result["commands"] if command.startswith("schedule ")
    ]
    assert schedule_commands
    assert "--scheduled" in schedule_commands[0]
    assert "--delay" not in schedule_commands[0]


@pytest.mark.unit
def test_edgesec_ar_linux_prefers_at_over_systemd_run(tmp_path, monkeypatch) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name in ("at", "systemd-run"):
        executable = bin_dir / name
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o755)

    monkeypatch.setenv("EDGESEC_AR_METHOD", "linux-iptables")
    monkeypatch.setenv("EDGESEC_AR_PLATFORM", "linux")
    monkeypatch.setenv("PATH", str(bin_dir) + os.pathsep + os.environ.get("PATH", ""))

    proc = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "isolate",
            "--dry-run",
            "--manager",
            "127.0.0.1",
            "--state-dir",
            str(tmp_path),
        ],
        text=True,
        capture_output=True,
        check=False,
    )

    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout)
    assert result["schedule_method"] == "at"
    assert any(command.startswith("schedule at ") for command in result["commands"])


@pytest.mark.unit
def test_edgesec_ar_route_quarantine_dry_run_uses_placeholder_routes(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("EDGESEC_AR_PLATFORM", "darwin")
    monkeypatch.setenv("EDGESEC_AR_METHOD", "route-quarantine")

    proc = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "isolate",
            "--dry-run",
            "--manager",
            "127.0.0.1",
            "--state-dir",
            str(tmp_path),
            "--no-schedule",
        ],
        text=True,
        capture_output=True,
        check=False,
    )

    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout)
    assert result["method"] == "route-quarantine"
    assert any("route -n delete default 192.0.2.1" in command for command in result["commands"])


@pytest.mark.unit
def test_edgesec_ar_refuses_isolate_without_manager_allowlist(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("EDGESEC_AR_METHOD", "linux-iptables")

    proc = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "isolate",
            "--dry-run",
            "--state-dir",
            str(tmp_path),
            "--no-schedule",
        ],
        text=True,
        capture_output=True,
        check=False,
    )

    assert proc.returncode == 2
    assert "refusing to isolate without a resolvable Wazuh manager" in proc.stderr


@pytest.mark.unit
def test_edgesec_ar_dry_run_release_uses_saved_method(tmp_path) -> None:
    (tmp_path / "edgesec-ar-state.json").write_text(
        json.dumps({
            "method": "linux-iptables",
            "routes": [],
            "allow_networks": ["127.0.0.1/32"],
        }),
        encoding="utf-8",
    )

    proc = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "release",
            "--dry-run",
            "--state-dir",
            str(tmp_path),
        ],
        text=True,
        capture_output=True,
        check=False,
    )

    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout)
    assert result["ok"] is True
    assert result["action"] == "release"
    assert result["method"] == "linux-iptables"
    assert any("EDGESEC_AR_OUT" in command for command in result["commands"])
