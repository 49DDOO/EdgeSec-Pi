from __future__ import annotations

import pytest

from support import fresh_bridge_import


@pytest.mark.unit
def test_sca_prompt_includes_description_checks_and_compliance(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.setenv("ORG_PROFILE_PATH", str(tmp_path / "org_profile.yaml"))
    prompting = fresh_bridge_import(["prompting"])["prompting"]

    alert = {
        "rule": {
            "id": "19007",
            "level": 3,
            "description": "CIS Apple macOS - App Store auto updates disabled",
            "groups": ["sca", "compliance"],
        },
        "agent": {"id": "001", "name": "finance-mac"},
        "full_log": "SCA check failed",
        "data": {
            "sca": {
                "check": {
                    "title": "Ensure that application updates are installed",
                    "result": "failed",
                    "description": (
                        "Ensure that application updates are installed after they are "
                        "available from Apple."
                    ),
                    "rationale": (
                        "Patches need to be applied in a timely manner to reduce the "
                        "risk of vulnerabilities being exploited."
                    ),
                    "remediation": (
                        "Terminal Method: Run /usr/bin/sudo /usr/bin/defaults write "
                        "/Library/Preferences/com.apple.commerce AutoUpdate -bool TRUE"
                    ),
                    "condition": "any",
                    "checks": [
                        "c:defaults read /Library/Preferences/com.apple.commerce AutoUpdate -> r:^1$",
                        (
                            "c:osascript -l JavaScript -e "
                            "\"$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SoftwareUpdate')"
                            ".objectForKey('AutomaticallyInstallAppUpdates')\" -> r:^1$"
                        ),
                    ],
                    "compliance": {
                        "cis": ["1.4"],
                        "pci_dss_v3.2.1": ["6.2"],
                        "nist_sp_800-53": ["SI-2(2)"],
                    },
                }
            }
        },
    }

    prompt, _, _ = prompting.build_prompt(alert)

    assert "Description: Ensure that application updates are installed" in prompt
    assert "Checks condition: any" in prompt
    assert "defaults read /Library/Preferences/com.apple.commerce AutoUpdate" in prompt
    assert "AutomaticallyInstallAppUpdates" in prompt
    assert "Compliance:" in prompt
    assert "cis: 1.4" in prompt
    assert "pci_dss_v3.2.1: 6.2" in prompt
    assert "AutoUpdate -bool TRUE" in prompt
