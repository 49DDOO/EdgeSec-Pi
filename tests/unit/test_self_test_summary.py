from __future__ import annotations

import pytest

from support import fresh_bridge_import


@pytest.mark.unit
def test_self_test_summary_fails_only_required_failures() -> None:
    self_test = fresh_bridge_import(["self_test"])["self_test"]

    summary = self_test._summarize(
        [
            {"status": "ok", "required": True},
            {"status": "fail", "required": True},
            {"status": "warn", "required": False},
        ]
    )

    assert summary["overall"] == "fail"
    assert "IT" in summary["title_zh"]


@pytest.mark.unit
def test_self_test_summary_warns_on_non_required_warnings() -> None:
    self_test = fresh_bridge_import(["self_test"])["self_test"]

    summary = self_test._summarize(
        [
            {"status": "ok", "required": True},
            {"status": "warn", "required": False},
        ]
    )

    assert summary["overall"] == "warn"
    assert "可以使用" in summary["title_zh"]


@pytest.mark.unit
def test_self_test_summary_ok_when_all_checks_ok_or_skipped() -> None:
    self_test = fresh_bridge_import(["self_test"])["self_test"]

    summary = self_test._summarize(
        [
            {"status": "ok", "required": True},
            {"status": "skip", "required": False},
        ]
    )

    assert summary["overall"] == "ok"
    assert "正常使用" in summary["title_zh"]
