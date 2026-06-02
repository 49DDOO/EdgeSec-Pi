from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
EVAL_DIR = ROOT / "wazuh-llm-bridge" / "eval"
BASELINE_MODULE = EVAL_DIR / "baseline.py"
CORPUS_PATH = EVAL_DIR / "corpus.jsonl"
BASELINE_PATH = EVAL_DIR / "baseline_wazuh_v1.json"


def _load_baseline_module():
    spec = importlib.util.spec_from_file_location("edgesec_eval_baseline", BASELINE_MODULE)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _case_by_id(baseline: dict, case_id: str) -> dict:
    return next(item for item in baseline["cases"] if item["case_id"] == case_id)


@pytest.mark.unit
def test_wazuh_eval_baseline_is_deterministic() -> None:
    baseline_module = _load_baseline_module()

    actual = baseline_module.build_baseline(CORPUS_PATH)
    expected = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))

    assert actual == expected


@pytest.mark.unit
def test_wazuh_eval_baseline_keeps_non_llm_quality_floor() -> None:
    baseline = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))

    assert baseline["schema_version"] == "wazuh-deterministic-baseline-v1"
    assert baseline["case_count"] == 21
    assert all(case["canonical"]["source"] == "wazuh" for case in baseline["cases"])
    assert all(case["technical_evidence"]["source"] == "wazuh" for case in baseline["cases"])

    ssh = _case_by_id(baseline, "ssh_brute_force")
    assert ssh["canonical"]["signal_type"] == "authentication.bruteforce"
    assert ssh["canonical"]["source_ip"] == "203.0.113.45"
    assert ssh["technical_evidence"]["module"] == "authentication"
    assert ssh["technical_evidence"]["indicator_values"]["username"] == "admin"

    cve = _case_by_id(baseline, "cve_apache_rce")
    assert cve["human_expected_severity"] == "critical"
    assert cve["canonical"]["signal_type"] == "vulnerability.detected"
    assert cve["technical_evidence"]["module"] == "vulnerability"

    c2 = _case_by_id(baseline, "c2_beacon_cn_geo")
    assert c2["canonical"]["observables"]["ips"] == ["10.0.5.20", "45.61.139.22"]
    assert c2["technical_evidence"]["indicator_values"]["destination_ip"] == "45.61.139.22"

    windows = _case_by_id(baseline, "win_sysmon_alice_psh_profile")
    assert "win" in windows["canonical"]["source_specific_keys"]
    assert windows["canonical"]["actor_user"] == "alice"
    assert windows["technical_evidence"]["module"] == "windows"
    assert windows["technical_evidence"]["indicator_values"]["process"].endswith("powershell.exe")
