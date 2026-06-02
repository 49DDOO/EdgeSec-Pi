"""
Deterministic Wazuh baseline generator.

This locks the non-LLM parts of the current Wazuh pipeline before moving
prompting and evidence readers onto the canonical signal contract. It is
deliberately narrow: no LM Studio calls, no free-form prose assertions, and no
timestamps that change between runs.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
BRIDGE_DIR = HERE.parent
sys.path.insert(0, str(BRIDGE_DIR))

import canonical_signal  # noqa: E402
import technical_evidence  # noqa: E402


BASELINE_SCHEMA_VERSION = "wazuh-deterministic-baseline-v1"
DEFAULT_RECEIVED_AT = 1760000000


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value in (None, "", [], {}):
        return []
    return [value]


def _nonempty_keys(value: dict[str, Any]) -> list[str]:
    return sorted(
        str(key)
        for key, item in value.items()
        if item not in (None, "", [], {})
    )


def _compact_indicator_values(indicators: dict[str, Any]) -> dict[str, Any]:
    selected_keys = (
        "source_ip",
        "destination_ip",
        "username",
        "file_path",
        "process",
        "port",
        "domain",
        "cve",
        "package",
        "package_version",
        "hashes",
    )
    return {
        key: indicators[key]
        for key in selected_keys
        if indicators.get(key) not in (None, "", [], {})
    }


def _technical_row(alert: dict[str, Any]) -> dict[str, Any]:
    rule = _dict(alert.get("rule"))
    agent = _dict(alert.get("agent"))
    return {
        "siem_source": "wazuh",
        "rule_id": rule.get("id", ""),
        "rule_level": rule.get("level", 0),
        "rule_description": rule.get("description", ""),
        "agent_id": agent.get("id", ""),
        "agent_name": agent.get("name", ""),
        "agent_ip": agent.get("ip", ""),
        "full_log": alert.get("full_log", ""),
        "llm_action": "",
        "llm_iocs": [],
    }


def _technical_summary(alert: dict[str, Any]) -> dict[str, Any]:
    evidence = technical_evidence.build_technical_evidence(
        row=_technical_row(alert),
        raw_alert=alert,
        llm={"iocs": [], "mitre": None, "action": ""},
    )
    indicators = _dict(evidence.get("indicators"))
    module_context = _dict(evidence.get("module_context"))
    summary: dict[str, Any] = {
        "source": evidence.get("source", ""),
        "module": evidence.get("module", ""),
        "rule_id": _dict(evidence.get("rule")).get("id", ""),
        "endpoint_name": _dict(evidence.get("endpoint")).get("name", ""),
        "indicator_keys": _nonempty_keys(indicators),
        "indicator_values": _compact_indicator_values(indicators),
        "module_context_keys": _nonempty_keys(module_context),
        "raw_log_present": bool(_dict(evidence.get("raw")).get("full_log")),
    }
    if evidence.get("fim_brief"):
        fim_brief = _dict(evidence.get("fim_brief"))
        summary["fim_brief"] = {
            "category": fim_brief.get("category", ""),
            "severity": fim_brief.get("severity", ""),
            "file_path": fim_brief.get("file_path", ""),
            "changed_by": fim_brief.get("changed_by", ""),
            "process": fim_brief.get("process", ""),
        }
    return summary


def _canonical_summary(alert: dict[str, Any]) -> dict[str, Any]:
    signal = canonical_signal.from_alert(alert, received_at=DEFAULT_RECEIVED_AT)
    source_specific = _dict(signal.get("source_specific"))
    wazuh_specific = _dict(source_specific.get("wazuh"))
    return {
        "source": signal.get("source", ""),
        "source_product": signal.get("source_product", ""),
        "signal_type": signal.get("signal_type", ""),
        "title": signal.get("title", ""),
        "native_severity": signal.get("native_severity", ""),
        "asset_name": _dict(signal.get("asset")).get("name", ""),
        "actor_user": _dict(signal.get("actor")).get("user", ""),
        "source_ip": _dict(signal.get("actor")).get("source_ip", ""),
        "destination_ip": _dict(signal.get("target")).get("destination_ip", ""),
        "target_service": _dict(signal.get("target")).get("service", ""),
        "observables": signal.get("observables", {}),
        "mitre": _list(_dict(signal.get("source_context")).get("mitre")),
        "rule_groups": _list(_dict(signal.get("source_context")).get("rule_groups")),
        "source_specific_keys": sorted(wazuh_specific.keys()),
    }


def load_corpus(corpus_path: Path) -> list[dict[str, Any]]:
    with corpus_path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def build_baseline(corpus_path: Path) -> dict[str, Any]:
    cases = []
    for item in load_corpus(corpus_path):
        alert = _dict(item.get("alert"))
        expected = _dict(item.get("expected"))
        rule = _dict(alert.get("rule"))
        agent = _dict(alert.get("agent"))
        cases.append(
            {
                "case_id": item.get("id", ""),
                "human_expected_severity": expected.get("severity", ""),
                "human_expected_keywords": _list(expected.get("keywords")),
                "rule_id": rule.get("id", ""),
                "rule_level": rule.get("level", 0),
                "agent_name": agent.get("name", ""),
                "canonical": _canonical_summary(alert),
                "technical_evidence": _technical_summary(alert),
            }
        )
    summary = _baseline_summary(cases)
    return {
        "schema_version": BASELINE_SCHEMA_VERSION,
        "corpus": corpus_path.name,
        "received_at_epoch": DEFAULT_RECEIVED_AT,
        "case_count": len(cases),
        "summary": summary,
        "cases": cases,
    }


def _count_by(cases: list[dict[str, Any]], path: tuple[str, ...]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for case in cases:
        current: Any = case
        for key in path:
            current = _dict(current).get(key, "")
        value = str(current or "")
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def _baseline_summary(cases: list[dict[str, Any]]) -> dict[str, Any]:
    cases_with_observables = 0
    cases_with_indicators = 0
    for case in cases:
        observables = _dict(_dict(case.get("canonical")).get("observables"))
        if any(_list(value) for value in observables.values()):
            cases_with_observables += 1
        indicators = _dict(_dict(case.get("technical_evidence")).get("indicator_values"))
        if indicators:
            cases_with_indicators += 1
    return {
        "human_expected_severity_counts": _count_by(cases, ("human_expected_severity",)),
        "canonical_signal_type_counts": _count_by(cases, ("canonical", "signal_type")),
        "technical_module_counts": _count_by(cases, ("technical_evidence", "module")),
        "cases_with_canonical_observables": cases_with_observables,
        "cases_with_technical_indicators": cases_with_indicators,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=HERE / "corpus.jsonl")
    parser.add_argument("--output", type=Path, default=HERE / "baseline_wazuh_v1.json")
    parser.add_argument("--check", action="store_true", help="Compare output with the existing baseline file.")
    args = parser.parse_args()

    baseline = build_baseline(args.corpus)
    rendered = json.dumps(baseline, ensure_ascii=False, indent=2) + "\n"

    if args.check:
        current = args.output.read_text(encoding="utf-8")
        if current != rendered:
            print(f"baseline drift: {args.output}", file=sys.stderr)
            return 1
        return 0

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered, encoding="utf-8")
    print(f"wrote {args.output} ({len(baseline['cases'])} cases)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
