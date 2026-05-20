"""
EdgeSec-Pi LLM eval harness
===========================

Reads `corpus.jsonl` (one Wazuh alert + expected labels per line),
runs each alert through the bridge's `build_prompt()`, sends it to a
configurable LLM endpoint, and scores the response.

Usage:
  python eval.py --mode mock                  # canned responses, no network
  python eval.py --mode live                  # POST to LM_STUDIO_URL
  python eval.py --mode offline               # just dump prompts
  python eval.py --mode live --output report.md
  python eval.py --mode live --limit 5

Scoring:
  • severity_match  — does the response mention a severity word
                       matching the human label? (critical/high/medium/low/info)
  • keyword_recall  — fraction of expected keywords found in the response
                       (case-insensitive substring match)
  • latency_ms      — wall time per LLM call

Outputs a Markdown report with a summary table + per-case detail.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

# Import build_prompt from the bridge — keeps this in sync with prod.
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from prompting import build_prompt  # noqa: E402

import httpx  # noqa: E402

LM_STUDIO_URL = os.getenv("LM_STUDIO_URL", "http://localhost:1234/v1/chat/completions")
LM_MODEL      = os.getenv("LM_MODEL", "local-model")
LM_TIMEOUT_S  = float(os.getenv("LM_TIMEOUT_S", "60"))

SEVERITIES = ["critical", "high", "medium", "low", "info"]


# ──────────────────────────────────────────────────────────────────────────
@dataclass
class Result:
    case_id: str
    expected_severity: str
    expected_keywords: list[str]
    response: str
    latency_ms: int
    error: str | None = None

    # derived
    detected_severity: str = ""
    severity_match: bool = False
    keyword_hits: list[str] = field(default_factory=list)
    keyword_recall: float = 0.0


def _try_parse_json(text: str) -> dict | None:
    """Parse a JSON object from text. Tolerates leading/trailing prose
    or markdown fences in case the model didn't fully obey the schema."""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            return None
    return None


def grade(r: Result) -> Result:
    """Grade a response. Prefers JSON parsing (precise); falls back to
    free-text regex if the model failed to produce JSON (so weaker models
    still get a score instead of a hard error)."""
    parsed = _try_parse_json(r.response)
    if parsed and "severity" in parsed:
        # JSON path — read severity directly, search the text fields for keywords.
        r.detected_severity = str(parsed.get("severity", "")).lower().strip()
        searchable = " ".join(str(x) for x in [
            parsed.get("root_cause", ""),
            parsed.get("action", ""),
            *(parsed.get("iocs") or []),
            parsed.get("mitre", ""),
        ]).lower()
    else:
        # Fallback path — old behaviour, grep severity words in highest-first order.
        text = r.response.lower()
        for s in SEVERITIES:
            if s in text:
                r.detected_severity = s
                break
        searchable = text

    r.severity_match = (r.detected_severity == r.expected_severity)
    r.keyword_hits = [k for k in r.expected_keywords if k.lower() in searchable]
    r.keyword_recall = (
        len(r.keyword_hits) / len(r.expected_keywords)
        if r.expected_keywords else 1.0
    )
    return r


# ──────────────────────────────────────────────────────────────────────────
# LLM transports
# ──────────────────────────────────────────────────────────────────────────
def call_live(prompt: str) -> tuple[str, int]:
    payload = {
        "model": LM_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.1,
        "stream": False,
        # response_format omitted on purpose — LM Studio 0.3.x rejects
        # `json_object` with 400. Prompt-only JSON works fine on Qwen3.
    }
    t0 = time.perf_counter()
    with httpx.Client(timeout=LM_TIMEOUT_S) as c:
        r = c.post(LM_STUDIO_URL, json=payload)
        r.raise_for_status()
        text = r.json()["choices"][0]["message"]["content"].strip()
    return text, int((time.perf_counter() - t0) * 1000)


def call_mock(case_id: str, expected_severity: str, expected_keywords: list[str]) -> tuple[str, int]:
    """Deterministic fake LLM. Returns a JSON triage that hits the expected
    keywords, so you can see what a 'good' structured report looks like."""
    obj = {
        "severity": expected_severity,
        "root_cause": f"Mock triage for {case_id}.",
        "iocs": list(expected_keywords),
        "action": f"Investigate; mention {', '.join(expected_keywords)}.",
        "mitre": None,
    }
    return json.dumps(obj), 12


# ──────────────────────────────────────────────────────────────────────────
def run(corpus_path: Path, mode: str, limit: int | None) -> list[Result]:
    results: list[Result] = []
    with corpus_path.open() as f:
        cases = [json.loads(line) for line in f if line.strip()]
    if limit:
        cases = cases[:limit]

    for case in cases:
        cid       = case["id"]
        alert     = case["alert"]
        exp       = case["expected"]
        prompt, _, _ = build_prompt(alert)

        try:
            if mode == "offline":
                response, ms = "(offline — prompt only)", 0
            elif mode == "mock":
                response, ms = call_mock(cid, exp["severity"], exp["keywords"])
            elif mode == "live":
                response, ms = call_live(prompt)
            else:
                raise ValueError(mode)
            err = None
        except Exception as e:
            response, ms, err = "", 0, repr(e)

        r = Result(
            case_id=cid,
            expected_severity=exp["severity"],
            expected_keywords=list(exp["keywords"]),
            response=response,
            latency_ms=ms,
            error=err,
        )
        if mode != "offline" and not err:
            grade(r)
        results.append(r)
        status = "·" if not err else "✗"
        print(f"  {status} {cid:40s}  {ms:>5} ms  sev={r.detected_severity or '-':8s}  recall={r.keyword_recall:.0%}")
    return results


def report(results: list[Result], mode: str, prompts: dict[str, str]) -> str:
    if mode == "offline":
        # Just dump prompts.
        lines = ["# EdgeSec-Pi eval — offline prompt dump\n"]
        for cid, p in prompts.items():
            lines += [f"## {cid}\n", "```", p, "```", ""]
        return "\n".join(lines)

    n = len(results)
    sev_hits = sum(1 for r in results if r.severity_match)
    avg_recall = sum(r.keyword_recall for r in results) / n if n else 0
    avg_lat = sum(r.latency_ms for r in results) / n if n else 0
    errs = sum(1 for r in results if r.error)

    out = []
    out += [
        f"# EdgeSec-Pi eval — `{mode}` mode\n",
        f"- Cases: **{n}** (errors: {errs})",
        f"- Severity match: **{sev_hits}/{n} ({sev_hits/n:.0%})**",
        f"- Avg keyword recall: **{avg_recall:.0%}**",
        f"- Avg latency: **{avg_lat:.0f} ms**",
        "",
        "## Summary",
        "",
        "| ID | Expected | Detected | Sev✓ | Recall | Latency |",
        "|----|----------|----------|:----:|:------:|--------:|",
    ]
    for r in results:
        ok = "✅" if r.severity_match else "❌"
        rec = f"{r.keyword_recall:.0%}"
        out.append(
            f"| `{r.case_id}` | {r.expected_severity} | {r.detected_severity or '—'} | {ok} | {rec} | {r.latency_ms} ms |"
        )
    out.append("")
    out.append("## Per-case detail")
    out.append("")
    for r in results:
        out += [
            f"### `{r.case_id}`",
            f"- expected severity: `{r.expected_severity}` · detected: `{r.detected_severity or '—'}`",
            f"- expected keywords: {', '.join(f'`{k}`' for k in r.expected_keywords)}",
            f"- hit: {', '.join(f'`{k}`' for k in r.keyword_hits) or '—'}",
        ]
        if r.error:
            out.append(f"- **error**: `{r.error}`")
        out += ["", "**Response:**", "", "```", r.response or "(empty)", "```", ""]
    return "\n".join(out)


# ──────────────────────────────────────────────────────────────────────────
def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mode", choices=["offline", "mock", "live"], default="mock")
    p.add_argument("--corpus", type=Path, default=HERE / "corpus.jsonl")
    p.add_argument("--output", type=Path, default=HERE / "report.md")
    p.add_argument("--limit", type=int, default=None)
    args = p.parse_args()

    print(f"running mode={args.mode} corpus={args.corpus}")
    results = run(args.corpus, args.mode, args.limit)

    # Always also collect prompts for offline mode.
    prompts: dict[str, str] = {}
    if args.mode == "offline":
        for line in args.corpus.open():
            case = json.loads(line)
            prompts[case["id"]], _, _ = build_prompt(case["alert"])

    md = report(results, args.mode, prompts)
    args.output.write_text(md)
    print(f"\nreport → {args.output}")

    if args.mode != "offline":
        n = len(results)
        sev_hits = sum(1 for r in results if r.severity_match)
        ok_pct = sev_hits / n if n else 0
        print(f"summary: severity_match={ok_pct:.0%}  errors={sum(1 for r in results if r.error)}/{n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
