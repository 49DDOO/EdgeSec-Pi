"""
LLM prompt building and reply parsing.

Three responsibilities, all pure functions:
  • _extract_extra_context — distil Wazuh's structured payload (SCA, CVE,
    FIM, MITRE, GeoIP, macOS rule-510 advisory, org_profile context) into a
    prompt-ready text block.
  • build_prompt — assemble the full Stage-1 prompt including the embedded
    SIEM severity rubric. Returns (prompt, rule_id, level).
  • parse_llm_reply — tolerant JSON extraction (handles markdown fences and
    stray prose) from a possibly-imperfect LLM response.

Extracted from app.py — purely mechanical move. No behavioural change.

The SIEM severity rubric in build_prompt is load-bearing for severity output
quality. Edits here directly shape what every alert looks like in Slack.
"""
from __future__ import annotations

import json
import re
from typing import Any

import org_profile  # for context_for_alert() — business context injection
import siem         # source labels for Wazuh / future SIEM adapters


def _compact_text(value: Any, limit: int) -> str:
    text = " ".join(str(value or "").split())
    return text[:limit]


def _format_prompt_value(value: Any, *, limit: int = 600) -> str:
    """Render structured Wazuh fields without assuming one exact schema."""
    if value in (None, "", [], {}):
        return ""
    if isinstance(value, dict):
        lines = []
        for key, item in value.items():
            rendered = _format_prompt_value(item, limit=180)
            if rendered:
                lines.append(f"{key}: {rendered}")
        return "; ".join(lines)[:limit]
    if isinstance(value, list):
        parts = []
        for item in value:
            rendered = _format_prompt_value(item, limit=220)
            if rendered:
                parts.append(rendered)
        return " | ".join(parts)[:limit]
    return _compact_text(value, limit)


def _severity_rubric(source: str, source_name: str) -> str:
    if source == "wazuh":
        return """Severity rubric — ANCHORED to Wazuh's own level classification.
Source: https://documentation.wazuh.com/current/user-manual/ruleset/rules/rules-classification.html
Wazuh levels are 0..15 (NOT 0..16). Map level → severity as follows:

  Wazuh level 15  →  critical    (Wazuh: "Severe attack. No chance of false positive.
                                          Immediate attention is necessary.")
  Wazuh level 14  →  critical or high   (Wazuh: "High importance security event,
                                                 done with correlation, indicates an attack.")
                       Pick critical when raw_log/description shows active compromise
                       (RCE in progress, data exfiltration, /etc/shadow tampering,
                       confirmed credential theft). Otherwise high.
  Wazuh level 13  →  high (default) or critical
                       (Wazuh: "Unusual error - most of the times matches a common
                                attack pattern.")
                       Pick critical only with strong corroboration (MITRE technique
                       mapped to a destructive tactic, GeoIP flags hostile origin,
                       correlation shows 3+ rules from same actor).
  Wazuh level 12  →  high or medium
                       (Wazuh: "High importance event - error or warning from system
                                or kernel, may indicate attack against an application.")
                       Pick high when raw_log/description identifies a named attack
                       (rootkit, FIM tampering, suspicious binary). Otherwise medium.
  Wazuh level 11  →  high or medium
                       (Wazuh: "Integrity checking warning - modification of binaries
                                or presence of rootkits. May indicate a successful
                                attack.")
                       Pick high when integrity violation affects security-relevant
                       paths (/etc/shadow, /etc/sudoers, /bin, /sbin, system binaries
                       on Windows). Otherwise medium.
  Wazuh level 10  →  medium or high
                       (Wazuh: "Multiple user generated errors - multiple bad
                                passwords, multiple failed logins. MAY indicate an
                                attack or may just be a user who forgot credentials.")
                       Pick high only when corroborated (Tor exit / hostile GeoIP /
                       known bad srcip / correlation shows lateral movement).
                       Default to medium when in doubt — Wazuh itself flags this as
                       ambiguous.
  Wazuh level 8–9  →  medium or low
                       (Wazuh 8: "First time seen". Wazuh 9: "Error from invalid
                                  source - login as unknown user, may have security
                                  relevance.")
                       Pick medium if enriched context upgrades the signal.
                       Otherwise low.
  Wazuh level 6–7  →  low or info
                       (Wazuh 6: "Low relevance attack - worm/virus with no system
                                  effect." Wazuh 7: "Bad word matching - mostly
                                  unclassified, may have some security relevance.")
                       Pick low if any attacker behaviour is concrete. Default info.
  Wazuh level 0–5  →  info
                       (Wazuh 0/2: "No security relevance." Wazuh 3: "Successful
                                    or authorized events." Wazuh 4: "Bad config /
                                    test devices." Wazuh 5: "User generated error -
                                    by themselves no security relevance.")
                       These are operational noise. Severity MUST be info."""

    return f"""Severity rubric — ANCHORED to the normalized {source_name} event.
EdgeSec-Pi maps non-Wazuh vendor severity into a 0..15 normalized level so the
LLM sees one stable contract across SIEMs:

  normalized level 15       → critical
  normalized level 11–14    → high, unless evidence shows only policy noise
  normalized level 8–10     → medium, unless correlation confirms compromise
  normalized level 6–7      → low
  normalized level 0–5      → info

Use the vendor message, rule name, raw_log, MITRE tags, IOC fields, and
correlation context to adjust by one tier when justified. Do not inflate
compliance-only or policy-only events unless the raw evidence shows an attack."""


def _extract_extra_context(alert: dict[str, Any]) -> str:
    """Pull alert-type-specific hints out of Wazuh's structured payload so
    Gemma can give concrete remediation, not generic "contact IT" advice.

    Wazuh's SCA / vulnerability / FIM decoders attach rich data Gemma can't
    see from rule.description + full_log alone. We surface it here.
    """
    extras: list[str] = []
    data = alert.get("data") or {}

    # Phase 4 — Business context from org_profile.yaml. Goes FIRST because
    # the LLM should weigh asset criticality / off-hours / user anomaly
    # before applying the static Wazuh-level rubric.
    if biz := org_profile.context_for_alert(alert):
        extras.append(biz)

    # CIS / SCA compliance check — has authoritative remediation steps
    sca_check = ((data.get("sca") or {}).get("check") or {})
    if sca_check:
        rationale   = _compact_text(sca_check.get("rationale"), 700)
        remediation = _compact_text(sca_check.get("remediation"), 1200)
        result      = _compact_text(sca_check.get("result"), 120)
        title       = _compact_text(sca_check.get("title"), 240)
        description = _compact_text(sca_check.get("description"), 700)
        condition   = _compact_text(sca_check.get("condition"), 160)
        checks      = _format_prompt_value(
            sca_check.get("checks")
            or sca_check.get("rules")
            or sca_check.get("check")
            or sca_check.get("commands"),
            limit=900,
        )
        compliance  = _format_prompt_value(
            sca_check.get("compliance")
            or sca_check.get("compliance_refs")
            or sca_check.get("requirements"),
            limit=700,
        )
        optional_lines = []
        if description:
            optional_lines.append(f"  Description: {description}")
        if condition:
            optional_lines.append(f"  Checks condition: {condition}")
        if checks:
            optional_lines.append(f"  Checks:      {checks}")
        if compliance:
            optional_lines.append(f"  Compliance:  {compliance}")
        extras.append(
            "ALERT TYPE: CIS / SCA compliance baseline check.\n"
            "This is a *configuration posture* finding, not an active attack. "
            "Tone the urgency down accordingly. Do NOT say things like 'isolate the host' "
            "or 'block IP'.\n"
            f"  Check:       {title}\n"
            f"  Result:      {result}\n"
            + ("\n".join(optional_lines) + "\n" if optional_lines else "")
            + f"  Why:         {rationale}\n"
            f"  Official remediation (translate this into Traditional Chinese in next_step_zh — "
            f"if it's a CLI command, give the actual command; if it's a System Settings path, "
            f"name the exact menu items; if it's an MDM profile, say so):\n"
            f"      {remediation}"
        )

    # Vulnerability detector — has CVE id and CVSS
    vuln = data.get("vulnerability") or {}
    if vuln:
        extras.append(
            "ALERT TYPE: vulnerability detection.\n"
            f"  CVE:        {vuln.get('cve','?')}\n"
            f"  CVSS:       {vuln.get('cvss3', vuln.get('cvss2', '?'))}\n"
            f"  Package:    {vuln.get('package',{}).get('name','?')} "
            f"{vuln.get('package',{}).get('version','')}\n"
            f"  Reference:  {vuln.get('reference','')[:200]}\n"
            "When writing next_step_zh, give the specific upgrade command "
            "(brew upgrade / apt upgrade / yum update / Microsoft Update etc.) "
            "matching the package's package manager."
        )

    # File Integrity Monitoring — has changed file path + who changed it
    syscheck = data.get("syscheck") or {}
    if syscheck.get("path"):
        audit = syscheck.get("audit") or {}
        extras.append(
            "ALERT TYPE: file integrity (FIM) change.\n"
            f"  Path:           {syscheck.get('path','?')}\n"
            f"  Event:          {syscheck.get('event','?')}\n"
            f"  By process:     {audit.get('process',{}).get('name','?')}\n"
            f"  By user:        {audit.get('user',{}).get('name','?')}\n"
            "Investigate whether this change was intended."
        )

    rule    = alert.get("rule")  or {}
    agent   = alert.get("agent") or {}
    rule_id = str(rule.get("id", ""))

    # MITRE ATT&CK tagging — Wazuh's rule decoder may attach tactic/technique
    # IDs (e.g. T1110 = Brute Force). Surfacing them lets the LLM map the
    # observation onto a known adversary playbook instead of guessing.
    mitre = rule.get("mitre") or {}
    if mitre:
        ids        = mitre.get("id")        or []
        tactics    = mitre.get("tactic")    or []
        techniques = mitre.get("technique") or []
        if ids or tactics or techniques:
            extras.append(
                "MITRE ATT&CK CONTEXT (use this to anchor your analysis — "
                "do NOT invent a different technique):\n"
                f"  Technique IDs: {', '.join(ids) or '—'}\n"
                f"  Tactic(s):     {', '.join(tactics) or '—'}\n"
                f"  Technique(s):  {', '.join(techniques) or '—'}\n"
                "Echo the first technique ID back into the `mitre` output field."
            )

    # GeoIP enrichment — Wazuh's GeoIP integration attaches country/city for
    # source/destination IPs. A failed login from RU/CN/KP vs. the office's
    # own country is a strong signal we want the LLM to weigh.
    src_geo = data.get("srcgeoip") or {}
    dst_geo = data.get("dstgeoip") or {}
    src_ip  = data.get("srcip") or data.get("src_ip") or ""
    dst_ip  = data.get("dstip") or data.get("dst_ip") or ""
    if src_geo or dst_geo:
        lines = ["GEO CONTEXT (source/destination location of the network actor):"]
        if src_geo:
            lines.append(
                f"  Source:      {src_ip or '?'}  →  "
                f"{src_geo.get('country_name','?')} / "
                f"{src_geo.get('city_name','?')} "
                f"(ASN: {src_geo.get('as_organization','?')})"
            )
        if dst_geo:
            lines.append(
                f"  Destination: {dst_ip or '?'}  →  "
                f"{dst_geo.get('country_name','?')} / "
                f"{dst_geo.get('city_name','?')} "
                f"(ASN: {dst_geo.get('as_organization','?')})"
            )
        lines.append(
            "If the source country is far from the business's normal operating "
            "region, or matches well-known threat-actor geographies, raise the "
            "severity one notch and mention the country in summary_zh."
        )
        extras.append("\n".join(lines))

    # Platform-specific false-positive awareness. Wazuh's detection rules are
    # tuned for Linux servers; some checks (notably rootcheck rule 510) are
    # known to fire spuriously on macOS desktops.
    agent_os = str((agent.get("os") or {}).get("platform", "")).lower()
    agent_name = str(agent.get("name", "")).lower()
    looks_like_mac = (
        agent_os == "darwin"
        or "mac" in agent_name
        or any(k in agent_name for k in ("studio", "macbook", "imac"))
    )

    if rule_id == "510" and looks_like_mac:
        extras.append(
            "FALSE-POSITIVE ADVISORY: This is rule 510 (rootcheck 'hidden port') "
            "on a macOS host. Wazuh's rootcheck was designed for Linux /proc; on "
            "Darwin kernel it has a >90% false-positive rate because legitimate "
            "macOS daemons (rapportd, mDNSResponder, identityservicesd, sharingd, "
            "AirPlay receiver, iCloud sync) bind ephemeral UDP ports in ways "
            "rootcheck cannot introspect. Real rootkits also do not typically "
            "use random high ephemeral ports.\n"
            "DO NOT classify this as 'critical'. Severity 'low' or 'info' is "
            "appropriate. In summary_zh, calmly note it is likely a false alarm "
            "from a macOS system daemon. In next_step_zh, suggest the user run "
            "`sudo lsof -i UDP:<port>` to identify the actual owning process "
            "before any drastic action like network isolation."
        )

    return ("\n\n" + "\n\n".join(extras)) if extras else ""


def build_prompt(alert: dict[str, Any]) -> tuple[str, str, Any]:
    """Extract the alert fields and format a structured-output prompt.

    Two design choices:

    1. Embedded severity rubric. Without an explicit 5-tier definition the
       model invents its own (usually high/medium/low) and never produces
       `critical` or `info`. The rubric below pins the vocabulary down.

    2. Forced JSON output via prompt instruction (LM Studio rejects the
       response_format JSON-mode flag for some models, see comment in
       analyze()).

    The leading `/no_think` is a Qwen3 control token; harmless on other models.
    """
    rule        = alert.get("rule") or {}
    description = rule.get("description", "<no description>")
    rule_id     = rule.get("id", "?")
    level       = rule.get("level", "?")
    full_log    = alert.get("full_log", "<no log>")
    meta        = alert.get("_edgesec") or {}
    source      = str(meta.get("siem_source") or "wazuh")
    source_name = str(meta.get("siem_product") or siem.source_label(source))
    rubric      = _severity_rubric(source, source_name)
    extras      = _extract_extra_context(alert)
    # mcp_enrichment is filled in async by analyze() → passed via the
    # alert dict's "_mcp_enrichment" key (a hack but avoids making
    # build_prompt async; analyze() always sets it before calling here).
    if mcp_chunk := alert.get("_mcp_enrichment"):
        extras += "\n\n" + mcp_chunk
    # Correlation context (same pattern) — recent alerts that share the
    # current alert's source IP or agent. Lets the LLM spot a multi-stage
    # attack instead of treating each alert as an isolated event.
    if corr_chunk := alert.get("_correlation_context"):
        extras += "\n\n" + corr_chunk

    prompt = f"""/no_think
You are a SOC analyst at a Taiwanese SMB. Your output is consumed by TWO audiences in the same JSON:
  (A) the non-technical business owner (reads Traditional Chinese, no jargon, just plain language)
  (B) the IT administrator (reads English, wants concise technical detail)

Output JSON only — no prose, no markdown fences, no commentary.

{rubric}

Hard overrides (apply AFTER the level mapping above):
  • If MITRE / GeoIP / correlation context explicitly flags an in-progress
    compromise, raise severity by one tier — but never above critical.
  • If a false-positive advisory is present in the extras (e.g. macOS rule 510),
    cap severity at low.
  • If rule.description says "PCI_DSS:" or other compliance prefix and the raw_log
    does not show an attack, treat as the BASELINE level mapping above — do not
    inflate just because it touches regulated data.

Business-owner wording rules:
  • summary_zh must name the affected computer/agent and, when BUSINESS CONTEXT
    is present, include the asset role in plain Chinese.
  • next_step_zh should say who should confirm or fix it when the business
    context identifies an owner or responsible role.
  • Do not start the owner-facing fields with CIS, rule names, MITRE, Wazuh
    rule IDs, or benchmark titles. Those belong in technical fields only.

{source_name} alert:
  rule_id: {rule_id}
  rule_level: {level}
  description: {description}
  raw_log: {full_log}{extras}

Output JSON with exactly these fields:
{{
  "severity": "critical|high|medium|low|info",

  "summary_zh":   "用一句白話繁體中文告訴非技術主管「哪台電腦發生什麼事」。若 BUSINESS CONTEXT 有 Asset role/owner/notes，請納入用途或負責人。避免英文與技術詞 (rule, CIS, benchmark, brute force, SSH, RCE, payload 等)。例：『會計電腦有多次登入失敗，請確認是不是本人操作』",
  "impact_zh":    "用一句白話繁體中文告訴主管「不處理會怎樣」。例：『若對方猜中密碼，可能進入系統竊取或破壞資料、安裝後門』",
  "next_step_zh": "用一句白話繁體中文告訴主管「現在立刻可以做什麼」。若有 owner/role，請指名負責人或該角色確認。避免叫主管自己 ssh、改 config；應該是給 IT 或負責人的明確指令，主管轉達就好。例：『請會計負責人確認是否本人操作；若不是，請 IT 暫時封鎖來源並回報結果』",

  "root_cause":   "<technical English, one sentence — for IT staff>",
  "iocs":         ["<IPs, files, users, hashes, domains — [] if none>"],
  "action":       "<technical English remediation steps, one sentence — for IT staff>",
  "mitre":        "<MITRE ATT&CK id like T1110, or null>",

  "needs_investigation": "<bool — true ONLY if you cannot confidently triage from this single alert and would benefit from querying SIEM history / agent state / vuln data via tools. Default to false. Set true for: brute-force / lateral-movement / suspected-compromise / rootkit / FIM tampering / unknown-process / CVE-being-exploited signals — anything where the 'is this a real campaign?' answer changes if we see 7d of history. Set false for: known-benign rule misfires, single low-severity policy violations, SCA baseline checks, FP-prone macOS rootcheck.>",
  "investigation_reason": "<one short English sentence — what specifically you want to look up. Empty string when needs_investigation=false.>"
}}"""
    return prompt, rule_id, level


def parse_llm_reply(text: str) -> dict | None:
    """Tolerantly extract a JSON object from an LLM reply.

    The LLM is asked for pure JSON but may add markdown fences or stray
    prose. We try strict parse first, then fall back to grabbing the
    largest balanced {…} substring.
    """
    if not text:
        return None
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
