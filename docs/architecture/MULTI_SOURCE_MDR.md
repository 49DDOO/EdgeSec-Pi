# Multi-Source MDR Architecture

Status: proposed direction

EdgeSec-Pi started with Wazuh because Wazuh is a practical first source for SMB
endpoint and server alerts. That should remain the first full reference
implementation. It should not become the product boundary.

The long-term product boundary is:

```text
Security sources -> Canonical signal -> Evidence -> MDR decision -> Response -> Owner/IT workflow
```

In plain terms: Wazuh, Microsoft 365, Google Workspace, firewall logs,
Cloudflare, or an EDR can all become inputs. EdgeSec-Pi's value is the judgment
and workflow layer that turns those inputs into:

- owner-readable Traditional Chinese risk explanation,
- IT-readable evidence and next steps,
- deterministic guardrails,
- human-approved response actions,
- local history and auditability.

## Decision

Do not position the product as "Wazuh + LLM" internally.

Use this framing instead:

> EdgeSec-Pi is a local MDR decision and workflow layer. Wazuh is the first
> source adapter.

This means new backend work should avoid leaking Wazuh-only assumptions into
prompting, Dashboard state, playbooks, response policy, and storage contracts
unless the code is explicitly inside a Wazuh adapter/provider.

## Architectural Roles

### Source Adapter

A source adapter converts vendor-specific alerts into a canonical EdgeSec-Pi
signal.

Examples:

| Source | Adapter responsibility |
|--------|-------------------------|
| Wazuh | Convert Wazuh alert JSON into canonical fields, keep raw alert for forensics. |
| Microsoft 365 | Convert risky sign-in, mailbox rule, OAuth consent, or Defender alert into canonical fields. |
| Google Workspace | Convert login anomaly, admin action, or Gmail security alert into canonical fields. |
| Firewall / Cloudflare / OPNsense | Convert network event, block, C2-like outbound, or scan into canonical fields. |
| EDR | Convert detection/incident into canonical fields and link vendor evidence. |

Source adapters should not decide final business severity. They can provide the
source's native severity as input evidence.

### Canonical Signal

The canonical signal is the minimum common contract consumed by routing,
playbooks, prompts, storage, and Dashboard views.

Proposed shape:

```json
{
  "source": "wazuh",
  "source_event_id": "1730000000.12345",
  "event_time": "2026-05-30T10:14:00Z",
  "received_time": "2026-05-30T10:14:03Z",
  "signal_type": "authentication.bruteforce",
  "title": "SSH brute force",
  "native_severity": "10",
  "asset": {
    "id": "002",
    "name": "web-prod",
    "ip": "192.0.2.10",
    "os": "linux",
    "business_criticality": "critical"
  },
  "actor": {
    "user": "admin",
    "source_ip": "203.0.113.45",
    "source_geo": "",
    "identity_provider": ""
  },
  "target": {
    "user": "admin",
    "destination_ip": "192.0.2.10",
    "service": "ssh"
  },
  "observables": {
    "ips": ["203.0.113.45"],
    "domains": [],
    "hashes": [],
    "files": [],
    "processes": [],
    "commands": []
  },
  "source_context": {
    "rule_id": "5712",
    "rule_groups": ["authentication_failed", "sshd"],
    "mitre": ["T1110"]
  },
  "source_specific": {
    "wazuh": {
      "syscheck": {},
      "sca": {},
      "win": {}
    }
  },
  "raw_ref": {
    "kind": "sqlite_alert_id",
    "id": "123"
  }
}
```

Rules:

- Keep `raw_ref` or raw payload for forensics, but prompts should consume a
  sanitized canonical view.
- Treat `observables`, usernames, command lines, file paths, HTTP headers, and
  raw logs as untrusted data.
- Preserve source-native IDs and severity, but do not let vendor severity become
  the final incident risk by itself.
- Allow sparse fields. A firewall alert may have no username; a SaaS login alert
  may have no endpoint process.
- Keep source-specific structured context under `source_specific` so canonical
  does not collapse every vendor into the smallest common denominator. This is
  where Wazuh FIM/SCA details, Elastic process trees, or M365 sign-in risk
  fields can survive without becoming required fields for every source.

### Evidence Provider

An evidence provider answers bounded questions about history or context.

Examples:

| Provider | Example questions |
|----------|-------------------|
| Wazuh MCP | "Did this IP hit other agents in 7 days?" |
| Wazuh Indexer | "Show recent FIM/SCA/Sysmon events for this agent." |
| Microsoft 365 | "Did this user have impossible travel or risky sign-ins?" |
| Google Workspace | "Was there a suspicious admin action or mailbox forwarding rule?" |
| Firewall / Cloudflare | "Did this asset connect to this IP/domain?" |
| Asset inventory | "Is this endpoint critical or owned by finance?" |

Evidence providers must be read-only by default. They should return structured
evidence, negative findings, and unknown/error states. They should not produce
final owner-facing conclusions.

### MDR Decision Layer

The MDR decision layer combines:

- deterministic guardrails,
- source-neutral playbooks,
- evidence provider results,
- local business context,
- LLM explanation.

The LLM should explain and summarize. It should not be the sole authority for:

- destructive actions,
- "safe to ignore" decisions,
- final escalation when deterministic high-risk evidence exists.

Example rule:

```text
failed login burst + later successful login for same user/source/asset -> high risk
```

That rule should be deterministic. The LLM can explain why it matters.

### Response Provider

A response provider executes an approved action.

Examples:

| Provider | Actions |
|----------|---------|
| Wazuh Active Response | block IP, unblock IP, isolate endpoint, release endpoint |
| Firewall / Cloudflare | block IP, unblock IP, add temporary rule |
| EDR | isolate endpoint, release endpoint |
| Microsoft 365 | disable user, revoke sessions, reset password, quarantine message |
| Ticketing / Slack | assign task, request approval, handoff to IT |

Response providers must be separate from source adapters. A Wazuh alert may lead
to a firewall block. A Microsoft 365 alert may lead to an IT ticket only. Do not
assume "source = response executor".

Destructive response requirements:

- human approval,
- explicit token or session authorization,
- target re-validation at execution time,
- allowlist/denylist policy,
- TTL or rollback path when technically possible,
- audit row,
- visible failure state.

## Source-Neutral Playbook Examples

### Authentication Attack

Inputs:

- source IP,
- target user,
- target asset or SaaS account,
- failed/successful login counts,
- time window.

Evidence:

- prior failures across assets/accounts,
- successful login after failures,
- risky geography or ASN,
- related MFA failures,
- whether the user/asset is business-critical.

Possible responses:

- monitor only,
- ask IT to reset password,
- revoke sessions,
- block IP at firewall/Wazuh,
- isolate endpoint only if endpoint compromise evidence exists.

### Suspicious File or Process

Inputs:

- file path,
- hash,
- process name,
- command line,
- asset.

Evidence:

- hash reputation,
- FIM history,
- process ancestry from EDR/Sysmon,
- whether path is startup/persistence-related,
- whether similar event appears on other endpoints.

Possible responses:

- ask IT to collect sample,
- isolate endpoint,
- kill process through EDR,
- mark benign with scoped suppression.

### Risky SaaS Account Event

Inputs:

- identity,
- SaaS provider,
- login location,
- OAuth app,
- admin action,
- mailbox rule.

Evidence:

- recent successful/risky sign-ins,
- MFA status,
- impossible travel,
- mailbox forwarding,
- new OAuth consent,
- business role of account.

Possible responses:

- revoke sessions,
- disable account,
- remove mailbox rule,
- require password reset,
- create ticket.

## Dashboard Contract

The Dashboard should prefer source-neutral concepts:

- incident / signal,
- affected asset,
- affected user,
- source,
- evidence,
- business impact,
- recommended next step,
- allowed actions,
- action status.

It should not need to know whether a question is answered through Wazuh MCP,
Microsoft Graph, a firewall API, or a future EDR API. The bridge should expose
the normalized answer and evidence.

Allowed source-specific UI:

- badges such as `Wazuh`, `M365`, `Firewall`,
- raw-event drawer for IT,
- source deep link.

Avoid source-specific primary workflows such as "Wazuh-only incident status" or
"Wazuh-only evidence fields" in owner-facing screens.

## Storage Direction

The current SQLite `alerts` table can remain as the Wazuh-backed pilot store.
The next schema direction should add source-neutral records rather than forcing
all future sources into Wazuh fields.

Proposed future tables:

```text
signals
  id
  source
  source_event_id
  event_time
  received_time
  signal_type
  title
  canonical_json
  raw_json
  case_status

evidence_items
  id
  signal_id
  provider
  evidence_type
  status        -- positive | negative | unknown | error
  summary_zh
  data_json

response_actions
  id
  signal_id
  provider
  action
  target_json
  status
  expires_at
  details_json
```

Migration rule: add the canonical layer beside the current Wazuh alert flow
first. Do not rewrite the working Wazuh pipeline until the new contract has test
coverage.

## Naming Guidance

Use source-neutral names in new shared code:

- `signal`, not always `alert` when it may come from SaaS/cloud.
- `source_adapter`, not `wazuh_parser`.
- `evidence_provider`, not `mcp_client` for shared interfaces.
- `response_provider`, not `active_response` for shared interfaces.
- `asset`, `identity`, `observable`, `incident_risk`.

Keep Wazuh-specific names inside Wazuh-specific modules.

## Recommended Roadmap

### Step 1: Define Canonical Signal Without Rewriting Everything

Status: started.

- Add a small adapter around Wazuh alerts that emits `CanonicalSignal`.
- Keep current `alerts` table and Dashboard behavior.
- Add tests that verify SSH brute force, FIM, SCA, Windows, and Sysmon-like
  Wazuh alerts map correctly.

Current implementation foothold:

- `wazuh-llm-bridge/siem.py` normalizes incoming vendor payloads into the
  existing internal alert shape. This is deliberately a compatibility bridge,
  not the final neutral core model: non-Wazuh events still get translated into
  the current `rule`/`agent`/`data`/`full_log` envelope until downstream
  prompting, evidence, and Dashboard flows consume `CanonicalSignal` directly.
- `wazuh-llm-bridge/canonical_signal.py` projects that alert into a
  source-neutral signal with core fields plus a `source_specific` preservation
  area. Wazuh FIM/SCA details and non-Wazuh process/identity context are kept
  here during Phase 1.
- `alerts.canonical_signal` stores this projection beside the existing
  Wazuh-first `raw_alert` payload.
- Deterministic tests now lock the payload-to-canonical layer for Wazuh SSH,
  Wazuh FIM, Wazuh SCA, Splunk authentication, Elastic process, and Microsoft
  365 risky sign-in samples. These tests intentionally assert canonical facts,
  not exact LLM prose.
- `wazuh-llm-bridge/eval/baseline.py` and
  `wazuh-llm-bridge/eval/baseline_wazuh_v1.json` lock the current Wazuh eval
  corpus at the deterministic layer. The baseline records canonical facts,
  technical-evidence indicators, module classification, source-specific
  preservation keys, and human severity labels. It does not lock LLM free-form
  output. Run `python eval/baseline.py --check` before moving prompt or
  evidence readers onto canonical fields.
- `wazuh-llm-bridge/prompting.py` now uses the canonical signal as the primary
  Stage-1 prompt contract. Source-native `rule.description` and `full_log` are
  kept only as untrusted fallback evidence blocks. Wazuh SCA/CVE/FIM/GeoIP
  details still appear as source-specific extras when present.
- `wazuh-llm-bridge/canonical_context.py` is the shared reader for canonical
  signal facts from either a raw alert or an alert DB row. Prompting,
  technical evidence, and investigation context should use it instead of
  reparsing `alerts.canonical_signal` independently.
- `wazuh-llm-bridge/technical_evidence.py` now includes a `canonical` evidence
  summary and uses canonical fallback values for non-Wazuh or sparse alerts.
  Existing Wazuh-specific extraction remains in place so current Dashboard
  evidence does not regress while the UI catches up.
- Dashboard investigation context and fast playbook routing now use canonical
  facts first (`actor.source_ip`, `asset`, `source_context`, `observables`).
  Wazuh MCP remains the current evidence provider, so non-Wazuh events can be
  explained from canonical facts but deep historical lookup still depends on
  adding non-Wazuh evidence providers.
- `wazuh-llm-bridge/source_settings.py` and
  `GET /api/dashboard/sources` expose source readiness to the Dashboard without
  pretending planned sources are already connected.
- `dashboard/src/app/settings/sources` shows Wazuh as the active configurable
  pioneer source and future sources as planned placeholders. The card separates
  source capabilities from controlled response capabilities so Wazuh can be the
  SMB go-to-market source without becoming a permanent architecture assumption.
- Source records expose a `setup_href`. `/settings/setup` starts by choosing a
  source, then renders that source's onboarding checklist before global AI,
  notification, and end-to-end test readiness. Today only Wazuh has a live setup
  path; future sources should add their own checklist instead of adding
  Wazuh-only steps to the global flow.

Operational rule: use explicit `/webhook/{source}` for production non-Wazuh
integrations. Auto-detection on `/webhook` is compatibility behavior for
existing Wazuh and simple test payloads, not a strong source-authentication
signal.

### Step 2: Move Prompt and Playbook Inputs to Canonical Signal

Status: mostly complete for prompt inputs. Stage-1 prompt, automated MCP
investigation prompt, Dashboard investigation context, fast playbook routing,
and technical evidence all read canonical facts first. The remaining work is
provider extraction: Wazuh MCP is still the only deep evidence provider, so
non-Wazuh sources need their own evidence-provider implementations before
historical investigation quality is equivalent.

- Keep `baseline_wazuh_v1.json` green first. If the canonical migration
  intentionally improves deterministic extraction, regenerate the baseline in
  the same change and explain the difference.
- Let prompts consume canonical facts.
- Keep raw Wazuh alert data available as untrusted evidence, not as the main
  prompt contract.
- Keep deterministic guardrails source-neutral where possible.

### Step 3: Extract Evidence Provider Interface

- Wrap Wazuh MCP behind an `EvidenceProvider` shape.
- Preserve the existing fast playbooks.
- Add negative/unknown/error evidence states as first-class outputs.

### Step 4: Add One Non-Wazuh Source

Recommended first non-Wazuh source for SMB value:

1. Microsoft 365 or Google Workspace identity events.
2. Firewall / Cloudflare network events.

Do not add many sources at once. The goal is to prove the abstraction with one
high-value source.

### Step 5: Extract Response Provider Interface

- Keep Wazuh Active Response as the first implementation.
- Make future actions source-neutral: `block_ip`, `isolate_asset`,
  `disable_identity`, `revoke_sessions`, `create_ticket`.
- Keep safety checks and approval flow shared.

## Non-Goals

- Do not build a generic SIEM.
- Do not replace Wazuh detection.
- Do not recreate a commercial EDR isolation product.
- Do not let the LLM choose arbitrary tools or actions without playbook bounds.
- Do not make the Dashboard depend on vendor-specific raw schemas for core
  workflows.

## Current Implication

For the current Wazuh-first codebase, the most important near-term discipline is
to stop introducing new shared concepts with Wazuh-only names. Wazuh-specific
code is fine inside the Wazuh adapter/provider boundary. Prompting, playbooks,
case status, evidence, and response approval should move toward canonical
language.
