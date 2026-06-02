# Current Architecture

Status: current Wazuh-first architecture

This document describes the architecture EdgeSec-Pi should keep clean today.
The future multi-source direction is documented separately in
[MULTI_SOURCE_MDR.md](MULTI_SOURCE_MDR.md). Do not use that future direction as
an excuse to blur today's boundaries.

## Product Boundary

Current EdgeSec-Pi is:

```text
Wazuh alert source
  -> EdgeSec-Pi bridge decision layer
  -> local LLM explanation
  -> Dashboard / notification workflow
  -> optional human-approved response
```

Wazuh is the current detection source of truth. EdgeSec-Pi owns:

- alert intake and back-pressure,
- prompt construction,
- deterministic guardrails,
- MCP evidence routing,
- case status and suppression lifecycle,
- owner-facing Traditional Chinese explanation,
- response approval and safety policy.

EdgeSec-Pi does **not** own:

- Wazuh rule authoring as a replacement for Wazuh,
- autonomous remediation,
- endpoint isolation correctness before real-machine verification,
- final security authority through LLM output alone.

## Non-Negotiable Boundaries

### Dashboard Is A Thin UI

The Dashboard may:

- show current risk, alerts, evidence, endpoints, settings, and action state,
- send `alert_id`, case updates, user questions, and settings to the bridge,
- render returned evidence and owner-facing text.

The Dashboard must not:

- build LLM prompts,
- call Wazuh, MCP, LM Studio, Slack, or email providers directly,
- hold secrets,
- decide whether a destructive action is safe,
- duplicate backend investigation helper policy.

Shared frontend helpers should live under `dashboard/src/lib` or focused
component folders. Repeated prompt/evidence policy in page components is a
regression.

### Bridge Owns Policy

The bridge is the only place that should decide:

- which alert categories reach the LLM,
- whether false-positive suppression applies,
- when MCP evidence is needed,
- how prompts are worded,
- how raw/untrusted fields are isolated,
- whether a response request passes safety checks,
- what readiness status is shown to owners.

### LLM Explains, It Does Not Authorize

The LLM may:

- summarize in Traditional Chinese,
- explain technical evidence,
- suggest next steps,
- help format owner/IT handoff text.

The LLM must not be the sole authority for:

- final high-risk escalation when deterministic evidence exists,
- "safe to ignore" decisions,
- blocking IPs,
- isolating endpoints,
- releasing endpoints,
- disabling users or other future destructive actions.

### MCP Is Read-Only Evidence

MCP is an evidence provider. It is not the product core and not an action
executor.

Current MCP use should follow this order:

1. deterministic fast playbook when the question and alert facts are clear,
2. restricted `tool_loop` deep path when the fast playbook cannot answer,
3. bounded fallback if the model or MCP cannot use tools.

Tool results must include positive, negative, unknown, or error evidence where
possible. Negative findings are important evidence, not missing text.

### Active Response Is Controlled Response

Active Response is optional and must stay human-approved.

Required response properties:

- `ACTIVE_RESPONSE_TOKEN` or short-lived remote action token,
- target re-validation at execution time,
- protected CIDR / never-isolate checks,
- TTL or release path when technically possible,
- lifecycle row in SQLite,
- retry or explicit manual-cleanup state,
- visible failure reason for IT.

Endpoint isolation must remain gated by
`ACTIVE_RESPONSE_ISOLATION_VERIFIED_PLATFORMS`. A platform should only be added
after real-machine isolate, release, TTL, reboot/fail-open, and manager
connectivity tests.

## Main Data Flows

### Alert Intake Flow

```text
Wazuh integrator or explicit SIEM source
  -> POST /webhook or /webhook/{source}
  -> siem.normalize_alert
  -> webhook_api validates source/auth
  -> asyncio.Queue returns 202
  -> app.consume worker
  -> db.match_false_positive_suppression
  -> detection_settings.is_enabled_for_alert
  -> triage_router.decide
  -> prompting.build_prompt
  -> LM Studio-compatible chat completion
  -> prompting.parse_llm_reply
  -> optional agent_loop deep investigation
  -> db.save_alert
  -> notification rendering / send
```

Why this shape matters:

- Wazuh integrator must not wait for LLM inference.
- The queue provides back-pressure with `503` instead of memory exhaustion.
- Suppression and category filtering happen before expensive LLM calls.
- Prompt ownership stays in the bridge.

`/webhook/{source}` is the preferred path for non-Wazuh sources because it
avoids weak auto-detection. `/webhook` remains for existing Wazuh integrations
and uses auto-detection only for compatibility. Unknown explicit source keys
must be rejected at the adapter boundary.

Current `siem.normalize_alert` is a compatibility adapter: it translates
non-Wazuh events into the internal Wazuh-shaped alert envelope
(`rule`/`agent`/`data`/`full_log`) so the existing pipeline can process them.
This is not the final neutral internal schema. `canonical_signal.py` is the
source-neutral projection layer. Stage-1 prompting, Dashboard investigation
context, fast playbook routing, automated MCP investigation prompts, and
technical evidence now read canonical facts first. Wazuh MCP is still the only
deep evidence provider.

The Wazuh eval corpus has a deterministic no-LLM baseline at
`wazuh-llm-bridge/eval/baseline_wazuh_v1.json`. It should remain green before
and after canonical prompt/evidence migration. The baseline locks structured
facts and evidence indicators, not owner-facing LLM prose.

### Dashboard Investigation Flow

```text
Dashboard alert UI
  -> POST /api/dashboard/investigation/chat
  -> ops_api
  -> investigation_chat.answer_for_alert
  -> investigation_playbooks.try_fast_alert_playbook
  -> optional tool_loop.run_tool_loop
  -> investigation_suggestions guardrails
  -> answer_zh + evidence + suggestions
```

Rules:

- The frontend sends alert context and question, not a hand-built LLM prompt.
- The bridge decides which tool, evidence, prompt, and guardrail apply.
- The same shared `tool_loop.py` serves automated deep investigation and
  Dashboard investigation.

### False-Positive Suppression Flow

```text
User marks alert false_positive
  -> db._create_false_positive_suppression_from_row
  -> false_positive_suppressions row
  -> future matching alert
  -> db.match_false_positive_suppression
  -> save skipped/normal case without LLM call
```

This is intentionally powerful because it can suppress repeated noise and skip
LLM spend. It must remain:

- scoped by rule/agent/source IP where available,
- time-bounded,
- visible in Dashboard,
- removable,
- tested.

### Setup Readiness Flow

```text
Dashboard /settings/setup
  -> choose source from GET /api/dashboard/sources
  -> route to source-specific setup href
  -> fetchServiceStatus
  -> GET /api/dashboard/service-status
  -> self_test.run_self_test
  -> setup-flow.ts maps checks into source-specific and global owner steps
```

Important checks:

- `wazuh_api`: Wazuh Manager reachability.
- `alert_flow`: alerts are arriving and being analyzed.
- `wazuh_hardening`: agent-groups exist and online agents have expected OS
  groups.
- `wazuh_module_flow`: recent SQLite history contains module events such as
  FIM/SCA/Sysmon/VT/YARA/Rootcheck/Syscollector.
- `notifications`: at least one channel configured and tested.

First-time setup must start from the source registry. `/settings/setup` should
not assume every deployment is Wazuh-only; it first asks which source is being
enabled, then shows that source's onboarding checklist. Today only Wazuh has a
real `setup_href`, so its source-specific steps cover Manager/Indexer/Webhook,
Agent deployment, agent-groups/module event flow, and endpoint business
context. AI, notification, and end-to-end test steps remain global war-room
steps.

Do not merge `wazuh_hardening` and `wazuh_module_flow`. Group assignment does
not prove event flow.

### Active Response Lifecycle Flow

```text
Slack/Dashboard action
  -> remote action token / ACTIVE_RESPONSE_TOKEN
  -> active_response_api
  -> active_response_safety validation
  -> wazuh.py dispatch or agent-side script command
  -> active_response_state records block/isolation
  -> active_response_lifecycle sweeper
  -> unblock/release retry or manual cleanup state
```

IP block and endpoint isolation share lifecycle principles, but they are not the
same action. Do not assume a block rollback path proves endpoint isolation is
safe.

## Backend Module Ownership

| Module | Owner boundary |
|--------|----------------|
| `app.py` | Process wiring, queue workers, lifecycle startup/shutdown. No route bloat. |
| `siem.py` | First-stage source adapter that normalizes vendor payloads into the current internal alert shape. |
| `canonical_signal.py` | Source-neutral signal projection used to prepare prompts, playbooks, and storage for future non-Wazuh sources. It is stored in `alerts.canonical_signal`. |
| `canonical_context.py` | Shared canonical-signal reader for raw alerts and DB rows. Use it before falling back to Wazuh-shaped fields. |
| `source_settings.py` | Dashboard-facing source registry. It reports Wazuh as the active source and future sources as planned; it does not ingest data. |
| `webhook_api.py` | Alert intake and webhook auth only. |
| `ops_api.py` | Dashboard facade. It may compose services, but heavy domain logic should move to focused modules. |
| `db.py` | Alert/case/suppression/trend persistence. Do not put vendor API calls here. |
| `detection_settings.py` | Category presets, noisy-category warnings, lightweight skip verdicts. |
| `prompting.py` | Stage-1 prompt ownership and parsing. The prompt uses canonical signal facts first, with raw source-native text quoted as untrusted fallback evidence. |
| `investigation_prompting.py` | MCP investigation prompt/evidence formatting. Current-alert context is canonical first; MCP tool output remains quoted untrusted evidence. |
| `prompt_safety.py` | Untrusted-data instructions and prompt-injection guard text. |
| `triage_router.py` | Deterministic quick/deep routing. |
| `tool_loop.py` | Generic OpenAI-compatible tool-call loop. It should not know Wazuh business policy. |
| `agent_loop.py` | Automated deep investigation. |
| `investigation_chat.py` | Dashboard investigation entry point. Keep it thin; helpers belong in split `investigation_*` modules. |
| `mcp_client.py` | Wazuh MCP HTTP client and formatting helpers. |
| `wazuh.py` | Wazuh Manager API client. |
| `wazuh_hardening.py` | Agent-group verification only. |
| `self_test.py` | Owner-facing service checks. |
| `active_response_api.py` | HTTP endpoints and token gate. |
| `active_response_safety.py` | Policy validation and capability gates. |
| `active_response_state.py` | SQLite lifecycle state and retry metadata. |
| `active_response_lifecycle.py` | Background TTL sweeper. |
| `slack_render.py` | Notification payload rendering. |
| `slack_actions.py` | Slack Socket Mode interactions. |

## Frontend Module Ownership

| Area | Owner boundary |
|------|----------------|
| `src/lib/api.ts` | Sole frontend bridge API client. |
| `src/lib/types.ts` | Shared API response types. |
| `src/lib/setup-flow.ts` | Source-specific and global first-time setup state machine and wording composition. |
| `src/lib/investigation.ts` | Shared alert investigation UI helpers, not prompt policy. |
| `src/components/dashboard/alerts/` | Alert table subcomponents. Keep `alerts-table.tsx` as a coordinator. |
| `src/app/settings/setup` | Entry point for onboarding. It should select a source first, then show source-specific setup plus global war-room readiness. |
| `src/app/settings/sources` | Source registry UI. It reads backend source state, separates data-source capability from controlled response capability, and links to source setup/settings; it must not call vendor APIs directly. |
| `src/app/settings/*` | Page shells that compose API data and components. Avoid domain logic in pages. |

Dashboard owner-facing language should remain source-neutral: use "事件中心",
"證據查詢", "資產 / 端點", "端點部署", "訊號類別", and
"流程測試". Wazuh-specific wording belongs in the Wazuh source details page,
technical evidence, or source-specific troubleshooting text.

Daily Triage should be visually separated from system setup. The top-level
operator path is:

```text
今日待辦
  -> Triage 主控台
  -> high-risk / pending / assigned queues
  -> 事件中心 filtered by URL query
  -> event detail
  -> evidence / decision / status update
```

Settings, source setup, and test tools should remain under system management and
must not be the primary daily path for a triage operator.

## Current Security Invariants

- Raw alert content is untrusted data.
- Severity guardrails must be deterministic where the evidence pattern is known.
- False-positive suppression is auditable and reversible.
- Destructive actions require human approval and backend validation.
- Endpoint isolation requires both isolate and release commands.
- Isolation UI/actions are hidden or denied unless platform capability is
  verified.
- Agent-group green state is not the same as module-event green state.
- Dependency failures should degrade gracefully and give owner/IT next steps.

## What "Clean" Means For This Phase

Clean does not mean no Wazuh-specific code. It means Wazuh-specific code is in
the right place.

Acceptable Wazuh-specific modules:

- `webhook_api.py`
- `siem.py`
- `canonical_signal.py` for source-neutral projection
- `wazuh.py`
- `mcp_client.py`
- `wazuh_hardening.py`
- Wazuh-specific parts of `prompting.py` and `investigation_prompting.py`

Shared or owner-facing areas should avoid new Wazuh-only assumptions:

- Dashboard page state,
- case lifecycle,
- evidence status,
- response approval state,
- setup step semantics,
- prompt safety policy,
- future storage contracts.

## Near-Term Hardening Checklist

Before adding a second source such as Google Workspace, finish these current
architecture items:

1. Keep `ops_api.py` below the point where it becomes another god module. Split
   new large API areas into focused routers.
2. Keep `investigation_chat.py` thin. New helpers should go into
   `investigation_*` modules.
3. Add tests whenever shared policy changes: `tool_loop`, false-positive
   suppression, setup status, prompt ownership, and Active Response lifecycle.
4. Keep Dashboard helpers shared; do not reintroduce duplicate prompt/evidence
   helpers in multiple components.
5. Keep setup wording honest: deployment evidence and event-flow evidence are
   different.
6. Document every destructive action's rollback or manual cleanup behavior.

## Current Status Summary

The current architecture is acceptable for a Wazuh-first pilot if it stays
within these boundaries:

- Bridge is the policy owner.
- Dashboard is a thin workflow UI.
- MCP is read-only evidence.
- LLM explains; deterministic guardrails decide high-risk patterns.
- Active Response is human-approved with lifecycle tracking.
- Wazuh hardening status is honest about what is verified and what is only
  inferred.
