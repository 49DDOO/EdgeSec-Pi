# EdgeSec-Pi Dashboard

This is the management Dashboard for EdgeSec-Pi.

It is a Next.js frontend that talks to the local EdgeSec-Pi bridge API. The
Dashboard is intentionally separate from the bridge service:

- `dashboard/` renders the management UI.
- `wazuh-llm-bridge/` receives SIEM alerts, stores data, enriches alerts, and
  exposes the Dashboard API.

The UI must stay a thin operational surface. It should not build LLM prompts,
call Wazuh/MCP directly, or hold secrets. Prompt construction, evidence policy,
Active Response safety, and external service credentials stay in the bridge.

## Development

From the repository root, start the managed local services:

```bash
./scripts/run.sh restart
```

The Dashboard runs at:

```text
http://127.0.0.1:3000
```

The Dashboard API is proxied through:

```text
/api/dashboard/*
```

By default the proxy points to the local bridge:

```text
https://127.0.0.1:8001
```

## Current Pages

| Route | Purpose |
|-------|---------|
| `/` | Today view: risk summary, open alerts, and action queue. |
| `/investigation` | Global MCP investigation workspace. |
| `/settings/setup` | First-time setup checklist for non-technical owners. |
| `/settings/endpoints` | Endpoint inventory, business context, and agent install guidance. |
| `/settings/sources` | Event-source overview and per-source entry points. |
| `/settings/sources/wazuh` | Wazuh Alert source overview. |
| `/settings/sources/wazuh/detections` | Wazuh-specific detection-category presets, noisy-category warnings, and false-positive suppression visibility. |
| `/settings/ai-model` | AI endpoint/model configuration and tests. |
| `/settings/wazuh` | Wazuh Manager/Indexer connection settings and tests. |
| `/settings/notifications` | LINE/Slack/Telegram/email settings and test sends. |
| `/settings/status` | Service status and self-test detail. |
| `/settings/testing` | Built-in sample/test alert replay. |

## Setup Checklist Contract

The setup checklist is modeled in `src/lib/setup-flow.ts`; do not bury setup
rules inside page components. The checklist currently separates:

- Wazuh API readiness from alert flow readiness.
- Agent online status from endpoint business context.
- `wazuh_hardening` (agent-groups deployed and assigned) from
  `wazuh_module_flow` (recent FIM/SCA/Sysmon/VT/YARA-style events observed).
- Notification configuration from successful notification test.

This distinction matters for security wording. The UI must not imply that
Sysmon/FIM/SCA/VT/YARA are producing data merely because Wazuh agent-groups
exist.

## Investigation Contract

Alert-specific investigation helpers live in `src/lib/investigation.ts` and
component files under `src/components/dashboard/alerts/`. The frontend sends
alert IDs, user questions, and display context to the bridge. The bridge owns
MCP tool selection, prompt wording, untrusted-data isolation, and answer
guardrails.

## UI Design Policy

The Dashboard uses a custom security-operations interface built with
Next.js, Tailwind CSS, shadcn-style components, Base UI primitives, and
Lucide icons. It does not aim to be a full Google Material Design or MUI
implementation.

Google Material Design is used as a reference for consistency, accessibility,
and interaction behavior:

- Keep component states clear: hover, focus, active, loading, disabled, and
  error states must be visible and predictable.
- Use consistent hierarchy for buttons, tabs, dialogs, forms, switches,
  snackbars, tooltips, and navigation.
- Prefer accessible primitives and keyboard-friendly flows for interactive
  controls.
- Keep owner-facing screens decision-oriented: show current risk, required
  approval, business impact, recommended action, and handoff status before
  technical detail.
- Keep IT-facing screens dense enough for investigation: alerts, endpoints,
  MITRE, IOCs, evidence, raw logs, health checks, and test tools belong below
  the owner-facing layer.
- Do not copy Material's visual style wholesale when it weakens the product's
  security-operations identity or reduces information density.

In short: use Material Design as a design-quality benchmark, not as a mandatory
visual system.

## v0 / UI Redesign Contract

When redesigning the Dashboard with v0 or another UI tool, keep the integration
boundary stable:

- UI pages and components may be redesigned freely under `src/app` and
  `src/components`.
- Frontend data access should go through `src/lib/api.ts`; pages should not
  call the bridge, Wazuh Manager, Wazuh Indexer, Slack, or LLM endpoints
  directly.
- Shared response types belong in `src/lib/types.ts`.
- Flow-specific view models belong in small files under `src/lib`, such as
  `src/lib/setup-flow.ts`. This lets v0 change layout without rewriting the
  setup rules.
- Secrets and operational credentials must stay in the bridge/backend. The UI
  should only receive configured flags, previews, status, and actionable
  messages.
- The local proxy `/api/dashboard/*` should remain the frontend contract. It
  hides TLS quirks, local Docker networking, and backend deployment details
  from the UI.

For v0 handoff, give it mock JSON shaped like `src/lib/types.ts` and ask it to
return React components that consume those props. Wire the components back to
`src/lib/api.ts` after the visual design is accepted.

## Checks

```bash
cd dashboard
npm run lint
npm run build
```

The full project release check is:

```bash
./scripts/check-quality.sh
```

## Release Note

This Dashboard is not a standalone SaaS deployment. It needs the EdgeSec-Pi
bridge, Wazuh, and notification settings to be running in the target local or
LAN environment.
