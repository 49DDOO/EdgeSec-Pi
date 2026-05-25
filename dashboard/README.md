# EdgeSec-Pi Dashboard

This is the management Dashboard for EdgeSec-Pi.

It is a Next.js frontend that talks to the local EdgeSec-Pi bridge API. The
Dashboard is intentionally separate from the bridge service:

- `dashboard/` renders the management UI.
- `wazuh-llm-bridge/` receives SIEM alerts, stores data, enriches alerts, and
  exposes the Dashboard API.

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

## Checks

```bash
cd dashboard
pnpm --config.verify-deps-before-run=false lint
pnpm --config.verify-deps-before-run=false build
```

The full project release check is:

```bash
./scripts/check-quality.sh
```

## Release Note

This Dashboard is not a standalone SaaS deployment. It needs the EdgeSec-Pi
bridge, Wazuh, and notification settings to be running in the target local or
LAN environment.
