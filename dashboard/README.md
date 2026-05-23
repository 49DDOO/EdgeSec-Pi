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
