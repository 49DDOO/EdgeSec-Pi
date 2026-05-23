# EdgeSec-Pi

EdgeSec-Pi is a local Wazuh alert explanation and response bridge for small
and medium-sized businesses. It receives Wazuh alerts, summarizes them in
business-readable Traditional Chinese, stores the history locally, and can send
LINE, Slack, Telegram, or email notifications with optional response actions.

The project is designed for teams that already like Wazuh's detection depth but
need a simpler owner-facing workflow: "What happened, how serious is it, and
what should we do next?"

> Project status: preview / pilot. EdgeSec-Pi is not a SIEM replacement and not
> a SOC automation platform. Wazuh remains the detection source of truth; this
> project adds a readable dashboard, notification workflow, and controlled
> response helpers on top.

## Start Here

If you want to install the whole system from zero, start with one of these:

- **[INSTALL.md — 完整安裝手冊（繁體中文）](INSTALL.md)**
- **[INSTALL.en.md — Complete Installation Guide (English)](INSTALL.en.md)**

That guide walks through:

1. Installing the EdgeSec-Pi Dashboard / bridge.
2. Starting a local AI service with LM Studio.
3. Starting the bundled Wazuh lab stack, or connecting an existing Wazuh.
4. Setting and testing LINE / Slack / Telegram / Email notifications.
5. Installing the correct Wazuh Agent package for Windows, macOS Apple silicon,
   macOS Intel, Debian/Ubuntu, or RPM-based Linux.
6. Filling endpoint business context.
7. Running readiness checks.

`SETUP_GUIDE.md` is only for the optional MCP / LobeChat investigation path. It
is not the main owner-facing installation flow.

## What This Repository Contains

This repository has three separate parts:

| Path | Purpose |
|------|---------|
| `wazuh-llm-bridge/` | The main EdgeSec-Pi service. FastAPI receives Wazuh alerts, calls a local LLM, stores results in SQLite, renders the dashboard, and sends Slack messages. |
| `wazuh-stack/` | A local Wazuh single-node lab stack for demo and testing. Use this when you do not already have Wazuh running. |
| `INSTALL.md` / `INSTALL.en.md` | Complete from-zero installation guides in Traditional Chinese and English for the main Dashboard / Wazuh / Agent / notification flow. |
| `install.sh` / `SETUP_GUIDE.md` | Optional LobeChat + Wazuh MCP Server flow. This is not required for the main Slack/dashboard pipeline. |

If you already have a Wazuh manager, you usually only need
`wazuh-llm-bridge/` plus one Wazuh integration webhook.

## Architecture

```text
Wazuh agents
    |
    v
Wazuh Manager / Integrator
    |
    | POST /webhook
    v
EdgeSec-Pi bridge
    |
    +--> async queue + workers
    +--> local LLM via LM Studio
    +--> SQLite alert history
    +--> owner dashboard (dashboard/ Next.js app)
    +--> LINE / Slack / Telegram / email notification
    +--> optional response buttons

Owner: reads the EdgeSec-Pi dashboard and notification summaries.
IT: investigates raw events in Wazuh Dashboard when needed.
```

Wazuh remains the source of detection truth. EdgeSec-Pi adds the communication
and response layer on top of it.

## Main Features

| Area | Capability |
|------|------------|
| Alert intake | Wazuh JSON webhook receiver with immediate `202 Accepted` response. |
| Back pressure | Bounded `asyncio.Queue`; returns `503` during bursts instead of exhausting host memory. |
| Local triage | Calls an LM Studio-compatible local model endpoint. |
| Business summary | Traditional Chinese `summary_zh`, `impact_zh`, and `next_step_zh` for non-SOC users. |
| IT context | Keeps technical fields such as rule ID, MITRE, IOC, root cause, and raw log. |
| Dashboard | `http://127.0.0.1:3000` shows owner-facing risk state, important events, and system health. |
| Notifications | LINE, Slack, Telegram, or email. Slack Bot Token + Socket Mode enables interactive buttons when configured. |
| Persistence | SQLite-backed alert history with `/alerts`, `/stats`, and `/status` APIs. |
| Optional response | Wazuh Active Response helpers for IP block/unblock workflows. Endpoint isolation is pluggable and requires a tested agent-side script. |

## Recommended Owner Flow

For a non-technical company owner, the installation should be operated from the
Dashboard in this order:

1. **Set up notifications** - LINE, Slack, Telegram, or email. At least one
   channel must send a successful test message.
2. **Install or connect Wazuh** - connect an existing Wazuh Manager, or use the
   bundled Wazuh lab stack for a local pilot.
3. **Install endpoint agents** - download the OS-specific Wazuh agent from the
   Dashboard, then verify the endpoint appears online.
4. **Fill endpoint business context** - add who uses the computer, what process
   it supports, business hours, and impact level. This helps the LLM explain
   alerts in business language.
5. **Wait for notifications** - review alerts in the Dashboard or notification
   channel; use Wazuh Dashboard / MCP only when deeper IT investigation is
   needed.

MCP and LobeChat are intentionally not part of this owner flow. They are
advanced investigation tools for IT or an outsourced security partner.

## Quick Start

For a complete first-time installation, use [INSTALL.md](INSTALL.md) or
[INSTALL.en.md](INSTALL.en.md). The short commands below are for users who
already understand the moving parts.

### macOS Dashboard installer

For a local macOS management machine, use the installer:

```bash
./scripts/install-dashboard-macos.sh
```

It creates missing config files, installs bridge dependencies, generates local
HTTPS certificates, starts the bridge, checks the AI analysis service, and opens
the onboarding page. It does not configure notification credentials or install
endpoint agents; those remain inside the Dashboard setup flow.

For non-technical owners, the Dashboard should describe this as:

- `AI 分析`: required. Turns raw SIEM alerts into readable business guidance.
- `進階查詢`: optional. Lets AI look up extra SIEM context when deeper
  investigation is needed.

### Manual setup

#### 1. Configure the bridge

```bash
cp bridge.env.example bridge.env
cd wazuh-llm-bridge
cp .env.example .env
```

Edit the two env files for your local setup:

- `bridge.env` is the service location map: bridge port, public URL, LM Studio
  URL, Wazuh API URL, Wazuh Indexer URL, MCP URL, and lab service ports.
- `wazuh-llm-bridge/.env` contains secrets and behavior settings such as Slack
  tokens, Wazuh credentials, MCP API key, and Active Response token.

Do not commit either real env file.

#### 2. Start LM Studio

Start LM Studio's local server and load the model configured by `LM_MODEL`.
The default endpoint is:

```text
http://localhost:1234/v1/chat/completions
```

If you use another OpenAI-compatible local or cloud endpoint, set
`LM_STUDIO_URL` and `LM_MODEL` in `bridge.env`. This is still shown to users as
`AI 分析`; keep provider names in the technical settings, not the owner-facing
workflow.

#### 3. Run the bridge

```bash
cd scripts
./run.sh bridge
```

Then open:

```text
http://127.0.0.1:3000
```

The health endpoint is:

```text
https://localhost:$BRIDGE_PORT/health
```

If `bridge.env` enables HTTPS with `BRIDGE_SSL_CERTFILE` and
`BRIDGE_SSL_KEYFILE`, `scripts/run.sh bridge` generates a local EdgeSec-Pi
certificate when it is missing. On macOS, the dashboard machine must trust the
local CA once:

```bash
EDGESEC_TRUST_LOCAL_CA=1 ./scripts/run.sh bridge
```

This is a local/LAN convenience path. For a customer deployment, prefer a real
domain plus a publicly trusted certificate so the owner does not need to manage
browser trust settings.

#### 4. Optional: run the bundled Wazuh lab stack

If you do not already have Wazuh:

```bash
cd wazuh-stack
./setup.sh
../tests/e2e/smoke-test.sh
```

The smoke test injects fake SSH brute-force lines into the demo agent so you
can verify the full Wazuh -> bridge -> dashboard/Slack path.

## Connect an Existing Wazuh Manager

For the complete existing-Wazuh procedure, use
[INSTALL.md](INSTALL.md#b-正式部署版接到既有-wazuh).

At minimum, Wazuh needs both:

1. A forwarder script at `/var/ossec/integrations/custom-llm-bridge`.
2. A matching `<integration>` block in `ossec.conf`.

```xml
<integration>
  <name>custom-llm-bridge</name>
  <hook_url>https://<bridge-host>:${BRIDGE_PORT}/webhook</hook_url>
  <api_key>same value as WEBHOOK_SECRET</api_key>
  <level>7</level>
  <alert_format>json</alert_format>
</integration>
```

For Docker Desktop on macOS or Windows, a Wazuh container can usually reach the
host bridge with:

```text
https://host.docker.internal:${BRIDGE_PORT}/webhook
```

For Linux hosts, put the bridge and Wazuh manager on a reachable network path
and use that address instead.

## Public API

| Endpoint | Purpose |
|----------|---------|
| `GET /dashboard` | Compatibility redirect to the Next.js Dashboard. |
| `GET /self-test` | Management-facing readiness check with Chinese action guidance. |
| `GET /health` | Bridge process health and queue size. |
| `GET /alerts` | Recent stored alerts. |
| `GET /stats` | Alert counts and severity breakdown. |
| `GET /status` | Bridge dependency and service status. |
| `POST /webhook` | Wazuh alert intake endpoint. |

FastAPI's generated docs are available at:

```text
http://localhost:$BRIDGE_PORT/docs
```

For non-technical owners, use the self-test button in the Dashboard. It reports
whether the system is usable and which item IT should handle, without exposing
terminal output or raw service logs.

## Security Notes

- Keep `.env`, `bridge.env`, SQLite files, and logs out of git.
- Keep `wazuh-llm-bridge/org_profile.yaml` out of git when it contains real
  device names, owners, or business notes. Use
  `wazuh-llm-bridge/org_profile.example.yaml` as the public template.
- In production, bind the bridge to a private interface or put it behind TLS.
- Set `WEBHOOK_SECRET` if the webhook is reachable by anything other than the
  local Wazuh manager.
- Treat `ACTIVE_RESPONSE_TOKEN` as a password. Anyone with it can trigger
  response actions.
- Start response actions in review-only mode before enabling destructive
  actions such as firewall block.
- Wazuh does not include a universal endpoint-isolation command. If you expose
  the `隔離端點` Slack action, install and test an agent-side isolation script
  first, then set `WAZUH_ISOLATE_COMMAND`.

## Testing

Install development dependencies:

```bash
python3 -m pip install -r requirements-dev.txt
```

Run the default test gate:

```bash
./scripts/test.sh
```

The default gate runs deterministic unit and integration tests with fake
LM Studio / fake MCP services. Real Wazuh, real LM Studio, and real
notification checks are separate e2e/manual targets; see [TESTING.md](TESTING.md).

## Release Readiness

Before presenting this repository as a public release, read
[RELEASE_READINESS.md](RELEASE_READINESS.md). It lists the honest product
boundary, what is ready for a pilot, and what should remain marked as advanced
or experimental.

## Documentation

- [wazuh-llm-bridge/README.md](wazuh-llm-bridge/README.md) - bridge design and tuning
- [wazuh-stack/README.md](wazuh-stack/README.md) - local Wazuh lab setup
- [INSTALL.md](INSTALL.md) / [INSTALL.en.md](INSTALL.en.md) - complete installation guide
- [TESTING.md](TESTING.md) - test strategy and commands
- [RELEASE_READINESS.md](RELEASE_READINESS.md) - release positioning and preflight checks
- [SETUP_GUIDE.md](SETUP_GUIDE.md) - optional LobeChat + Wazuh MCP Server setup
- [PARTNER_BRIEF.md](PARTNER_BRIEF.md) - business-facing partner brief

## Project Status

This is an early-stage implementation intended for local evaluation and pilot
deployments. The core webhook, local LLM triage, dashboard, SQLite history, and
Slack delivery paths are implemented. Production deployments should add normal
hardening around TLS, authentication, monitoring, backup, and change control.
