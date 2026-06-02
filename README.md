# EdgeSec-Pi

EdgeSec-Pi is a security agent advice layer for small and medium-sized
businesses. It receives alerts from upstream security sources, with Wazuh Alert
as the first production source, normalizes them into a canonical signal,
explains them in business-readable Traditional Chinese, stores the history
locally, and can send LINE, Slack, Telegram, or email notifications with
optional human-approved response actions.

The project is designed for teams that need a controlled security agent
recommendation flow rather than a free-form chatbot: "What happened, how
serious is it, what evidence supports that, and should anyone do anything now?"

> Project status: preview / pilot. EdgeSec-Pi is not a Wazuh distribution, not a
> SIEM replacement, and not a generic autonomous AI agent. Wazuh Alert is
> currently the first event source of truth; Wazuh MCP/API and Active Response
> are capabilities around that source for evidence lookup and controlled
> response. EdgeSec-Pi adds the owner-facing agent advice workflow,
> notification routing, evidence handling, and response guardrails on top.

## 專案目的（Project Purpose）

EdgeSec-Pi 是給**沒有 SOC 團隊的中小企業**使用的「資安 Agent 建議層」。Dashboard 就像 Agent 把上游告警消化後給你的建議面板：今天安不安全、老闆要不要決定、IT 要處理什麼。它**不取代 Wazuh，也不重做 SIEM 或 EDR**，而是把 Wazuh Alert 這類事件來源、證據查詢能力、受控處置能力接起來，形成**老闆看得懂、IT 能執行、AI 不能越權**的判斷與處置流程。

1. **接入事件來源** — 先以 Wazuh Alert 為第一個來源，未來可擴充 Microsoft 365、Google Workspace、防火牆、EDR 等事件來源。
2. **統一事件格式** — 把不同來源的告警轉成 canonical signal，讓判斷流程不被單一產品綁死。
3. **協助判斷風險** — 以**規則與 playbook 為主、本地 LLM 負責解釋**，搭配歷史查證與企業資產脈絡，判斷這是噪音、可觀察事件，還是需要 IT 立刻處理的風險。LLM 是解釋者，不是裁判：嚴重度與處置由 deterministic 規則約束，LLM 不得憑空升降級、也不授權任何破壞性動作。
4. **產出白話說明** — 給老闆的是繁體中文白話結論：哪台電腦、發生什麼事、會有什麼影響、下一步找誰處理。
5. **提供 IT 證據** — 給 IT 的是來源 IP、帳號、主機、規則、MITRE、歷史關聯、MCP 查證結果等可執行證據。
6. **支援安全處置** — 先透過 Wazuh Active Response 做封鎖 IP、隔離端點、解除封鎖、解除隔離；未來可接防火牆、EDR、雲端身分平台等處置能力。所有破壞性動作都要經過人工確認、TTL、白名單、防呆與稽核。**Dashboard 是 Agent 建議與決策介面，不是唯讀儀表板。**

**界線（誠實聲明）：** EdgeSec-Pi 的偵測能力取決於上游來源——它判斷、翻譯、處置 Wazuh（或其他來源）**已經偵測到**的事件，本身不做偵測。要抓得到更多，請強化上游（agent-groups、Sysmon、VirusTotal、YARA 等）。

> 一句話：EdgeSec-Pi 把不同來源送來的「資安告警」變成「中小企業真的看得懂、能判斷、能安全處理的 Agent 建議」。

## Agent Advice Flow Model

| Layer | Responsibility | Current implementation |
|-------|----------------|------------------------|
| Event source | Sends alerts or security events into EdgeSec-Pi. | Wazuh Alert webhook first; planned Google Workspace, Microsoft 365, Firewall, and EDR event sources. |
| Canonical signal | Normalizes vendor payloads into one security-event shape. | `canonical_signal.py` plus source adapters. |
| Evidence capability | Looks up context before the LLM explains the event. | Wazuh MCP and Wazuh Manager/Indexer queries. |
| Decision playbook | Makes deterministic routing and safety decisions. | Triage routing, false-positive suppression, detection categories, and response guards. |
| Explanation agent | Turns evidence into owner and IT language. | Local or OpenAI-compatible LLM prompts. |
| Decision surface | Shows the agent recommendation and asks for human judgment when needed. | Dashboard, LINE, Slack, Telegram, and email notifications. |
| Response capability | Executes approved containment or remediation. | Wazuh Active Response for block/unblock and isolate/release. |

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

This repository has three main runtime parts plus optional tooling:

| Path | Purpose |
|------|---------|
| `wazuh-llm-bridge/` | The main EdgeSec-Pi service. FastAPI receives Wazuh alerts, applies deterministic routing/suppression, calls a local LLM, stores results in SQLite, exposes Dashboard APIs, sends notifications, and gates response actions. |
| `dashboard/` | The Next.js management UI for first-time setup, alert review, MCP investigation, endpoint inventory, detection presets, notification settings, and self-tests. |
| `wazuh-stack/` | A local Wazuh single-node lab stack for demo and testing. Use this when you do not already have Wazuh running. |
| `INSTALL.md` / `INSTALL.en.md` | Complete from-zero installation guides in Traditional Chinese and English for the main Dashboard / Wazuh / Agent / notification flow. |
| `install.sh` / `SETUP_GUIDE.md` | Optional LobeChat + Wazuh MCP Server flow. This is not required for the main Slack/dashboard pipeline. |

If you already have a Wazuh manager, you usually only need
`wazuh-llm-bridge/` plus one Wazuh integration webhook.

## Architecture

```text
Event sources (Wazuh Alert first)
    |
    v
Source adapter / Wazuh Manager Integrator
    |
    | POST /webhook
    v
EdgeSec-Pi bridge
    |
    +--> async queue + workers
    +--> canonical signal normalization
    +--> false-positive suppression + detection-category routing
    +--> evidence lookup through source capabilities
    +--> local LLM via LM Studio
    +--> optional MCP investigation (playbook first, tool-loop deep path second)
    +--> SQLite alert history
    +--> agent recommendation dashboard (dashboard/ Next.js app)
    +--> LINE / Slack / Telegram / email notification
    +--> optional human-approved response actions

Owner: reads the EdgeSec-Pi dashboard and notification summaries.
IT: investigates raw events in the source system when needed.
```

Wazuh Alert remains the first event source of truth. Wazuh MCP/API and Active
Response are capabilities around that source, used for evidence lookup and
controlled response. EdgeSec-Pi keeps the higher-level agent boundary: source
input, evidence, playbook decision, LLM explanation, human approval, and
controlled response.

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
| Investigation | Dashboard "MCP 查證" uses deterministic fast playbooks when possible, then a restricted tool loop for deeper Wazuh MCP questions. |
| Wazuh signal controls | Wazuh Alert detection-category presets (`conservative`, `recommended`, `expanded`) plus noisy-category warnings and bridge-level false-positive suppression. |
| Setup checks | Owner-facing self-test verifies bridge, AI, Wazuh, notification settings, agent-groups, and recent module event flow. |
| Optional response | Wazuh Active Response helpers for IP block/unblock and endpoint isolate/release workflows, guarded by TTL, audit rows, allow/deny policy, and human approval. |

## Recommended Owner Flow

For a non-technical company owner, the installation should be operated from the
Dashboard in this order:

1. **Open First-time Setup** - use `/settings/setup` as the non-technical
   checklist instead of terminal logs.
2. **Connect Wazuh** - connect an existing Wazuh Manager, or use the bundled
   Wazuh lab stack for a local pilot.
3. **Set up AI analysis** - point the bridge at LM Studio or another
   OpenAI-compatible endpoint and verify the configured model.
4. **Set up notifications** - LINE, Slack, Telegram, or email. At least one
   channel must send a successful test message.
5. **Install endpoint agents** - download the OS-specific Wazuh agent from the
   Dashboard, then verify the endpoint appears online.
6. **Enable detection hardening carefully** - agent-groups prove deployment and
   assignment; recent module event flow is the second evidence layer. Group
   membership alone does not prove Sysmon/FIM/SCA/VT/YARA are emitting events.
7. **Fill endpoint business context** - add who uses the computer, what process
   it supports, business hours, and impact level. This helps the LLM explain
   alerts in business language.
8. **Run a test alert** - confirm Dashboard history, AI wording, and the chosen
   notification channel all receive the same event.

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

EdgeSec-Pi treats Wazuh Alert as the first event source, not as a fixed
deployment shape. The Wazuh source has three installation modes:

| Mode | Use when | Customer input |
|------|----------|----------------|
| `managed` | EdgeSec runs Wazuh for the customer. | No Wazuh host/key from the owner; platform provisioning creates and stores them. |
| `existing` | The customer already has Wazuh, either cloud-hosted or self-hosted. | Wazuh Manager URL, Indexer URL, and service credentials/token. |
| `local_lab` | Demo, PoC, or engineering validation. | Local Docker Wazuh defaults plus lab credentials. |

Only `existing` and `local_lab` are implemented in this repository today.
`managed` is a clean product boundary for future cloud provisioning, not a
pretend local setup.

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
| `GET /api/dashboard/service-status` | Owner-facing readiness checks for Dashboard setup. |
| `GET /api/dashboard/summary` | Dashboard landing-page summary. |
| `POST /api/dashboard/investigation/chat` | MCP-backed owner/IT investigation chat. |
| `GET/PUT /api/dashboard/detection-categories` | Detection-category preset and noise settings. |
| `GET/PUT /api/dashboard/notifications/*` | Notification settings and channel tests. |
| `GET/PUT /api/dashboard/wazuh-settings` | Wazuh Manager/Indexer settings and connection tests. |
| `POST /webhook` | Wazuh alert intake endpoint. |
| `POST /active-response/*` | Token-gated block/unblock/isolate/release actions. |

FastAPI's generated docs are available at:

```text
https://localhost:$BRIDGE_PORT/docs
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
- LLM prompts treat raw log fields as untrusted data. Keep deterministic
  guardrails and human approval in front of severity escalation and destructive
  actions.
- Marking an alert false-positive creates a short-lived, scoped suppression
  rule. This reduces repeated noise, but suppression rules must stay visible and
  removable from the Dashboard.
- Firewall blocks are tracked with a TTL and a background sweeper attempts to
  remove them when they expire. TTL accuracy is approximately the configured
  sweep interval, so a block can remain for up to one extra sweep cycle. Failed
  unblock attempts retry with bounded backoff before being marked for manual IT
  cleanup. For non-local agents, set `WAZUH_UNBLOCK_COMMAND` after installing a
  tested agent-side unblock script.
- Wazuh does not include a universal endpoint-isolation command. If you expose
  the `隔離端點` Slack action, install and test an agent-side isolation script
  first, then set both `WAZUH_ISOLATE_COMMAND` and
  `WAZUH_RELEASE_ISOLATION_COMMAND`. Enable only platforms listed in
  `ACTIVE_RESPONSE_ISOLATION_VERIFIED_PLATFORMS` after real-machine testing.
- Wazuh agent-groups are deployment evidence, not detection proof. The Dashboard
  separately checks recent module event flow so the UI does not imply
  Sysmon/FIM/SCA/VT/YARA are active merely because a group was assigned.

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
- [docs/architecture/CURRENT_ARCHITECTURE.md](docs/architecture/CURRENT_ARCHITECTURE.md) - current Wazuh-first architecture and ownership boundaries
- [docs/architecture/MULTI_SOURCE_MDR.md](docs/architecture/MULTI_SOURCE_MDR.md) - long-term multi-source MDR architecture direction
- [wazuh-stack/active-response/README.md](wazuh-stack/active-response/README.md) - optional endpoint isolate/release scripts
- [SETUP_GUIDE.md](SETUP_GUIDE.md) - optional LobeChat + Wazuh MCP Server setup
- [PARTNER_BRIEF.md](PARTNER_BRIEF.md) - business-facing partner brief

## Project Status

This is an early-stage implementation intended for local evaluation and pilot
deployments. The core webhook, local LLM triage, dashboard, SQLite history, and
Slack delivery paths are implemented. Production deployments should add normal
hardening around TLS, authentication, monitoring, backup, and change control.
