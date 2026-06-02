# EdgeSec-Pi Complete Installation Guide

Language: [繁體中文](INSTALL.md) | English

This guide is for a first-time installation. The goal is to start from a clean
management computer and bring up the whole system:

1. Wazuh collects security events from computers and servers.
2. EdgeSec-Pi Dashboard shows what needs attention today.
3. A local AI model turns technical Wazuh alerts into readable explanations.
4. LINE, Slack, Telegram, or email sends notifications.
5. Wazuh Agent is installed on every computer you want to protect.

> MCP / LobeChat is an advanced investigation path. It is not required for the
> first production or pilot setup. See [SETUP_GUIDE.md](SETUP_GUIDE.md) when
> you are ready to add it for IT or an outsourced security partner.

---

## Choose an Installation Path

### A. Local Pilot, Recommended for First Use

Use this if you want to test everything on one Mac first.

This installs:

- EdgeSec-Pi Dashboard
- Local HTTPS
- Local Wazuh lab stack: Manager, Indexer, Dashboard, and a demo agent
- Agent download links for real computers

### B. Production Setup with an Existing Wazuh Manager

Use this if your company already has Wazuh, or if Wazuh will run on a dedicated
server.

This installs:

- EdgeSec-Pi Dashboard / Bridge
- A webhook integration from Wazuh Manager to EdgeSec-Pi
- Notification channels
- Agents installed through your existing Wazuh process or from the Dashboard

---

## A. Local Pilot: From Zero

### 1. Prepare a Management Computer

Recommended baseline:

| Item | Recommendation |
|------|----------------|
| Operating system | macOS |
| Memory | 32 GB or more; 64 GB is better for larger local models |
| Docker | Docker Desktop installed and running |
| Python | Python 3.10 or newer |
| Git | Used to download the project |
| AI runtime | LM Studio installed |

Check Docker:

```bash
docker ps
```

### 2. Download EdgeSec-Pi

```bash
git clone https://github.com/49DDOO/EdgeSec-Pi.git
cd EdgeSec-Pi
```

### 3. Start the Local AI Server

1. Open LM Studio.
2. Download and load a model that can understand Chinese.
3. Open Local Server and click Start.
4. Confirm that the endpoint responds:

```bash
curl http://localhost:1234/v1/models
```

You should see the model name. Keep that name, for example:

```text
gemma-4-31b-it-mlx
```

### 4. Install the Dashboard and Wazuh Lab

```bash
./scripts/install-dashboard-macos.sh --with-wazuh-stack
```

The installer will:

- create `bridge.env`
- create `wazuh-llm-bridge/.env`
- install Python dependencies
- create a local HTTPS certificate
- start the EdgeSec-Pi Dashboard
- start the local Wazuh lab stack

If the installer asks whether to trust the EdgeSec-Pi Local CA, choose `Y`.
This lets the local browser open the HTTPS Dashboard.

### 5. Set the AI Model Name

Open `bridge.env` and set `LM_MODEL` to the exact model name loaded in LM
Studio:

```env
LM_MODEL=gemma-4-31b-it-mlx
```

Restart the Dashboard:

```bash
./scripts/run.sh bridge
```

### 6. Open the Dashboard

```text
http://127.0.0.1:3000/settings/setup
```

For first-time setup, follow this order:

1. Connect Wazuh.
2. Configure AI and verify the model.
3. Set up at least one notification channel and pass a test message.
4. Install the first Agent.
5. Check detection hardening status.
6. Fill the business context for each endpoint.
7. Send one test alert.
8. Return to Today and wait for alerts.

### 7. Configure Notifications

In the Dashboard:

```text
Setup -> Notification settings
```

Set at least one channel:

- LINE: best for non-technical users.
- Slack: best when the company already uses Slack.
- Telegram: useful for technical contacts.
- Email: useful as a fallback channel.

Each channel must send a successful test message before it should be considered
ready.

### 8. Install the First Agent

Agent installers are OS-specific. Download the correct package for each
computer:

| Computer type | Dashboard download option | Use for |
|---------------|---------------------------|---------|
| Windows | `Windows / MSI` | Windows desktops, laptops, and Windows Server |
| macOS Apple silicon | `macOS / Apple silicon` | M1 / M2 / M3 / M4 Macs |
| macOS Intel | `macOS / Intel` | older Intel Macs |
| Ubuntu / Debian | `Linux / DEB` | Ubuntu, Debian, Linux Mint |
| Red Hat family | `Linux / RPM` | RHEL, Rocky Linux, AlmaLinux, CentOS, Fedora |

To add the current Mac as a monitored endpoint:

```bash
sudo ./scripts/install-mac-agent.sh
```

For another computer:

1. Open `Endpoints` in the Dashboard.
2. Click `Install Agent`.
3. Download the package that matches that computer's operating system.
4. Install it on that computer.
5. Return to `Endpoints` and confirm that the new computer appears.

> Important: if the Agent is installed on another computer, the Manager address
> must not be `localhost` or `127.0.0.1`. Use the LAN IP of the EdgeSec-Pi /
> Wazuh Manager machine, for example `192.168.50.177`.

Agent connectivity requirements:

| Port | Purpose |
|------|---------|
| `1515/tcp` | first-time Agent enrollment |
| `1514/tcp` | continuous Agent event reporting |

If the Agent does not appear in the Dashboard, test from that endpoint:

```bash
nc -vz <Wazuh-Manager-IP> 1515
nc -vz <Wazuh-Manager-IP> 1514
```

On Windows, use PowerShell:

```powershell
Test-NetConnection <Wazuh-Manager-IP> -Port 1515
Test-NetConnection <Wazuh-Manager-IP> -Port 1514
```

Check whether the Agent service is running:

| Operating system | How to check |
|------------------|--------------|
| Windows | Open `services.msc` and confirm `WazuhSvc` is Running |
| macOS | `sudo /Library/Ossec/bin/wazuh-control status` |
| Linux | `sudo systemctl status wazuh-agent` |

### 9. Fill Endpoint Business Context

In the Dashboard:

```text
Endpoints -> Endpoint business context
```

For each computer, fill at least:

- Purpose: for example `Developer`, `Accounting PC`, or `Store POS`.
- Importance: low, normal, important, or critical.
- Business hours: for example `Mon-Fri 09:00-19:00 Asia/Taipei`.
- Notes: for example `Only Peter uses this computer` or `Handles customer data`.

This step is important. Without business context, the AI can only describe a
technical alert. With context, notifications can explain who, which process, or
which system may be affected.

### 10. Verify the Whole System

Run the environment check:

```bash
./scripts/test.sh env
```

Expected result:

```text
environment readiness passed
```

Then open:

```text
http://127.0.0.1:3000/settings/status
```

Click the self-check button. If it reports that the system is usable, the main
services are connected.

> Note: detection hardening has two evidence layers. Applied `agent-groups`
> mean the Wazuh hardening recipe was deployed to endpoints. That does not
> prove Sysmon, FIM, SCA, VirusTotal, or YARA are all producing events. The
> Dashboard separately checks recent event history as a second signal.

---

## B. Production Setup: Connect an Existing Wazuh Manager

If the company already has Wazuh, the flow is:

1. Install EdgeSec-Pi Bridge on the management computer or server.
2. Add a webhook integration to Wazuh Manager.
3. Configure notifications.
4. Install or confirm Wazuh Agents.

### 1. Install EdgeSec-Pi Bridge

```bash
git clone https://github.com/49DDOO/EdgeSec-Pi.git
cd EdgeSec-Pi
cp bridge.env.example bridge.env
cd wazuh-llm-bridge
cp .env.example .env
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Edit `bridge.env`

At minimum, confirm:

```env
BRIDGE_PORT=8001
BRIDGE_PUBLIC_URL=https://your-dashboard-host:8001

LM_STUDIO_URL=http://localhost:1234/v1/chat/completions
LM_MODEL=your-model-name

WAZUH_API_URL=https://your-wazuh-manager:55000
WAZUH_INDEXER_URL=https://your-wazuh-indexer:9200
SIEM_DASHBOARD_URL=https://your-wazuh-dashboard

MANAGER_HOST=your-wazuh-manager-ip
WAZUH_AGENT_PORT=1514
WAZUH_AUTHD_PORT=1515
```

### 3. Edit `wazuh-llm-bridge/.env`

Confirm Wazuh API credentials and notification settings.

For production, set strong secrets:

```env
WEBHOOK_SECRET=replace-with-a-long-secret
ACTIVE_RESPONSE_TOKEN=replace-with-a-long-secret
```

Do not commit `.env` or `bridge.env` to GitHub.

### 4. Start the Bridge

```bash
cd ../scripts
./run.sh bridge
```

Check health:

```bash
curl -k https://localhost:8001/health
```

### 5. Add the Wazuh Webhook Integration

Wazuh integrations require two things:

1. A forwarder script named `custom-llm-bridge`.
2. A matching `<integration>` block in `ossec.conf`.

#### 5-1. Install the Forwarder Script

On a native Wazuh Manager:

```bash
sudo cp wazuh-stack/customizations/custom-llm-bridge /var/ossec/integrations/custom-llm-bridge
sudo chown root:wazuh /var/ossec/integrations/custom-llm-bridge
sudo chmod 750 /var/ossec/integrations/custom-llm-bridge
```

If Wazuh Manager runs in Docker:

```bash
docker cp wazuh-stack/customizations/custom-llm-bridge \
  <wazuh-manager-container>:/var/ossec/integrations/custom-llm-bridge
docker exec <wazuh-manager-container> chown root:wazuh /var/ossec/integrations/custom-llm-bridge
docker exec <wazuh-manager-container> chmod 750 /var/ossec/integrations/custom-llm-bridge
```

#### 5-2. Add the `ossec.conf` Integration

Add this to Wazuh Manager's `/var/ossec/etc/ossec.conf`:

```xml
<integration>
  <name>custom-llm-bridge</name>
  <hook_url>https://your-edgesec-pi-host:8001/webhook</hook_url>
  <api_key>your WEBHOOK_SECRET</api_key>
  <level>7</level>
  <alert_format>json</alert_format>
</integration>
```

The `api_key` must match `WEBHOOK_SECRET` in `wazuh-llm-bridge/.env`. The
forwarder sends it to EdgeSec-Pi as `Authorization: Bearer ...`.

Restart Wazuh Manager after editing.

#### 5-3. Verify Delivery

Check the Wazuh integration log:

```bash
sudo tail -80 /var/ossec/logs/integrations.log
```

Docker version:

```bash
docker exec <wazuh-manager-container> tail -80 /var/ossec/logs/integrations.log
```

Check that EdgeSec-Pi received alerts:

```bash
curl -k https://localhost:8001/alerts?limit=5
```

### 6. Confirm Agents

Every protected computer needs a Wazuh Agent pointed at:

```text
MANAGER_HOST:1514
MANAGER_HOST:1515
```

The Dashboard `Endpoints` page lists monitored endpoints.

---

## Should I Install MCP / LobeChat?

Not during first setup.

Recommended order:

1. Make sure Dashboard, notifications, and Agents work.
2. Make sure the company can receive and understand alerts.
3. Then let IT or an outsourced security partner add MCP / LobeChat.

MCP is useful for:

- querying raw Wazuh events
- checking endpoint vulnerabilities
- checking agent status
- giving AI more investigation context

See [SETUP_GUIDE.md](SETUP_GUIDE.md).

---

## Troubleshooting

### 1. Dashboard HTTPS Does Not Open

The local certificate is not trusted by the browser. Run:

```bash
EDGESEC_TRUST_LOCAL_CA=1 ./scripts/run.sh bridge
```

If it still fails, restart the browser. For production, use a real domain and a
publicly trusted certificate.

### 2. LM Studio Is Not Working

Check:

```bash
curl http://localhost:1234/v1/models
```

If no model appears, load a model in LM Studio and start Local Server. Then set
`LM_MODEL` in `bridge.env` to the actual model name.

### 3. Agent Is Installed but Does Not Appear

Check the Agent service:

```bash
sudo /Library/Ossec/bin/wazuh-control status
```

Check Manager connectivity:

```bash
nc -vz <MANAGER_HOST> 1514
nc -vz <MANAGER_HOST> 1515
```

If a macOS Agent config still contains `MANAGER_IP`, the Manager address was not
replaced during installation. Reconfigure `/Library/Ossec/etc/ossec.conf`.

### 4. Slack / LINE Does Not Receive Notifications

Do not wait for a real alert. Open:

```text
Setup -> Notification settings
```

Click Test. A notification channel is ready only after a test message is
received.

### 5. Today Shows Many Duplicate Events

The Dashboard groups events from the same endpoint, same rule, and same source
IP or account into one card. The card shows `N similar events`. Updating the
case status updates the whole group.

---

## Go-Live Checklist

- [ ] Docker Desktop is running.
- [ ] LM Studio Local Server is running.
- [ ] `LM_MODEL` matches the loaded model name.
- [ ] EdgeSec-Pi Dashboard opens.
- [ ] Wazuh Manager / Indexer / Dashboard are usable.
- [ ] At least one notification channel passes a test.
- [ ] At least one Agent is online.
- [ ] Endpoint business context is filled.
- [ ] `/self-test` reports the system is usable.
- [ ] `./scripts/test.sh env` passes.
