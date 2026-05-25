# Wazuh → LM Studio Bridge

A minimal async FastAPI webhook that takes Wazuh alerts, extracts
`rule.description` + `full_log`, and asks a local LM Studio model to triage them.

## Why async?

Wazuh's `integrator` daemon will fire one HTTP POST per alert. If your handler
runs LLM inference inline, a 30-second model call blocks the next alert.
This service:

1. **POST `/webhook`** validates the JSON and **immediately** pushes it onto an
   `asyncio.Queue`, returning `202 Accepted`. Wazuh moves on instantly.
2. **Background workers** (count configurable) pull from the queue and call
   LM Studio in parallel.
3. The queue is **bounded** — when it fills up the webhook returns `503` so
   Wazuh re-queues on its side instead of the host OOM-ing.

## Run

```bash
cd wazuh-llm-bridge
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# Copy runtime locations and secrets from the templates:
cp ../bridge.env.example ../bridge.env
cp .env.example .env

# Start LM Studio's local server first (LM Studio app → Local Server → Start)
# default: http://localhost:1234

# Then run the bridge:
set -a; source ../bridge.env; set +a
uvicorn app:app --host 0.0.0.0 --port "$BRIDGE_PORT" \
  --ssl-certfile "$BRIDGE_SSL_CERTFILE" \
  --ssl-keyfile "$BRIDGE_SSL_KEYFILE"
```

`app.py` also loads `../bridge.env` first, then `.env`, so modules imported by
the bridge see the same service URLs. The shell `source` above is still needed
for the `uvicorn --port "$BRIDGE_PORT"` argument.

Open the management-facing dashboard at `http://127.0.0.1:3000`.

For local/LAN HTTPS, prefer the wrapper because it generates and trusts the
local certificate consistently:

```bash
EDGESEC_TRUST_LOCAL_CA=1 ../scripts/run.sh bridge
```

For customer deployments, use a real domain and public certificate instead of a
local CA whenever possible.

## Smoke test

```bash
set -a; source ../bridge.env; set +a
curl -s "https://localhost:$BRIDGE_PORT/health"

curl -s -X POST "http://localhost:$BRIDGE_PORT/webhook" \
  -H 'Content-Type: application/json' \
  -d '{
    "rule": {"id": "5712", "level": 10, "description": "SSHD brute force"},
    "full_log": "Nov 24 12:00:01 host sshd[1234]: Failed password for root from 10.0.1.45 port 55512 ssh2"
  }'
# → 202 Accepted, then watch the bridge logs for the LM Studio reply
```

## Burst test

```bash
set -a; source ../bridge.env; set +a
for i in $(seq 1 200); do
  curl -s -X POST "http://localhost:$BRIDGE_PORT/webhook" \
    -H 'Content-Type: application/json' \
    -d "{\"rule\":{\"id\":\"$i\",\"level\":7,\"description\":\"test $i\"},\"full_log\":\"line $i\"}" \
    -o /dev/null -w "%{http_code}\n"
done | sort | uniq -c
# Expect mostly 202; some 503 once the queue fills — that is the
# back-pressure working as intended.
```

## Wire it to Wazuh

In `/var/ossec/etc/ossec.conf` on your Wazuh manager:

```xml
<integration>
  <name>custom-llm-bridge</name>
  <hook_url>http://<bridge-host>:${BRIDGE_PORT}/webhook</hook_url>
  <level>7</level>            <!-- only forward level ≥ 7 -->
  <alert_format>json</alert_format>
</integration>
```

Then drop a tiny passthrough script at
`/var/ossec/integrations/custom-llm-bridge` (chmod 750, owner root:wazuh):

```bash
#!/usr/bin/env bash
# Wazuh integrator — just forwards the alert JSON to our webhook.
ALERT_FILE="$1"
HOOK_URL="$3"
curl -sS -m 5 -H 'Content-Type: application/json' \
     --data-binary "@${ALERT_FILE}" "${HOOK_URL}"
```

Restart wazuh-manager and tail `/var/ossec/logs/integrations.log`.

## Tuning

| Knob | Effect |
|------|--------|
| `WORKER_COUNT` | Parallel LM Studio calls. 1–2 for a single GPU model; raise only if the model + hardware can sustain it. |
| `QUEUE_MAXSIZE` | Burst tolerance vs. memory. 1000 alerts × few KB each ≈ a few MB. |
| `LM_TIMEOUT_S` | Per-request timeout. Bump if your model is slow on long logs. |
| `<level>` in ossec.conf | Cheapest filter — don't ship noise to the LLM at all. |

## Remote action tokens

Slack buttons and future remote remediation links must use
`remote_action_tokens.py` instead of embedding raw command parameters. The token
is a short-lived, one-time HMAC ticket that binds:

- `action` — for example `block_ip`, `unblock_ip`, or `isolate_endpoint`
- `agent_id` — the Wazuh agent that the backend must re-check before executing
- `target` — the IP, endpoint name, or other action target
- `nonce` and `exp` — replay protection and expiry

The button or link is only a request to perform an action. The backend must
consume the token, verify the expected action, check authorization, and then
execute through the normal Wazuh or internal API path. Do not put shell commands,
URLs with privileged secrets, or long-lived credentials inside Slack messages.

Configuration:

| Knob | Effect |
|------|--------|
| `REMOTE_ACTION_TOKEN_TTL_S` | Token lifetime in seconds; default is 300. |
| `REMOTE_ACTION_TOKEN_SECRET` | Optional HMAC secret. If omitted, a local secret file is generated. |
| `REMOTE_ACTION_TOKEN_SECRET_FILE` | Optional path for the generated secret. |
| `REMOTE_ACTION_ALLOWED_USERS` | Optional comma-separated Slack user IDs allowed to run high-risk actions. |

Legacy `SLACK_ACTION_*` env names are still accepted as fallbacks, but new code
should use the `REMOTE_ACTION_*` names because the same guard is intended for
Slack, Dashboard, email approval links, and future mobile workflows.

## Next steps

- For production, put the bridge behind TLS and set `WEBHOOK_SECRET` so only
  your Wazuh manager can post alerts.
- Use the Next.js Dashboard for owner-facing summaries and Wazuh Dashboard for IT
  investigation.
- Keep `.env`, `data/`, and logs out of git; copy examples from
  `.env.example` and `../bridge.env.example`.
