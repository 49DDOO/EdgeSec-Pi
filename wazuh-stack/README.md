# Wazuh stack — end-to-end with the LLM bridge

This is the **front end** of the EdgeSec-Pi pipeline. It brings up:

- **Wazuh Indexer** (OpenSearch fork) on `:9200`
- **Wazuh Manager** with our `<integration>` block + `custom-llm-bridge` script on `:55000` / `:1514` / `:1515`
- **Wazuh Dashboard** on `:443`
- **One Ubuntu agent container** that auto-enrolls with the manager

Once it's up, every alert with `level >= 7` is POSTed to `https://host.docker.internal:$BRIDGE_PORT/webhook` — i.e. straight into the FastAPI bridge running on your Mac. `BRIDGE_PORT` is loaded from the repo-root `bridge.env`.

## Product boundary (important)

EdgeSec-Pi's job is to **consume Wazuh's alert output**, translate it into
boss-readable Chinese, triage it, and route it to Slack/Active-Response.
It is **not** a Wazuh-deployment tool. We rely on Wazuh's per-OS agent
installer to choose what raw logs to monitor — those defaults are
sufficient for the bridge to do its work.

The `agent-groups/` subfolder contains **OPTIONAL** Wazuh tuning recipes
(extra log sources, filtered Unified Log queries, scheduled command
probes) for environments that want to extend what Wazuh sees. They are
*not* part of the core EdgeSec-Pi product; you can run the whole bridge
without ever deploying them. See `agent-groups/README.md`.

---

## Architecture

```
[ wazuh-llm-agent ]   ──ship logs──►   [ wazuh.manager ]   ──HTTPS POST──►  [ FastAPI bridge ]   ──►   [ LM Studio ]
   (Ubuntu container,                     (analysisd +                         (uvicorn on $BRIDGE_PORT) (Gemma 4 31B)
    monitors auth.log)                     integrator daemon)
                                                  │
                                                  └──►  [ wazuh.indexer ]  ◄──  [ wazuh.dashboard ]
                                                       (search/storage)         (browser UI)
```

---

## Prerequisites

| Item | Why |
|------|-----|
| Docker Desktop ≥ 4.x | Wazuh stack needs Compose v2, BuildKit, vm.max_map_count handling |
| **≥ 6 GB RAM free** for Wazuh + 32 GB for LM Studio + Gemma 31B = **~40 GB total** | M-series Max/Ultra with 64 GB recommended |
| `git`, `curl`, `python3` | bring-up script |
| The `wazuh-llm-bridge` already tested (eval mode-live passing) | this stack feeds into it |

---

## Bring it up

```bash
cd EdgeSec-Pi/wazuh-stack
chmod +x setup.sh teardown.sh
./setup.sh                             # ≈ 5–10 min on first run (image pulls + cert gen)
```

You'll see logs for clone → patch → cert generation → `docker compose up`. The script waits up to 3 min for the manager API to come online before exiting.

In a **separate terminal**, start the bridge pointing at LM Studio:

```bash
cd EdgeSec-Pi/wazuh-llm-bridge
set -a; source ../bridge.env; set +a
LM_STUDIO_URL=http://localhost:1234/v1/chat/completions \
LM_MODEL=gemma-4-31b-it-mlx \
LM_TIMEOUT_S=180 \
uvicorn app:app --host 0.0.0.0 --port "$BRIDGE_PORT" \
  --ssl-certfile "$BRIDGE_SSL_CERTFILE" \
  --ssl-keyfile "$BRIDGE_SSL_KEYFILE"
```

Make sure LM Studio's local server is **Running** with the model loaded (you've been here — the toggle next to "Status: Running").

---

## Smoke test

```bash
../tests/e2e/smoke-test.sh
```

This injects 8 fake `Failed password` lines into the agent container's `/var/log/auth.log`, enough to trigger Wazuh's level-10 brute-force rule. The chain you should see:

1. **Agent log** (`docker logs wazuh-llm-agent`):
   `ossec-logcollector: INFO: ... Reading file '/var/log/auth.log'`

2. **Manager processed + integrator triggered**:
   ```bash
   docker exec single-node-wazuh.manager-1 tail -20 /var/ossec/logs/integrations.log
   ```
   Expect lines mentioning `custom-llm-bridge` and rule `5712`.

3. **Bridge stdout** (your `uvicorn` terminal):
   ```
   POST /webhook  HTTP/1.1  202 Accepted
   worker-0 → LM Studio rule=5712 level=10
   worker-0 ← rule=5712 reply='{"severity":"high",...,"action":"Block 203.0.113.45 ..."}'
   ```

4. **(Bonus) Wazuh Dashboard**: open <https://localhost:443> (admin / SecretPassword), go to *Threat Hunting* → *Events*, filter `rule.id: 5712`.

---

## Verify each link in isolation

If something's broken, work backwards from the LLM end:

| Check | Command | Expect |
|-------|---------|--------|
| LM Studio reachable | `curl -s http://localhost:1234/v1/models \| python3 -m json.tool` | JSON with the loaded model |
| Bridge healthy | `curl -ks "https://localhost:$BRIDGE_PORT/health"` | `{"status":"ok",...}` |
| Boss dashboard | `open "https://localhost:$BRIDGE_PORT/dashboard"` | management summary page |
| Bridge ↔ LM Studio | `curl -k -X POST "https://localhost:$BRIDGE_PORT/webhook" -H 'Content-Type: application/json' -d '{"rule":{"id":"5712","level":10,"description":"test"},"full_log":"hi"}'` | `202` and an LLM reply in bridge log |
| Manager → bridge from container | `docker exec single-node-wazuh.manager-1 curl -ks -X POST "https://host.docker.internal:$BRIDGE_PORT/webhook" -H 'Content-Type: application/json' -d '{"rule":{"id":"5712","level":10,"description":"test"},"full_log":"hi"}'` | `202` |
| Agent → manager link | `docker exec wazuh-llm-agent /var/ossec/bin/agent_control -l` | `(should be empty)` from agent side; check from manager: `docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l` and look for `wazuh-agent-01` |
| Integrator daemon alive | `docker exec single-node-wazuh.manager-1 ps aux \| grep integrator` | `wazuh-integratord` running |

---

## Troubleshooting

**Indexer container stays stuck `Restarting`**
On Mac, Docker Desktop usually handles `vm.max_map_count` automatically, but on older versions you can hit *"max virtual memory areas vm.max_map_count [65530] is too low"*. Fix:

```bash
docker run --rm --privileged --pid=host alpine \
  nsenter -t 1 -m -u -n -i sysctl -w vm.max_map_count=262144
```

That setting is volatile — re-apply after each Docker Desktop restart, or set it permanently in Docker Desktop → Settings → "Apply at startup" custom command.

**Manager API never reaches `200/401`**
Cert generation race. Re-run:
```bash
( cd wazuh-docker/single-node && docker compose down -v && docker compose -f generate-indexer-certs.yml run --rm generator && docker compose up -d )
```

**Agent never enrolls** (`docker logs wazuh-llm-agent` shows `agent-auth` errors)
Manager isn't ready yet. Wait 60s and `docker compose -f agent/docker-compose.yml restart`.

**Bridge gets nothing despite agent logs showing the brute-force lines**
- Confirm the integrator is mounted: `docker exec single-node-wazuh.manager-1 ls -l /var/ossec/integrations/custom-llm-bridge` (should be executable).
- Confirm `host.docker.internal` resolves from the manager: `docker exec single-node-wazuh.manager-1 getent hosts host.docker.internal`.
- Check the integrator log: `docker exec single-node-wazuh.manager-1 cat /var/ossec/logs/integrations.log`.

---

## Tear down

```bash
./teardown.sh           # stop containers, keep certs (faster re-up)
./teardown.sh --wipe    # also delete cloned wazuh-docker (force fresh certs)
```

---

## What's next

Once the smoke test puts a real LLM-triaged alert in your bridge log, the Wazuh ↔ LLM loop is closed. The next layer is **what to do with the LLM's verdict** — Slack notification, write to SQLite, fire `wazuh_block_ip` active response. That's option **A** from the original menu, which is genuinely useful only after this stack is working.
