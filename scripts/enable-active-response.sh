#!/usr/bin/env bash
# Enable Active Response on the Wazuh manager.
#
# Adds a <command name="firewall-drop"> block to /var/ossec/etc/ossec.conf
# inside the manager container, so the bridge can call the Wazuh API to
# trigger firewall-drop on any agent without needing a rule-bound
# <active-response> declaration first.
#
# This script is idempotent — re-runs are safe.

set -euo pipefail

# ── Load unified config (bridge.env) ──────────────
_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_BRIDGE_ENV="$_SCRIPT_DIR/../bridge.env"
if [[ -f "$_BRIDGE_ENV" ]]; then
  set -a; source "$_BRIDGE_ENV"; set +a
fi
BRIDGE_PORT="${BRIDGE_PORT:-8001}"
WAZUH_API_URL="${WAZUH_API_URL:-https://localhost:55000}"
WAZUH_API_URL="${WAZUH_API_URL%/}"


MANAGER_CT="single-node-wazuh.manager-1"
CONF_HOST_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../wazuh-stack/wazuh-docker/single-node/config/wazuh_cluster/wazuh_manager.conf"

c_log() { printf "\033[1;36m[%s]\033[0m %s\n" "$(date '+%H:%M:%S')" "$*"; }
c_ok()  { printf "\033[1;32m[✓]\033[0m %s\n" "$*"; }
c_err() { printf "\033[1;31m[x]\033[0m %s\n" "$*"; exit 1; }

[[ -f "$CONF_HOST_PATH" ]] || c_err "manager config not found at $CONF_HOST_PATH"
docker ps --format '{{.Names}}' | grep -q "^${MANAGER_CT}$" \
    || c_err "manager container not running"

# Inject <command> block (the canonical firewall-drop is built-in to
# the agent at /var/ossec/active-response/bin/firewall-drop)
if grep -q '<name>firewall-drop</name>' "$CONF_HOST_PATH"; then
    c_log "firewall-drop command already configured, skipping"
else
    c_log "injecting <command> block for firewall-drop"
    python3 - "$CONF_HOST_PATH" <<'PY'
import sys, pathlib
p = pathlib.Path(sys.argv[1])
content = p.read_text()
block = """
  <!-- Added by EdgeSec-Pi enable-active-response.sh — allows bridge to
       trigger firewall blocks via the Wazuh API. -->
  <command>
    <name>firewall-drop</name>
    <executable>firewall-drop</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

"""
new = content.replace("</ossec_config>", block + "</ossec_config>", 1)
if new == content:
    sys.exit("could not find </ossec_config> in manager config")
p.write_text(new)
print("  injected")
PY
    c_ok "manager config updated"
fi

c_log "restarting manager to load new <command> block (~30s)"
docker compose -f "$(dirname "$CONF_HOST_PATH")/../../docker-compose.yml" \
    restart wazuh.manager > /dev/null
sleep 30

# Wait for API
c_log "waiting for Wazuh API to come back online"
for i in $(seq 1 30); do
    if curl -ks -o /dev/null -w "%{http_code}" "$WAZUH_API_URL/" \
       | grep -qE '^(200|401)$'; then
        c_ok "manager API up"
        break
    fi
    sleep 2
    [[ $i -eq 30 ]] && c_err "manager API didn't come back; check 'docker logs $MANAGER_CT'"
done

cat <<EOF

──────────────────────────────────────────────────────────────────
✓ Active Response enabled. The Wazuh API will now accept:

    PUT /active-response  command=firewall-drop0  agents_list=<id>

Test from the bridge end:

  # 1. set the auth token (any random string)
  echo "ACTIVE_RESPONSE_TOKEN=\$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')" \\
      >> ./wazuh-llm-bridge/.env

  # 2. restart bridge to pick it up
  kill "\$(cat ./scripts/logs/bridge.pid)"
  sleep 2
  cd ./scripts
  set -a; source ../wazuh-llm-bridge/.env; set +a
  ./run.sh bridge

  # 3. list agents (verify auth works)
  TOKEN=\$(grep ^ACTIVE_RESPONSE_TOKEN ../wazuh-llm-bridge/.env | cut -d= -f2)
  curl -s -H "Authorization: Bearer \$TOKEN" \\
       http://localhost:$BRIDGE_PORT/active-response/agents | python3 -m json.tool

  # 4. block a test IP on your Mac (agent_id 002 — find yours in step 3)
  curl -s -X POST -H "Authorization: Bearer \$TOKEN" \\
       -H "Content-Type: application/json" \\
       -d '{"agent_id":"002","ip":"203.0.113.99"}' \\
       http://localhost:$BRIDGE_PORT/active-response/block-ip | python3 -m json.tool

  # 5. verify the block landed (on the Mac, that's pfctl)
  sudo pfctl -t blocklist -T show 2>/dev/null \\
      || sudo cat /etc/pf.conf | grep blocklist
──────────────────────────────────────────────────────────────────
EOF
