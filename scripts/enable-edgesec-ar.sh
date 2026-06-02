#!/usr/bin/env bash
# Register EdgeSec-Pi isolate/release commands in the Wazuh manager config.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib/load-config.sh"

MANAGER_CT="single-node-wazuh.manager-1"
CONF_HOST_PATH="$SCRIPT_DIR/../wazuh-stack/wazuh-docker/single-node/config/wazuh_cluster/wazuh_manager.conf"

c_log() { printf "\033[1;36m[%s]\033[0m %s\n" "$(date '+%H:%M:%S')" "$*"; }
c_ok()  { printf "\033[1;32m[✓]\033[0m %s\n" "$*"; }
c_err() { printf "\033[1;31m[x]\033[0m %s\n" "$*"; exit 1; }

[[ -f "$CONF_HOST_PATH" ]] || c_err "manager config not found at $CONF_HOST_PATH"
docker ps --format '{{.Names}}' | grep -q "^${MANAGER_CT}$" \
  || c_err "manager container not running"

if grep -q '<name>edgesec-isolate</name>' "$CONF_HOST_PATH" \
  && grep -q '<name>edgesec-release-isolate</name>' "$CONF_HOST_PATH"; then
  c_log "edgesec-ar commands already configured, skipping"
else
  c_log "injecting edgesec-ar command blocks"
  python3 - "$CONF_HOST_PATH" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
content = path.read_text()
block = """
  <!-- Added by EdgeSec-Pi enable-edgesec-ar.sh.
       Requires matching scripts on each target agent:
       active-response/bin/edgesec-isolate
       active-response/bin/edgesec-release-isolate -->
  <command>
    <name>edgesec-isolate</name>
    <executable>edgesec-isolate</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>edgesec-release-isolate</name>
    <executable>edgesec-release-isolate</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

"""
if "<name>edgesec-isolate</name>" in content:
    block = block.replace(
        """  <command>
    <name>edgesec-isolate</name>
    <executable>edgesec-isolate</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

""",
        "",
    )
if "<name>edgesec-release-isolate</name>" in content:
    block = block.replace(
        """  <command>
    <name>edgesec-release-isolate</name>
    <executable>edgesec-release-isolate</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

""",
        "",
    )
new = content.replace("</ossec_config>", block + "</ossec_config>", 1)
if new == content:
    sys.exit("could not find </ossec_config> in manager config")
path.write_text(new)
PY
  c_ok "manager config updated"
fi

c_log "restarting manager to load command blocks (~30s)"
docker compose -f "$SCRIPT_DIR/../wazuh-stack/wazuh-docker/single-node/docker-compose.yml" \
  restart wazuh.manager >/dev/null
sleep 30

c_log "waiting for Wazuh API to come back online"
for i in $(seq 1 30); do
  if curl -ks -o /dev/null -w "%{http_code}" "$WAZUH_API_URL/" | grep -qE '^(200|401)$'; then
    c_ok "manager API up"
    break
  fi
  sleep 2
  [[ $i -eq 30 ]] && c_err "manager API did not come back; check docker logs $MANAGER_CT"
done

c_ok "registered commands: edgesec-isolate0 / edgesec-release-isolate0"
