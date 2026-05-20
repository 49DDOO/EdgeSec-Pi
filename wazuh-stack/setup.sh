#!/usr/bin/env bash
# EdgeSec-Pi → Wazuh single-node bring-up.
#
#   1. Clones wazuh/wazuh-docker (single-node compose)
#   2. Injects our <integration> block into the manager's ossec.conf
#   3. Drops the custom-llm-bridge integrator script into the right path
#   4. Adds a volume mount so the manager container can see the script
#   5. Generates Wazuh's self-signed certs (one-time)
#   6. Brings up Indexer + Manager + Dashboard
#   7. Builds + starts our Ubuntu agent container, attached to Wazuh's network
#
# After this completes, run tests/e2e/smoke-test.sh to fire a fake brute force and verify
# the alert flows all the way through to the bridge.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
DIR="$(pwd)"

# ── 0. Load unified config (bridge.env) from project root ──────────────
_BRIDGE_ENV="$DIR/../bridge.env"
if [[ -f "$_BRIDGE_ENV" ]]; then
  set -a; source "$_BRIDGE_ENV"; set +a
fi
_BRIDGE_APP_ENV="$DIR/../wazuh-llm-bridge/.env"
if [[ -f "$_BRIDGE_APP_ENV" ]]; then
  set -a; source "$_BRIDGE_APP_ENV"; set +a
fi
BRIDGE_PORT="${BRIDGE_PORT:-8001}"
export BRIDGE_PORT
WEBHOOK_SECRET="${WEBHOOK_SECRET:-}"
WAZUH_API_URL="${WAZUH_API_URL:-https://localhost:55000}"
WAZUH_API_URL="${WAZUH_API_URL%/}"

WAZUH_VERSION="${WAZUH_VERSION:-v4.14.5}"  # must match the agent .deb version installed by apt
COMPOSE_DIR="$DIR/wazuh-docker/single-node"

log()  { printf "\033[1;36m[*]\033[0m %s\n" "$*"; }
ok()   { printf "\033[1;32m[✓]\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m[!]\033[0m %s\n" "$*"; }
err()  { printf "\033[1;31m[x]\033[0m %s\n" "$*" >&2; exit 1; }

# ── 1. Prereqs ──────────────────────────────────────────────────────────
for c in docker git python3 curl; do command -v "$c" >/dev/null || err "missing: $c"; done
docker compose version >/dev/null || err "need docker compose v2"
ok "prereqs ok"

# ── 2. Clone Wazuh single-node ──────────────────────────────────────────
if [[ ! -d wazuh-docker ]]; then
  log "cloning wazuh/wazuh-docker $WAZUH_VERSION"
  git clone --depth 1 -b "$WAZUH_VERSION" https://github.com/wazuh/wazuh-docker.git
fi

# ── 3. Inject our integration into ossec.conf ───────────────────────────
CONF="$COMPOSE_DIR/config/wazuh_cluster/wazuh_manager.conf"
[[ -f "$CONF" ]] || err "missing $CONF — wazuh-docker layout changed?"

# Generate the integration block from template, substituting BRIDGE_PORT and
# WEBHOOK_SECRET. Re-apply it on every setup run so bridge.env / bridge .env
# remain the single source of truth even after config changes.
_INTEGRATION_XML="$DIR/customizations/ossec-integration.xml"
_INTEGRATION_TMP=$(mktemp)
if [[ -z "$WEBHOOK_SECRET" ]]; then
  warn "WEBHOOK_SECRET is empty; Wazuh webhook will be unauthenticated"
  WEBHOOK_SECRET="-"
fi
python3 - "$_INTEGRATION_XML" "$_INTEGRATION_TMP" <<'PY'
import os
import pathlib
import sys

src = pathlib.Path(sys.argv[1])
dst = pathlib.Path(sys.argv[2])
text = src.read_text()
text = text.replace("{{BRIDGE_PORT}}", os.environ.get("BRIDGE_PORT", "8001"))
text = text.replace("{{WEBHOOK_SECRET}}", os.environ.get("WEBHOOK_SECRET", "-"))
dst.write_text(text)
PY
python3 - "$CONF" "$_INTEGRATION_TMP" <<'PY'
import re
import sys
import pathlib

conf_path = pathlib.Path(sys.argv[1])
block = pathlib.Path(sys.argv[2]).read_text()
conf = conf_path.read_text()

pattern = re.compile(
    r"\s*<integration>\s*<name>custom-llm-bridge</name>.*?</integration>\s*",
    re.DOTALL,
)

if pattern.search(conf):
    patched = pattern.sub("\n" + block + "\n", conf, count=1)
    action = "integration block updated"
else:
    patched = conf.replace("</ossec_config>", block + "</ossec_config>", 1)
    if patched == conf:
        sys.exit("could not find </ossec_config> in manager config")
    action = "integration block injected"

conf_path.write_text(patched)
print(action)
PY
rm -f "$_INTEGRATION_TMP"
ok "ossec.conf bridge integration points to https://host.docker.internal:$BRIDGE_PORT"

# ── 4. Stage the integrator script (will be docker-cp'd into the manager
#       AFTER it boots — see step 9 below).
#
# Why not bind-mount? Docker Desktop on macOS virtualises file modes via
# osxfs/virtiofs and sometimes adds invisible setuid/setgid bits that the
# host can't `chmod` away. Wazuh's `wpopenv()` rejects the script with
# "has write permissions" in that case. Putting the script directly into
# the wazuh_integrations Docker volume sidesteps the issue entirely.
mkdir -p "$COMPOSE_DIR/config/integrations"
cp "$DIR/customizations/custom-llm-bridge" "$COMPOSE_DIR/config/integrations/"
chmod 750 "$COMPOSE_DIR/config/integrations/custom-llm-bridge"
ok "integrator script staged (will be docker-cp'd post-startup)"

# ── 5. (Removed) volume mount block ─────────────────────────────────────
# The bind-mount approach was unreliable on macOS Docker Desktop.
# We now docker-cp the script into the running manager container in step 9.
# If a previous run of this script left the bind-mount line in
# docker-compose.yml, strip it out so we don't re-introduce the bug.
DC="$COMPOSE_DIR/docker-compose.yml"
if grep -q "config/integrations/custom-llm-bridge" "$DC"; then
  sed -i.bak '/config\/integrations\/custom-llm-bridge:/d' "$DC"
  ok "removed stale bind-mount line from docker-compose.yml"
fi

# ── 6. Generate certs (one-time) ────────────────────────────────────────
if [[ ! -f "$COMPOSE_DIR/config/wazuh_indexer_ssl_certs/root-ca.pem" ]]; then
  log "generating Wazuh self-signed certs"
  ( cd "$COMPOSE_DIR" && docker compose -f generate-indexer-certs.yml run --rm generator )
  ok "certs generated"
fi

# ── 7. Bring up the stack ──────────────────────────────────────────────
log "starting Wazuh stack (Indexer → Manager → Dashboard)"
( cd "$COMPOSE_DIR" && docker compose up -d )

log "waiting for Wazuh Manager API at $WAZUH_API_URL (60-180s typical first run)"
for i in $(seq 1 90); do
  if curl -ks -o /dev/null -w "%{http_code}" "$WAZUH_API_URL/" | grep -qE "^(200|401)$"; then
    ok "manager API reachable"
    break
  fi
  sleep 2
  [[ $i -eq 90 ]] && warn "manager API not responding after 180s — check 'docker logs single-node-wazuh.manager-1'"
done

# ── 8. docker-cp the integrator script into the manager (bypasses the
#       macOS bind-mount permission virtualisation gotcha) ─────────────
log "installing integrator script into manager via docker cp"
docker cp "$DIR/customizations/custom-llm-bridge" \
          single-node-wazuh.manager-1:/var/ossec/integrations/custom-llm-bridge
docker exec single-node-wazuh.manager-1 chown root:wazuh /var/ossec/integrations/custom-llm-bridge
docker exec single-node-wazuh.manager-1 chmod 750 /var/ossec/integrations/custom-llm-bridge
ok "integrator script installed inside manager container"

# ── 9. Agent ───────────────────────────────────────────────────────────
log "building + starting Ubuntu agent"
docker compose -f "$DIR/agent/docker-compose.yml" up -d --build

# ── 9. Hint ────────────────────────────────────────────────────────────
cat <<EOF

──────────────────────────────────────────────────────────────────
✓ Wazuh stack up.
  Dashboard:  https://localhost:443    (admin / SecretPassword)
  Manager API: $WAZUH_API_URL
  Agent:       wazuh-llm-agent  (auto-enrolling, watch with 'docker logs -f wazuh-llm-agent')

⚠ Don't forget to start the bridge in another terminal:

    cd ../wazuh-llm-bridge
    LM_STUDIO_URL=http://localhost:1234/v1/chat/completions \\
    LM_MODEL=gemma-4-31b-it-mlx \\
    uvicorn app:app --host 0.0.0.0 --port $BRIDGE_PORT

Then trigger an alert:

    ../tests/e2e/smoke-test.sh

──────────────────────────────────────────────────────────────────
EOF
