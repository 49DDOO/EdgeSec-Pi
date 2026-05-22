#!/usr/bin/env bash
# Install the Wazuh agent NATIVELY on this macOS host (not in Docker) and
# point it at the local manager (the one running in our docker compose).
#
# After this completes, every real event on your Mac — sudo commands,
# ssh logins, file integrity changes, software installs — flows through:
#   Mac (agent) → Wazuh manager → integratord → bridge → Gemma → Slack
#
# Usage:  sudo ./install-mac-agent.sh
#         (or just ./install-mac-agent.sh; it'll prompt for your password)
#
# Re-run safe: detects an existing install and only re-configures.

set -euo pipefail

# ── Load unified config (bridge.env) ──────────────
_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_BRIDGE_ENV="$_SCRIPT_DIR/../bridge.env"
if [[ -f "$_BRIDGE_ENV" ]]; then
  set -a; source "$_BRIDGE_ENV"; set +a
fi
BRIDGE_PORT="${BRIDGE_PORT:-8001}"


WAZUH_VERSION="${WAZUH_VERSION:-4.14.5}"
MANAGER_HOST="${MANAGER_HOST:-localhost}"  # docker manager exposes :1514/1515
WAZUH_AGENT_PORT="${WAZUH_AGENT_PORT:-1514}"
WAZUH_AUTHD_PORT="${WAZUH_AUTHD_PORT:-1515}"
ARCH="$(uname -m)"
case "$ARCH" in
  arm64)  PKG_ARCH=arm64    ;;  # Apple Silicon (M1/M2/M3/M4)
  x86_64) PKG_ARCH=intel64  ;;  # Intel
  *) echo "unsupported arch: $ARCH"; exit 1 ;;
esac

PKG="wazuh-agent-${WAZUH_VERSION}-1.${PKG_ARCH}.pkg"
URL="https://packages.wazuh.com/4.x/macos/${PKG}"
TMP="/tmp/${PKG}"
OSSEC_DIR="/Library/Ossec"

c_log() { printf "\033[1;36m[%s]\033[0m %s\n" "$(date '+%H:%M:%S')" "$*"; }
c_ok()  { printf "\033[1;32m[✓]\033[0m %s\n" "$*"; }
c_err() { printf "\033[1;31m[x]\033[0m %s\n" "$*" >&2; exit 1; }

# ── Sanity ───────────────────────────────────────────────────────────────
[[ "$(uname)" == "Darwin" ]] || c_err "This script only runs on macOS. For Linux, use 'apt-get install wazuh-agent'."

# Confirm the manager is actually reachable before we install.
nc -z -G 2 "$MANAGER_HOST" "$WAZUH_AGENT_PORT" 2>/dev/null \
  || c_err "manager not reachable at $MANAGER_HOST:$WAZUH_AGENT_PORT — did you run ../wazuh-stack/setup.sh first?"

# ── 1. Download .pkg ──────────────────────────────────────────────────────
if [[ -f "$TMP" ]] && [[ -s "$TMP" ]]; then
  c_log "found cached pkg at $TMP, skipping download"
else
  c_log "downloading $URL"
  curl -fSL --progress-bar -o "$TMP" "$URL" || c_err "download failed"
fi
c_ok "package: $(ls -lh "$TMP" | awk '{print $5}') at $TMP"

# ── 2. Install (or skip if already installed) ─────────────────────────────
if [[ -d "$OSSEC_DIR" ]]; then
  c_log "Wazuh agent already installed at $OSSEC_DIR — re-configuring"
else
  c_log "installing pkg (you'll be asked for your Mac password)"
  c_log "macOS may pop up 'Wazuh Agent wants to install' — click Allow"
  sudo /usr/sbin/installer -pkg "$TMP" -target / \
    || c_err "pkg install failed"
fi
c_ok "agent installed at $OSSEC_DIR"

# ── 3. Configure manager address in ossec.conf ─────────────────────────────
c_log "pointing agent at manager → $MANAGER_HOST:$WAZUH_AGENT_PORT"
sudo cp "$OSSEC_DIR/etc/ossec.conf" "$OSSEC_DIR/etc/ossec.conf.bak.$(date +%s)" 2>/dev/null || true

# Replace the placeholder MANAGER_IP (or any prior value) with our manager
sudo sed -i '' \
  -e "s|<address>.*</address>|<address>${MANAGER_HOST}</address>|" \
  -e "s|<port>.*</port>|<port>${WAZUH_AGENT_PORT}</port>|" \
  "$OSSEC_DIR/etc/ossec.conf"
c_ok "ossec.conf updated"

# ── 4. Stop agent if running, re-enrol with manager, start ────────────────
c_log "stopping agent if running…"
sudo "$OSSEC_DIR/bin/wazuh-control" stop 2>/dev/null || true

c_log "enroling with manager (using authd on :$WAZUH_AUTHD_PORT)…"
sudo "$OSSEC_DIR/bin/agent-auth" -m "$MANAGER_HOST" -p "$WAZUH_AUTHD_PORT" \
  || c_err "enrolment failed — check manager logs ('docker logs single-node-wazuh.manager-1')"
c_ok "enrolled"

c_log "starting agent…"
sudo "$OSSEC_DIR/bin/wazuh-control" start
sleep 4

# ── 5. Verify ────────────────────────────────────────────────────────────
c_log "verifying agent is in manager's roster…"
docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l \
  | grep -E "Mac|$(hostname)|Active" || true

cat <<'EOF'

──────────────────────────────────────────────────────────────────
✓ Done. Your Mac is now a Wazuh agent reporting to the local manager.

To produce a real test event, open a Terminal and run:

    sudo whoami

Within ~10 seconds you should:

  1. See it in alerts.json:
       docker exec single-node-wazuh.manager-1 \
         tail -3 /var/ossec/logs/alerts/alerts.json

  2. Get a Slack notification with Gemma's Chinese triage:
       (check the Slack channel where you set up the webhook)

  3. Find it in the bridge's SQLite history:
       curl -ks "https://localhost:$BRIDGE_PORT/alerts?limit=3" | python3 -m json.tool

If macOS pops up a "Wazuh Agent wants Full Disk Access" prompt,
allow it — that's how the agent reads /var/log/* for sudo/auth events.

To uninstall later:
    sudo /Library/Ossec/uninstall.sh   # (provided by Wazuh's pkg)
──────────────────────────────────────────────────────────────────
EOF
