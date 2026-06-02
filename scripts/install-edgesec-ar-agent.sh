#!/usr/bin/env bash
# Install EdgeSec-Pi isolation/release Active Response scripts on the local
# Linux/macOS Wazuh agent. Run this on each endpoint that should support
# Slack's "隔離端點" button.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SRC_DIR="$ROOT_DIR/wazuh-stack/active-response"

c_log() { printf "\033[1;36m[%s]\033[0m %s\n" "$(date '+%H:%M:%S')" "$*"; }
c_ok()  { printf "\033[1;32m[✓]\033[0m %s\n" "$*"; }
c_err() { printf "\033[1;31m[x]\033[0m %s\n" "$*"; exit 1; }

if [[ "$(uname -s)" == "Darwin" ]]; then
  OSSEC_DIR="${EDGESEC_AR_OSSEC_DIR:-/Library/Ossec}"
else
  OSSEC_DIR="${EDGESEC_AR_OSSEC_DIR:-/var/ossec}"
fi

AR_DIR="$OSSEC_DIR/active-response/bin"
ETC_DIR="$OSSEC_DIR/etc"

[[ -d "$OSSEC_DIR" ]] || c_err "Wazuh agent directory not found: $OSSEC_DIR"
[[ -d "$AR_DIR" ]] || c_err "active-response directory not found: $AR_DIR"

c_log "installing edgesec-ar scripts to $AR_DIR"
sudo install -m 0750 "$SRC_DIR/edgesec-ar.py" "$AR_DIR/edgesec-ar.py"
sudo install -m 0750 "$SRC_DIR/edgesec-isolate" "$AR_DIR/edgesec-isolate"
sudo install -m 0750 "$SRC_DIR/edgesec-release-isolate" "$AR_DIR/edgesec-release-isolate"

CONFIG="$ETC_DIR/edgesec-ar.env"
if [[ ! -f "$CONFIG" ]]; then
  c_log "creating $CONFIG"
  sudo tee "$CONFIG" >/dev/null <<'EOF'
# Extra management CIDRs/IPs to preserve during isolation.
# The script also parses the Wazuh manager address from ossec.conf.
EDGESEC_AR_ALLOW_CIDRS=
EDGESEC_AR_TTL_S=900
# Optional override: linux-iptables, macos-pf, windows-firewall, route-quarantine.
# Leave blank for platform default.
EDGESEC_AR_METHOD=
EOF
  sudo chmod 0640 "$CONFIG" || true
else
  c_log "$CONFIG already exists, leaving it unchanged"
fi

c_ok "installed"
cat <<EOF

Next:
  1. Dry-run on this agent:
     sudo "$AR_DIR/edgesec-isolate" --dry-run --ttl 120 --no-schedule

  2. On the manager host, register the command blocks:
     ./scripts/enable-edgesec-ar.sh

  3. In bridge .env, set:
     WAZUH_ISOLATE_COMMAND=edgesec-isolate0
     WAZUH_RELEASE_ISOLATE_COMMAND=edgesec-release-isolate0
     ACTIVE_RESPONSE_ISOLATION_PRESERVE_CHANNELS_ACK=1
EOF
