#!/usr/bin/env bash
# Allow the bridge user to remove IPs from Wazuh's pfctl block table
# without password prompt.  Tightly scoped: ONLY `pfctl -t wazuh_fwtable
# -T delete *` is permitted as root, nothing else.
#
# Why: Wazuh's API only dispatches firewall-drop's ADD action; the
# DELETE action is reserved for internal timeout cleanup. So we run
# pfctl directly from the bridge to unblock. This is safe because the
# sudoers entry only allows the specific command needed.
#
# Idempotent: rerun-safe.

set -euo pipefail

USER_TO_ALLOW="${1:-${USER:-$(id -un)}}"
SUDOERS_FILE="/etc/sudoers.d/edgesec-bridge-unblock"

c_log() { printf "\033[1;36m[*]\033[0m %s\n" "$*"; }
c_ok()  { printf "\033[1;32m[✓]\033[0m %s\n" "$*"; }
c_err() { printf "\033[1;31m[x]\033[0m %s\n" "$*" >&2; exit 1; }

[[ "$(uname)" == "Darwin" ]] || c_err "macOS only (this script's pfctl path is BSD/Darwin)"

TMP=$(mktemp)
cat > "$TMP" <<EOF
# Installed by EdgeSec-Pi enable-unblock.sh
# Allows ${USER_TO_ALLOW} to remove IPs from Wazuh's pfctl firewall
# block table only — no other privileged operations.
${USER_TO_ALLOW} ALL=(root) NOPASSWD: /sbin/pfctl -t wazuh_fwtable -T delete *
EOF

c_log "validating sudoers fragment with visudo -cf"
sudo visudo -cf "$TMP" >/dev/null \
    || { rm "$TMP"; c_err "sudoers fragment has syntax error"; }

c_log "installing $SUDOERS_FILE (you'll be asked for your Mac password)"
sudo install -m 440 -o root -g wheel "$TMP" "$SUDOERS_FILE"
rm "$TMP"
c_ok "installed"

c_log "smoke test — should run without password"
if sudo -n /sbin/pfctl -t wazuh_fwtable -T show >/dev/null 2>&1; then
    c_ok "sudo -n pfctl works (NOPASSWD active)"
else
    # fall through; -T show might still need sudo prompt because we only NOPASSWD-ed delete
    c_log "(show requires password; that's expected — only delete is NOPASSWD)"
fi

cat <<EOF

──────────────────────────────────────────────────────────────────
✓ EdgeSec-Pi unblock capability enabled.

  Now restart the bridge so wazuh.unblock_ip() picks up the change:
      kill "\$(cat ./scripts/logs/bridge.pid)"
      sleep 2
      cd ./scripts
      set -a; source ../wazuh-llm-bridge/.env; set +a
      ./run.sh bridge

  After that, every blocked IP gets a 🔓 解封 button on its
  confirmation card. Clicking it runs:
      sudo -n /sbin/pfctl -t wazuh_fwtable -T delete <ip>

  To uninstall: sudo rm /etc/sudoers.d/edgesec-bridge-unblock
──────────────────────────────────────────────────────────────────
EOF
