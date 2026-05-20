#!/usr/bin/env bash
#
# wazuh-stack/agent-groups/setup-agent-groups.sh
#
# ┌────────────────────────────────────────────────────────────────┐
# │  OPTIONAL — NOT REQUIRED FOR EDGESEC-PI TO WORK                │
# │                                                                │
# │  EdgeSec-Pi (the LLM bridge) consumes whatever alerts Wazuh    │
# │  produces. Wazuh's per-OS installer ships with sensible        │
# │  defaults that are sufficient for the bridge to function.      │
# │                                                                │
# │  This script is a recipe for tuning Wazuh to collect MORE      │
# │  log sources via centralized group configuration. Run it only  │
# │  if you want the additions (see README.md for the list).       │
# └────────────────────────────────────────────────────────────────┘
#
# Bootstraps Wazuh's centralized agent-groups configuration.
#
# What it does (all idempotent — safe to re-run):
#   1. Creates groups: macos, linux, windows  (default already exists)
#   2. Copies each per-OS agent.conf into the manager's shared/ folder
#   3. Discovers currently enrolled agents and assigns them to the
#      matching OS group based on a name heuristic
#   4. Restarts the wazuh-manager process so the merged.mg gets rebuilt
#      and agents pull on next ping
#   5. Prints group membership + verification commands
#
# Prerequisites:
#   - Wazuh stack already running (./setup.sh)
#   - Manager container reachable as `single-node-wazuh.manager-1`
#

set -euo pipefail

# ── Constants ────────────────────────────────────────────────────────
MANAGER="single-node-wazuh.manager-1"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Pretty printers ──────────────────────────────────────────────────
log()  { echo;        echo "▶ $*"; }
ok()   { echo "  ✓ $*"; }
warn() { echo "  ⚠ $*"; }
fail() { echo "  ✗ $*"; exit 1; }

manager() { docker exec "$MANAGER" "$@"; }

# ── Pre-flight ───────────────────────────────────────────────────────
log "Pre-flight: checking manager container is up"
if ! docker ps --format '{{.Names}}' | grep -q "^${MANAGER}\$"; then
  fail "Manager container '$MANAGER' not running. Bring stack up first: cd .. && ./setup.sh"
fi
ok "manager container '$MANAGER' is up"

for f in default/agent.conf macos/agent.conf linux/agent.conf windows/agent.conf; do
  [[ -f "$HERE/$f" ]] || fail "missing $HERE/$f"
done
ok "all 4 agent.conf source files present"

# ── Step 1: Create the 3 non-default groups (idempotent) ─────────────
log "Step 1/5 — Creating agent groups"
EXISTING_GROUPS="$(manager /var/ossec/bin/agent_groups -l 2>/dev/null || true)"
for g in macos linux windows; do
  if echo "$EXISTING_GROUPS" | grep -qE "^\s*${g}\s|\s${g}\s|\s${g}\$"; then
    ok "group '$g' already exists"
  else
    # -q skips the interactive confirmation prompt
    manager /var/ossec/bin/agent_groups -a -g "$g" -q >/dev/null
    ok "group '$g' created"
  fi
  # Fix perms: agent_groups -a creates the dir as 700, but agents need
  # group-read access (default dir is 2770). Set it explicitly.
  manager chown wazuh:wazuh "/var/ossec/etc/shared/$g" 2>/dev/null || true
  manager chmod 2770       "/var/ossec/etc/shared/$g" 2>/dev/null || true
done

# ── Step 2: Push agent.conf into each group's shared/ directory ──────
log "Step 2/5 — Pushing agent.conf to each group"
for g in default macos linux windows; do
  src="$HERE/$g/agent.conf"
  dst="/var/ossec/etc/shared/$g/agent.conf"
  docker cp "$src" "${MANAGER}:${dst}"
  manager chown wazuh:wazuh "$dst"
  manager chmod 660 "$dst"
  ok "$g/agent.conf  →  $dst"
done

# ── Step 3: Discover enrolled agents and assign by OS heuristic ──────
log "Step 3/5 — Discovering enrolled agents"

# `agent_control -lc` lists active agents in `id name ip` columns
agents_raw="$(manager /var/ossec/bin/agent_control -lc 2>/dev/null || true)"
echo "$agents_raw"

# Pull (id, name) pairs. The output looks like:
#    ID: 001, Name: wazuh-llm-agent, IP: 172.18.0.5, Active/Local
#    ID: 002, Name: office-macbook, IP: 192.168.1.20, Active/Local
parse_ids_named() {
  # $1 = regex of names to MATCH (case-insensitive)
  echo "$agents_raw" \
    | grep -iE "$1" \
    | grep -oE 'ID:[[:space:]]*[0-9]+' \
    | grep -oE '[0-9]+' \
    || true
}

mac_ids="$(parse_ids_named 'darwin|mac|studio|imac|macbook')"
# `wazuh-agent` (singular) is the default name on the Linux container we ship,
# so include it explicitly even though it doesn't say "linux" anywhere.
linux_ids="$(parse_ids_named 'ubuntu|debian|centos|fedora|llm-agent|wazuh-agent|alpine|rocky|rhel|kali|arch')"
win_ids="$(parse_ids_named 'windows|win10|win11|win-')"

assign() {
  local id="$1"
  local group="$2"
  if manager /var/ossec/bin/agent_groups -a -i "$id" -g "$group" -q >/dev/null 2>&1; then
    ok "agent $id → group '$group'"
  else
    warn "could not assign agent $id to group '$group' (already there? check with: agent_groups -c -i $id)"
  fi
}

log "Step 3 (cont) — Assigning agents to OS groups"
if [[ -z "$mac_ids$linux_ids$win_ids" ]]; then
  warn "no enrolled agents matched any OS heuristic"
  warn "after enrolling agents, assign manually:  agent_groups -a -i <id> -g <macos|linux|windows>"
else
  for id in $mac_ids;   do assign "$id" macos;   done
  for id in $linux_ids; do assign "$id" linux;   done
  for id in $win_ids;   do assign "$id" windows; done
fi

# ── Step 4: Restart manager so merged.mg rebuilds immediately ────────
log "Step 4/5 — Restarting manager (forces merged.mg rebuild)"
manager /var/ossec/bin/wazuh-control restart >/dev/null
ok "manager restarted"

# Give it a moment to come back
sleep 3

# ── Step 5: Verify ───────────────────────────────────────────────────
log "Step 5/5 — Verification"

echo
echo "── Group list ────────────────────────────────────────────"
manager /var/ossec/bin/agent_groups -l

echo
echo "── shared/ directory layout ──────────────────────────────"
manager ls -la /var/ossec/etc/shared/

echo
echo "── Per-group membership ──────────────────────────────────"
# `agent_groups -l -g <name>` lists agents in a group — more reliable than
# the per-agent inverse query (which doesn't exist on every Wazuh version).
for g in default macos linux windows; do
  members="$(manager /var/ossec/bin/agent_groups -l -g "$g" 2>/dev/null \
              | grep -E '^[[:space:]]*ID:' | tr -d '\n' | sed 's/   */ /g')"
  echo "  $g : ${members:-(empty)}"
done

cat <<'EOF'

═══════════════════════════════════════════════════════════════════
✅ Done. Each agent will auto-pull its merged config within ~10 min.

To force an IMMEDIATE pull, restart the agent on the host:
  macOS:    sudo /Library/Ossec/bin/wazuh-control restart
  Linux:    sudo systemctl restart wazuh-agent
            (or `docker compose -f wazuh-stack/agent/docker-compose.yml restart`)
  Windows:  net stop WazuhSvc && net start WazuhSvc

To verify the merged effective config on an agent:
  Dashboard → Endpoints → click the agent → Configuration tab
  OR on the agent host:
    macOS:   cat /Library/Ossec/etc/shared/merged.mg
    Linux:   cat /var/ossec/etc/shared/merged.mg
    Windows: type "C:\Program Files (x86)\ossec-agent\shared\merged.mg"

Adding new agents later — assign at enrollment time:
  sudo /Library/Ossec/bin/agent-auth -m <manager_ip> -G default,macos
  sudo /var/ossec/bin/agent-auth   -m <manager_ip> -G default,linux
  agent-auth.exe -m <manager_ip> -G default,windows
═══════════════════════════════════════════════════════════════════
EOF
