#!/usr/bin/env bash
# Enable proper sudo auditing on this macOS host.
#
# macOS Tahoe doesn't write the human-readable sudo format to system.log
# anymore — only USER_PROCESS / DEAD_PROCESS stubs. Apple moved everything
# to unified log, but unified log only has libsystem internal traces, no
# "user X ran command Y" semantics.
#
# Workaround: enable sudo's *own* logfile (a feature of OpenBSD sudo that
# Apple ships), have the Wazuh agent monitor that file, and add a custom
# decoder + rule on the manager so the new format is parsed and a rule
# fires at level 9 — passing our integration filter and triggering Slack.
#
# Idempotent: rerun-safe.

set -euo pipefail

# ── Load unified config (bridge.env) ──────────────
_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$_SCRIPT_DIR/lib/load-config.sh"

OSSEC_CONF="/Library/Ossec/etc/ossec.conf"
SUDO_LOG="/var/log/sudo.log"
SUDOERS_FILE="/etc/sudoers.d/wazuh-monitoring"
MANAGER_CT="single-node-wazuh.manager-1"

c_log() { printf "\033[1;36m[%s]\033[0m %s\n" "$(date '+%H:%M:%S')" "$*"; }
c_ok()  { printf "\033[1;32m[✓]\033[0m %s\n" "$*"; }
c_err() { printf "\033[1;31m[x]\033[0m %s\n" "$*"; exit 1; }

# ── Sanity ────────────────────────────────────────────────────────────────
[[ "$(uname)" == "Darwin" ]]      || c_err "macOS only"
[[ -d /Library/Ossec ]]            || c_err "Wazuh agent not found at /Library/Ossec"
docker ps --format '{{.Names}}' | grep -q "^${MANAGER_CT}$" \
                                   || c_err "manager container '$MANAGER_CT' not running"

# ── 1. /etc/sudoers.d entry — make sudo write its own log ─────────────────
c_log "step 1/4 — installing sudoers fragment to enable /var/log/sudo.log"
TMPFILE=$(mktemp)
cat > "$TMPFILE" <<'EOF'
# Installed by EdgeSec-Pi enable-mac-sudo-audit.sh
# Makes sudo write each invocation in the classic format Wazuh can parse.
Defaults logfile=/var/log/sudo.log
EOF
# Validate BEFORE installing — a syntax error in sudoers can lock you out.
sudo visudo -cf "$TMPFILE" >/dev/null \
    || { rm "$TMPFILE"; c_err "sudoers fragment has syntax error — aborting"; }
sudo install -m 440 -o root -g wheel "$TMPFILE" "$SUDOERS_FILE"
rm "$TMPFILE"
c_ok "sudoers fragment installed at $SUDOERS_FILE"

# Pre-create the log file with sane perms so sudo (root) can write it
sudo touch "$SUDO_LOG"
sudo chmod 600 "$SUDO_LOG"
sudo chown root:wheel "$SUDO_LOG"
c_ok "$SUDO_LOG ready"

# ── 2. Mac agent ossec.conf — monitor /var/log/sudo.log ───────────────────
c_log "step 2/4 — adding localfile entry to agent ossec.conf"
if grep -q "${SUDO_LOG}" "$OSSEC_CONF" 2>/dev/null; then
    c_ok "agent ossec.conf already monitors $SUDO_LOG, skipping"
else
    sudo tee -a "$OSSEC_CONF" > /dev/null <<EOF

<ossec_config>
  <localfile>
    <log_format>syslog</log_format>
    <location>${SUDO_LOG}</location>
  </localfile>
</ossec_config>
EOF
    c_ok "added /var/log/sudo.log monitoring to agent config"
fi

# ── 3. Manager — custom decoder + rule ────────────────────────────────────
c_log "step 3/4 — installing custom decoder + rule on manager"

# 3a. Decoder
docker exec "$MANAGER_CT" bash -c '
DEC=/var/ossec/etc/decoders/local_decoder.xml
mkdir -p "$(dirname $DEC)"
[ -f "$DEC" ] || echo "<!-- local decoders -->" > "$DEC"
if ! grep -q "sudo-mac-logfile" "$DEC"; then
cat >> "$DEC" <<EOF

<!-- macOS sudo logfile parser. Format produced by /etc/sudoers.d/wazuh-monitoring:
       May 10 18:30:15 : alice : TTY=ttys001 ; PWD=/Users/alice ; USER=root ; COMMAND=/usr/bin/whoami
-->
<decoder name="sudo-mac-logfile">
  <prematch>: \S+ : TTY=\S+ ; PWD=\S+ ; USER=\S+ ; COMMAND=</prematch>
</decoder>

<decoder name="sudo-mac-logfile">
  <parent>sudo-mac-logfile</parent>
  <regex>: (\S+) : TTY=(\S+) ; PWD=(\S+) ; USER=(\S+) ; COMMAND=(.+)$</regex>
  <order>srcuser,tty,pwd,dstuser,command</order>
</decoder>
EOF
echo "  decoder installed"
else
echo "  decoder already present"
fi
'

# 3b. Rule
docker exec "$MANAGER_CT" bash -c '
RULE=/var/ossec/etc/rules/local_rules.xml
[ -f "$RULE" ] || echo "<!-- local rules -->" > "$RULE"
if ! grep -q "id=\"100200\"" "$RULE"; then
cat >> "$RULE" <<EOF

<group name="syslog,sudo,local,">
  <rule id="100200" level="9">
    <decoded_as>sudo-mac-logfile</decoded_as>
    <description>macOS sudo: $(srcuser) ran $(command) as $(dstuser)</description>
    <group>authentication_success,</group>
    <mitre>
      <id>T1078</id>
    </mitre>
  </rule>
</group>
EOF
echo "  rule 100200 installed"
else
echo "  rule 100200 already present"
fi
'
c_ok "decoder + rule deployed in manager"

# ── 4. Restart everything to load new config ──────────────────────────────
c_log "step 4/4 — restarting Mac agent + Wazuh manager"

sudo /Library/Ossec/bin/wazuh-control restart >/dev/null
c_ok "Mac agent restarted"

docker compose -f "$_SCRIPT_DIR/../wazuh-stack/wazuh-docker/single-node/docker-compose.yml" \
    restart wazuh.manager >/dev/null 2>&1
c_log "waiting 25s for manager to come back online…"
sleep 25
c_ok "manager restarted"

# ── 5. Live test ──────────────────────────────────────────────────────────
echo
c_log "Live test: running 'sudo whoami' (should fire rule 100200 → Slack)…"
sudo whoami
echo "  waiting 12s for the chain (agent → manager → integrator → bridge → Gemma → Slack)…"
sleep 12

echo
c_log "── /var/log/sudo.log (last 3 lines) ──"
sudo tail -3 "$SUDO_LOG" 2>/dev/null || echo "(empty — sudo didn't write yet)"

echo
c_log "── manager alerts.json (last 3) ──"
docker exec "$MANAGER_CT" tail -3 /var/ossec/logs/alerts/alerts.json 2>/dev/null \
  | python3 -c "
import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try:
        a = json.loads(line)
        rule = a.get('rule', {})
        print(f\"  rule={rule.get('id','?'):8s}  level={rule.get('level','?'):2}  agent={a.get('agent',{}).get('name','?')[:25]:25s}  {rule.get('description','')[:80]}\")
    except: pass
"

echo
c_log "── bridge most recent alerts ──"
curl -s "http://localhost:$BRIDGE_PORT/alerts?limit=3" | python3 -c "
import sys, json, datetime
rows = json.load(sys.stdin)
for r in rows:
    ts = datetime.datetime.fromtimestamp(r['received_at']).strftime('%H:%M:%S')
    print(f\"  {ts}  rule={r['rule_id']}  sev={r.get('llm_severity','-')}  {r.get('rule_description','')[:60]}\")
"

cat <<'EOF'

──────────────────────────────────────────────────────────────────
✓ Setup done. From now on, every `sudo <command>` you run on this Mac
  will:
    1. be appended to /var/log/sudo.log (in classic syslog format)
    2. be picked up by the Wazuh agent's logcollector
    3. be parsed by the new sudo-mac-logfile decoder on the manager
    4. fire rule 100200 at level 9
    5. be forwarded to the bridge, triaged by Gemma, and posted to Slack

  Slack should have a fresh 「警示」card from the test sudo above.

  To undo:
    sudo rm /etc/sudoers.d/wazuh-monitoring
    # then restart agent / manager
──────────────────────────────────────────────────────────────────
EOF
