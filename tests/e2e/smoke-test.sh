#!/usr/bin/env bash
# Inject N fake "Failed password" lines into the agent container's auth.log.
# The Wazuh agent monitors /var/log/auth.log by default, ships the events
# to the manager, where rule 5712 fires after 8 attempts and the integrator
# triggers our bridge because the rule is level 10.
#
# Usage:
#   ./smoke-test.sh                        # default 8 attempts from 203.0.113.45
#   ./smoke-test.sh 198.51.100.42 10       # 10 attempts from that IP

set -euo pipefail

TARGET_IP="${1:-203.0.113.45}"
COUNT="${2:-8}"
AGENT="${AGENT_CONTAINER:-wazuh-llm-agent}"

if ! docker ps --format '{{.Names}}' | grep -q "^${AGENT}$"; then
  echo "✗ container '$AGENT' not running. Run ./setup.sh first." >&2
  exit 1
fi

echo "→ injecting $COUNT failed-login lines (source IP $TARGET_IP) into $AGENT"
for i in $(seq 1 "$COUNT"); do
  # LC_ALL=C forces English month abbreviations (May/Jun/Jul…). Without this,
  # macOS users with non-English locales get e.g. "5月" which Wazuh's sshd
  # decoder cannot parse — the decoder silently drops the line, no rule fires,
  # no alert reaches the integrator, and the whole chain looks broken for
  # reasons that don't show up in any log.
  STAMP="$(LC_ALL=C date '+%b %_d %H:%M:%S')"
  PORT="$((55500 + i))"
  docker exec "$AGENT" sh -c \
    "echo '$STAMP wazuh-agent-01 sshd[1234]: Failed password for invalid user admin from $TARGET_IP port $PORT ssh2' >> /var/log/auth.log"
  printf "  attempt %d/%s\n" "$i" "$COUNT"
  sleep 0.4
done

cat <<EOF

✓ injected. Now check the chain:

  1. Manager processed it and called the integrator:
     docker exec single-node-wazuh.manager-1 tail -20 /var/ossec/logs/integrations.log

  2. Bridge received the alert and queued it (look in your uvicorn terminal
     for a 'POST /webhook 202 Accepted' line).

  3. Worker called LM Studio and logged the response:
     look for 'worker-0 ← rule=5712 reply=...' in the bridge stdout.

  4. (Optional) See the alert in the Wazuh dashboard:
     https://localhost:443  →  Threat Hunting → Search 'rule.id:5712'

EOF
