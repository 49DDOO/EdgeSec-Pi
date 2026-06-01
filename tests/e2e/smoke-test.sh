#!/usr/bin/env bash
# Inject a deterministic fake sshd scan line into the agent container's auth.log.
# The Wazuh agent monitors /var/log/auth.log, ships the event to the manager,
# where rule 5701 fires at level 8 and the integrator triggers our bridge.
#
# Usage:
#   ./smoke-test.sh                        # default scan from a fresh TEST-NET-3 IP
#   ./smoke-test.sh 198.51.100.42          # scan from that IP
#   SMOKE_MODE=bruteforce ./smoke-test.sh 198.51.100.42 10

set -euo pipefail

DEFAULT_OCTET="$(( ( $(date +%s) + $$ ) % 200 + 20 ))"
TARGET_IP="${1:-${SMOKE_SOURCE_IP:-203.0.113.$DEFAULT_OCTET}}"
COUNT="${2:-${SMOKE_ATTEMPTS:-8}}"
AGENT="${AGENT_CONTAINER:-wazuh-llm-agent}"
MODE="${SMOKE_MODE:-probe}"

if ! docker ps --format '{{.Names}}' | grep -q "^${AGENT}$"; then
  echo "✗ container '$AGENT' not running. Run ./setup.sh first." >&2
  exit 1
fi

if [[ "$MODE" == "bruteforce" ]]; then
  echo "→ injecting $COUNT failed-login lines (source IP $TARGET_IP) into $AGENT"
  for i in $(seq 1 "$COUNT"); do
    # LC_ALL=C forces English month abbreviations (May/Jun/Jul…). Without this,
    # macOS users with non-English locales get e.g. "5月" which Wazuh's sshd
    # decoder cannot parse — the decoder silently drops the line.
    STAMP="$(LC_ALL=C date '+%b %_d %H:%M:%S')"
    PORT="$((55500 + i))"
    docker exec "$AGENT" sh -c \
      "echo '$STAMP wazuh-agent-01 sshd[1234]: Failed password for invalid user admin from $TARGET_IP port $PORT ssh2' >> /var/log/auth.log"
    printf "  attempt %d/%s\n" "$i" "$COUNT"
    sleep 0.4
  done
else
  STAMP="$(LC_ALL=C date '+%b %_d %H:%M:%S')"
  echo "→ injecting one sshd version-probe line (source IP $TARGET_IP) into $AGENT"
  docker exec "$AGENT" sh -c \
    "echo \"$STAMP wazuh-agent-01 sshd[1234]: Bad protocol version identification 'GET / HTTP/1.1' from $TARGET_IP port 55555\" >> /var/log/auth.log"
fi

cat <<EOF

✓ injected. Now check the chain:

  1. Manager processed it and called the integrator:
     docker exec single-node-wazuh.manager-1 tail -20 /var/ossec/logs/integrations.log

  2. Bridge received the alert and queued it (look in your uvicorn terminal
     for a 'POST /webhook 202 Accepted' line).

  3. Worker called LM Studio and logged the response.

  4. (Optional) See the alert in the Wazuh dashboard:
     https://localhost:443  →  Threat Hunting → Search 'rule.id:5701'

EOF
