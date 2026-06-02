#!/usr/bin/env bash
# Verify that a smoke alert reached both Wazuh Manager and the bridge database.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck disable=SC1091
source "$ROOT/scripts/lib/load-config.sh"

SMOKE_IP="${1:?source IP is required}"
RULE_ID="${2:-5701}"
TIMEOUT_S="${SMOKE_VERIFY_TIMEOUT_S:-180}"
BRIDGE_DIR="${EDGESEC_BRIDGE_DIR:-$ROOT/wazuh-llm-bridge}"
MANAGER_CONTAINER="${WAZUH_MANAGER_CONTAINER:-single-node-wazuh.manager-1}"
deadline=$((SECONDS + TIMEOUT_S))
manager_ok=false

echo "verifying Wazuh emitted rule $RULE_ID for $SMOKE_IP"
while (( SECONDS < deadline )); do
  if docker exec "$MANAGER_CONTAINER" sh -c "grep -F '$SMOKE_IP' /var/ossec/logs/alerts/alerts.json | grep -q '\"id\":\"$RULE_ID\"'" >/dev/null 2>&1; then
    manager_ok=true
    break
  fi
  sleep 2
done

if [[ "$manager_ok" != "true" ]]; then
  echo "ERROR: Wazuh did not emit rule $RULE_ID for $SMOKE_IP within ${TIMEOUT_S}s" >&2
  exit 1
fi
echo "OK: Wazuh emitted rule $RULE_ID for $SMOKE_IP"

if ! command -v sqlite3 >/dev/null 2>&1; then
  echo "WARN: sqlite3 not found; skipping bridge DB smoke verification" >&2
  exit 0
fi

deadline=$((SECONDS + TIMEOUT_S))
db_row=""
while (( SECONDS < deadline )); do
  db_row="$(
    sqlite3 "$BRIDGE_DIR/data/alerts.db" \
      "SELECT id || '|' || llm_status FROM alerts WHERE rule_id='$RULE_ID' AND raw_alert LIKE '%$SMOKE_IP%' ORDER BY id DESC LIMIT 1;" \
      2>/dev/null || true
  )"
  if [[ -n "$db_row" ]]; then
    echo "OK: bridge stored smoke alert id/status: $db_row"
    exit 0
  fi
  sleep 2
done

echo "ERROR: bridge did not store rule $RULE_ID for $SMOKE_IP within ${TIMEOUT_S}s" >&2
exit 1
