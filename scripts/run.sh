#!/usr/bin/env bash
# EdgeSec-Pi unified wrapper.
#
# Captures every step's output into ./logs/ so diagnostics are easy to review
# without copy-pasting terminal output.
#
# Usage:
#   ./run.sh check     # verify prereqs (Docker / LM Studio / port free)
#   ./run.sh setup     # bring up Wazuh stack only
#   ./run.sh bridge    # start the bridge in the background → logs/bridge.log
#   ./run.sh smoke     # fire a fake brute-force + dump diagnostics
#   ./run.sh diag      # just dump current pipeline state
#   ./run.sh dashboard # start the new Next.js dashboard in the background
#   ./run.sh status    # show bridge/dashboard/Wazuh/LLM/MCP state
#   ./run.sh start     # start bridge + dashboard
#   ./run.sh restart   # stop then start bridge + dashboard
#   ./run.sh up        # check + setup + bridge + dashboard
#   ./run.sh           # = up && smoke   (the full happy path)
#   ./run.sh stop      # stop bridge + dashboard only
#   ./run.sh down      # stop bridge + dashboard + teardown Wazuh + remove agent

set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOGS="$DIR/logs"
mkdir -p "$LOGS"

# ── Load unified config (bridge.env) from project root ──────────────
# shellcheck disable=SC1091
source "$DIR/lib/load-config.sh"

ROOT="$EDGESEC_ROOT"
WAZUH_STACK="$EDGESEC_WAZUH_STACK_DIR"
DASHBOARD_DIR="$EDGESEC_DASHBOARD_DIR"
BRIDGE_DIR="$EDGESEC_BRIDGE_DIR"

if [[ "$BRIDGE_SCHEME" == "https" && ( -z "${BRIDGE_SSL_CERTFILE:-}" || -z "${BRIDGE_SSL_KEYFILE:-}" ) ]]; then
  printf "\033[1;31m[x]\033[0m set both BRIDGE_SSL_CERTFILE and BRIDGE_SSL_KEYFILE, or neither\n"
  exit 1
fi

c_log() { printf "\033[1;36m[%s]\033[0m %s\n" "$(date '+%H:%M:%S')" "$*"; }
c_ok()  { printf "\033[1;32m[✓]\033[0m %s\n" "$*"; }
c_err() { printf "\033[1;31m[x]\033[0m %s\n" "$*"; }
c_warn() { printf "\033[1;33m[!]\033[0m %s\n" "$*"; }

pid_alive() {
  local pid="$1"
  [[ -n "$pid" ]] && ps -p "$pid" >/dev/null 2>&1
}

read_pid_file() {
  local file="$1"
  [[ -f "$file" ]] && tr -d '[:space:]' < "$file"
}

listen_pids() {
  local port="$1"
  lsof -nP -tiTCP:"$port" -sTCP:LISTEN 2>/dev/null || true
}

describe_port() {
  local port="$1"
  lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null || true
}

stop_pid_file() {
  local name="$1"
  local pid_file="$2"
  local port="${3:-}"
  local pid
  pid="$(read_pid_file "$pid_file")"

  if pid_alive "$pid"; then
    c_log "stopping $name pid=$pid"
    kill "$pid" 2>/dev/null || true
    sleep 1
    if pid_alive "$pid"; then
      c_warn "$name pid=$pid did not stop gracefully; sending TERM again"
      kill "$pid" 2>/dev/null || true
      sleep 1
    fi
  elif [[ -n "$pid" ]]; then
    c_warn "$name pid file was stale (pid=$pid)"
  fi
  rm -f "$pid_file"

  if [[ -n "$port" ]]; then
    local port_pids
    port_pids="$(listen_pids "$port")"
    if [[ -n "$port_pids" ]]; then
      c_warn "$name port $port is still occupied; stopping listener(s): $(echo "$port_pids" | tr '\n' ' ')"
      echo "$port_pids" | while read -r p; do
        [[ -n "$p" ]] && kill "$p" 2>/dev/null || true
      done
      sleep 1
    fi
  fi
}

stop_screen_session() {
  local session="$1"
  if command -v screen >/dev/null 2>&1 && screen -ls 2>/dev/null | grep -q "[.]$session[[:space:]]"; then
    screen -S "$session" -X quit 2>/dev/null || true
    sleep 1
  fi
}

start_detached_service() {
  local session="$1"
  local service_cmd="$2"
  if command -v screen >/dev/null 2>&1; then
    stop_screen_session "$session"
    screen -dmS "$session" "$0" "$service_cmd"
  else
    nohup "$0" "$service_cmd" >/dev/null 2>&1 &
  fi
}

cmd_serve_bridge() {
  ensure_bridge_https || exit $?
  cd "$BRIDGE_DIR"
  LM_STUDIO_URL="$LM_STUDIO_URL" \
  LM_MODEL="$LM_MODEL" \
  LM_TIMEOUT_S="$LM_TIMEOUT_S" \
  BRIDGE_BIND_HOST="$BRIDGE_BIND_HOST" \
  DASHBOARD_V2_URL="$DASHBOARD_V2_URL" \
  exec python3 -m uvicorn app:app --host "$BRIDGE_BIND_HOST" --port "$BRIDGE_PORT" "${BRIDGE_SSL_ARGS[@]}" \
    > "$LOGS/bridge.log" 2>&1
}

cmd_serve_dashboard() {
  cd "$DASHBOARD_DIR"
  local node_extra_ca=""
  local node_options="${NODE_OPTIONS:-}"
  local node_tls_reject="${NODE_TLS_REJECT_UNAUTHORIZED:-}"
  if [[ "$BRIDGE_SCHEME" == "https" && -f "$DIR/certs/ca.crt" ]]; then
    node_extra_ca="$DIR/certs/ca.crt"
    node_options="$node_options --use-system-ca"
    # Next.js dev rewrites run inside Node. Local self-signed certs are valid
    # for browser testing but may still fail Node's proxy verification.
    node_tls_reject="${node_tls_reject:-0}"
  fi
  DASHBOARD_PORT="$DASHBOARD_PORT" \
  BRIDGE_API_BASE="$BRIDGE_LOCAL_BASE" \
  NEXT_PUBLIC_BRIDGE_API_BASE="" \
  NODE_EXTRA_CA_CERTS="$node_extra_ca" \
  NODE_OPTIONS="$node_options" \
  NODE_TLS_REJECT_UNAUTHORIZED="$node_tls_reject" \
  exec npm run dev -- --hostname "$DASHBOARD_BIND_HOST" --port "$DASHBOARD_PORT" \
    > "$LOGS/dashboard.log" 2>&1
}

service_status_line() {
  local name="$1"
  local url="$2"
  local port="$3"
  local pid_file="$4"
  local pid
  pid="$(read_pid_file "$pid_file")"

  if curl -ksS -m 3 "$url" >/dev/null 2>&1; then
    if pid_alive "$pid"; then
      c_ok "$name responding at $url (pid $pid)"
    else
      local port_pids
      port_pids="$(listen_pids "$port" | tr '\n' ' ')"
      c_warn "$name responding at $url, but pid file is stale; listener pid(s): ${port_pids:-unknown}"
    fi
  else
    if [[ -n "$(listen_pids "$port")" ]]; then
      c_warn "$name port $port is occupied but $url is not healthy"
      describe_port "$port"
    else
      c_err "$name not running at $url"
    fi
  fi
}

bridge_exposes_network() {
  [[ "$BRIDGE_BIND_HOST" == "0.0.0.0" || "$BRIDGE_BIND_HOST" == "::" || "$BRIDGE_BIND_HOST" == "[::]" ]]
}

ensure_bridge_security() {
  local webhook_secret="${WEBHOOK_SECRET:-}"
  local placeholder_secret=false
  [[ "$webhook_secret" == "replace-with-a-long-random-secret" ]] && placeholder_secret=true
  if bridge_exposes_network && [[ ( -z "$webhook_secret" || "$placeholder_secret" == "true" ) && "${EDGESEC_ALLOW_UNAUTH_WEBHOOK:-}" != "1" ]]; then
    c_err "refusing to start bridge on $BRIDGE_BIND_HOST without WEBHOOK_SECRET"
    c_err "Set a real random WEBHOOK_SECRET in wazuh-llm-bridge/.env, then restart."
    c_err "For a private lab only, override with EDGESEC_ALLOW_UNAUTH_WEBHOOK=1."
    return 1
  fi
  if bridge_exposes_network && [[ "${EDGESEC_ALLOW_UNAUTH_WEBHOOK:-}" == "1" ]]; then
    c_warn "bridge is exposed on $BRIDGE_BIND_HOST and webhook auth is explicitly disabled"
  fi
}

ensure_bridge_https() {
  [[ "$BRIDGE_SCHEME" == "https" ]] || return 0

  if ! (cd "$BRIDGE_DIR" && [[ -f "$BRIDGE_SSL_CERTFILE" && -f "$BRIDGE_SSL_KEYFILE" ]]); then
    c_log "HTTPS certificate missing; generating local EdgeSec-Pi certificate → logs/https.log"
    "$DIR/setup-local-https.sh" > "$LOGS/https.log" 2>&1
    local rc=$?
    if [[ $rc -ne 0 ]]; then
      c_err "HTTPS certificate generation failed — see logs/https.log"
      return $rc
    fi
  fi

  if [[ "$(uname)" == "Darwin" ]]; then
    if [[ "${EDGESEC_TRUST_LOCAL_CA:-}" == "1" ]]; then
      c_log "trusting EdgeSec-Pi Local CA for this macOS user → logs/https.log"
      "$DIR/setup-local-https.sh" --trust >> "$LOGS/https.log" 2>&1
    elif security dump-trust-settings 2>/dev/null | grep -q "EdgeSec-Pi Local CA"; then
      c_ok "EdgeSec-Pi Local CA already trusted for this macOS user"
    else
      c_warn "HTTPS uses a local CA. If the browser says the certificate is untrusted, run:"
      c_warn "  EDGESEC_TRUST_LOCAL_CA=1 $0 bridge"
    fi
  fi
}

# ─── check ────────────────────────────────────────────────────────────────
cmd_check() {
  c_log "writing prereq check → logs/check.log"
  {
    echo "════ check @ $(date) ════"
    echo
    echo "── docker daemon ──"
    docker info --format '{{.ServerVersion}}' 2>&1 || echo "DOCKER DAEMON NOT RUNNING"
    echo
    echo "── docker compose v2 ──"
    docker compose version 2>&1 || echo "COMPOSE V2 MISSING"
    echo
    echo "── LM Studio models endpoint ($LM_STUDIO_MODELS_URL) ──"
    curl -sS -m 5 "$LM_STUDIO_MODELS_URL" 2>&1 \
      | python3 -m json.tool 2>&1 | head -40 \
      || echo "LM STUDIO NOT REACHABLE at $LM_STUDIO_MODELS_URL"
    echo
    echo "── target model present? ($LM_MODEL) ──"
    curl -sS -m 5 "$LM_STUDIO_MODELS_URL" 2>/dev/null \
      | python3 -c "import sys,json; target=sys.argv[1]; d=json.load(sys.stdin); ids=[m['id'] for m in d.get('data',[])]; print('\n'.join(ids)); print('FOUND' if target in ids else 'NOT FOUND — fix LM_MODEL or load it in LM Studio')" "$LM_MODEL" 2>&1
    echo
    echo "── port $BRIDGE_PORT free? ──"
    lsof -nP -i:"$BRIDGE_PORT" 2>&1 | head -5 || echo "(free)"
    echo
    echo "── bridge source present ──"
    ls "$BRIDGE_DIR/app.py" 2>&1 || echo "BRIDGE NOT FOUND at $BRIDGE_DIR"
    echo
    echo "── disk free ──"
    df -h "$DIR" 2>&1 | head -3
  } > "$LOGS/check.log" 2>&1
  cat "$LOGS/check.log"
}

# ─── setup (Wazuh stack) ─────────────────────────────────────────────────
cmd_setup() {
  c_log "running setup.sh → logs/setup.log (this can take 5-10 min on first run)"
  "$WAZUH_STACK/setup.sh" > "$LOGS/setup.log" 2>&1
  local rc=$?
  if [[ $rc -eq 0 ]]; then
    c_ok "setup done"
  else
    c_err "setup failed (exit $rc) — see logs/setup.log"
  fi
  return $rc
}

# ─── bridge (background) ─────────────────────────────────────────────────
cmd_bridge() {
  ensure_bridge_https || return $?
  ensure_bridge_security || return $?
  if curl -ksS -m 3 "$BRIDGE_SCHEME://127.0.0.1:$BRIDGE_PORT/health" 2>/dev/null | grep -q '"status":"ok"'; then
    local pid
    pid="$(listen_pids "$BRIDGE_PORT" | head -1)"
    [[ -n "$pid" ]] && echo "$pid" > "$LOGS/bridge.pid"
    c_ok "bridge already responding on $BRIDGE_SCHEME://127.0.0.1:$BRIDGE_PORT${pid:+ (pid $pid)}"
    return 0
  fi
  if [[ -n "$(listen_pids "$BRIDGE_PORT")" ]]; then
    c_err "bridge port $BRIDGE_PORT is occupied, but /health is not responding"
    describe_port "$BRIDGE_PORT"
    c_err "Run: $0 stop"
    return 1
  fi
  c_log "starting bridge in background → logs/bridge.log (model=$LM_MODEL)"
  start_detached_service "edgesec-bridge" "_serve_bridge"
  sleep 3
  if curl -ksS -m 3 "$BRIDGE_SCHEME://127.0.0.1:$BRIDGE_PORT/health" 2>/dev/null | grep -q '"status":"ok"'; then
    local pid
    pid="$(listen_pids "$BRIDGE_PORT" | head -1)"
    [[ -n "$pid" ]] && echo "$pid" > "$LOGS/bridge.pid"
    c_ok "bridge up${pid:+ (pid $pid)}"
  else
    c_err "bridge didn't pass /health — see logs/bridge.log"
    return 1
  fi
}

cmd_stop_bridge() {
  stop_screen_session "edgesec-bridge"
  stop_pid_file "bridge" "$LOGS/bridge.pid" "$BRIDGE_PORT"
}

cmd_dashboard() {
  if [[ ! -f "$DASHBOARD_DIR/package.json" ]]; then
    c_err "dashboard source not found at $DASHBOARD_DIR"
    return 1
  fi
  if curl -sS -m 3 "http://127.0.0.1:$DASHBOARD_PORT" >/dev/null 2>&1; then
    local pid
    pid="$(listen_pids "$DASHBOARD_PORT" | head -1)"
    [[ -n "$pid" ]] && echo "$pid" > "$LOGS/dashboard.pid"
    c_ok "dashboard already responding on http://127.0.0.1:$DASHBOARD_PORT${pid:+ (pid $pid)}"
    return 0
  fi
  if [[ -n "$(listen_pids "$DASHBOARD_PORT")" ]]; then
    c_err "dashboard port $DASHBOARD_PORT is occupied, but the dashboard is not responding"
    describe_port "$DASHBOARD_PORT"
    c_err "Run: $0 stop"
    return 1
  fi
  c_log "starting dashboard in background → logs/dashboard.log"
  start_detached_service "edgesec-dashboard" "_serve_dashboard"
  sleep 3
  if curl -sS -m 3 "http://127.0.0.1:$DASHBOARD_PORT" >/dev/null 2>&1; then
    local pid
    pid="$(listen_pids "$DASHBOARD_PORT" | head -1)"
    [[ -n "$pid" ]] && echo "$pid" > "$LOGS/dashboard.pid"
    c_ok "dashboard up${pid:+ (pid $pid)}"
  else
    c_err "dashboard didn't pass startup check — see logs/dashboard.log"
    return 1
  fi
}

cmd_stop_dashboard() {
  stop_screen_session "edgesec-dashboard"
  stop_pid_file "dashboard" "$LOGS/dashboard.pid" "$DASHBOARD_PORT"
}

cmd_start() {
  cmd_bridge && cmd_dashboard
}

cmd_stop() {
  cmd_stop_dashboard
  cmd_stop_bridge
}

cmd_restart() {
  cmd_stop
  cmd_start
}

cmd_status() {
  c_log "EdgeSec-Pi service status"
  service_status_line "bridge" "$BRIDGE_SCHEME://127.0.0.1:$BRIDGE_PORT/health" "$BRIDGE_PORT" "$LOGS/bridge.pid"
  service_status_line "dashboard" "http://127.0.0.1:$DASHBOARD_PORT" "$DASHBOARD_PORT" "$LOGS/dashboard.pid"

  if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^single-node-wazuh.manager-1$'; then
    c_ok "Wazuh manager container is running"
  else
    c_warn "Wazuh manager container not found"
  fi

  if curl -sS -m 3 "$LM_STUDIO_MODELS_URL" >/dev/null 2>&1; then
    c_ok "LM Studio responding at $LM_STUDIO_MODELS_URL"
  else
    c_warn "LM Studio not responding at $LM_STUDIO_MODELS_URL"
  fi

  if curl -sS -m 3 "$MCP_SERVER_URL/health" >/dev/null 2>&1 || curl -sS -m 3 "$MCP_SERVER_URL" >/dev/null 2>&1; then
    c_ok "MCP endpoint responding at $MCP_SERVER_URL"
  else
    c_warn "MCP endpoint not responding at $MCP_SERVER_URL"
  fi
}

# ─── smoke test + diagnostics ────────────────────────────────────────────
default_smoke_ip() {
  local seed
  seed="$(date +%s)"
  printf '203.0.113.%d\n' "$(( (seed + $$) % 200 + 20 ))"
}

verify_smoke_alert() {
  local smoke_ip="$1"
  local rule_id="${2:-5701}"
  local timeout_s="${SMOKE_VERIFY_TIMEOUT_S:-180}"
  local deadline=$((SECONDS + timeout_s))
  local manager_ok=false
  local db_row=""

  c_log "verifying smoke alert rule $rule_id for source IP $smoke_ip"
  while (( SECONDS < deadline )); do
    if docker exec single-node-wazuh.manager-1 sh -c "grep -F '$smoke_ip' /var/ossec/logs/alerts/alerts.json | grep -q '\"id\":\"$rule_id\"'" >/dev/null 2>&1; then
      manager_ok=true
      break
    fi
    sleep 2
  done

  if [[ "$manager_ok" != "true" ]]; then
    c_err "Wazuh did not emit rule $rule_id for $smoke_ip within ${timeout_s}s"
    return 1
  fi
  c_ok "Wazuh emitted rule $rule_id for $smoke_ip"

  if ! command -v sqlite3 >/dev/null 2>&1; then
    c_warn "sqlite3 not found; skipping bridge DB smoke verification"
    return 0
  fi

  deadline=$((SECONDS + timeout_s))
  while (( SECONDS < deadline )); do
    db_row="$(sqlite3 "$BRIDGE_DIR/data/alerts.db" "SELECT id || '|' || llm_status FROM alerts WHERE rule_id='$rule_id' AND raw_alert LIKE '%$smoke_ip%' ORDER BY id DESC LIMIT 1;" 2>/dev/null || true)"
    if [[ -n "$db_row" ]]; then
      c_ok "bridge stored smoke alert id/status: $db_row"
      return 0
    fi
    sleep 2
  done

  c_err "bridge did not store rule $rule_id for $smoke_ip within ${timeout_s}s"
  return 1
}

cmd_smoke() {
  local smoke_ip="${SMOKE_SOURCE_IP:-$(default_smoke_ip)}"
  local smoke_count="${SMOKE_ATTEMPTS:-8}"
  local smoke_rule_id="${SMOKE_RULE_ID:-5701}"
  if [[ "${SMOKE_MODE:-probe}" == "bruteforce" && -z "${SMOKE_RULE_ID:-}" ]]; then
    smoke_rule_id="5712"
  fi
  c_log "firing smoke test ($smoke_ip) → logs/smoke.log"
  "$ROOT/tests/e2e/smoke-test.sh" "$smoke_ip" "$smoke_count" > "$LOGS/smoke.log" 2>&1
  c_log "waiting 10s for the chain to settle (agent → manager → integrator → bridge → LM Studio)"
  sleep 10
  cmd_diag
  verify_smoke_alert "$smoke_ip" "$smoke_rule_id" || return $?
  c_ok "smoke done — see logs/diag.log"
}

# ─── diag ────────────────────────────────────────────────────────────────
cmd_diag() {
  c_log "dumping diagnostic → logs/diag.log"
  {
    echo "════════════════════ DIAG @ $(date) ════════════════════"
    echo
    echo "── docker ps ──"
    docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' 2>&1
    echo
    echo "── bridge /health ──"
    curl -ksS -m 3 "$BRIDGE_SCHEME://localhost:$BRIDGE_PORT/health" 2>&1; echo
    echo
    echo "── bridge tail (last 60 lines) ──"
    tail -60 "$LOGS/bridge.log" 2>&1 || echo "(no bridge.log)"
    echo
    echo "── manager: script perms inside container ──"
    docker exec single-node-wazuh.manager-1 ls -la /var/ossec/integrations/ 2>&1
    echo
    echo "── manager: integrations.log (full file) ──"
    docker exec single-node-wazuh.manager-1 cat /var/ossec/logs/integrations.log 2>&1
    echo
    echo "── manager: alerts.json (last 5 alerts, decoded) ──"
    docker exec single-node-wazuh.manager-1 tail -5 /var/ossec/logs/alerts/alerts.json 2>&1
    echo
    echo "── manager: ossec.log (last 30, only errors and rule fires) ──"
    docker exec single-node-wazuh.manager-1 sh -c "grep -E 'ERROR|integratord|rule|5712|5710|5763' /var/ossec/logs/ossec.log | tail -30" 2>&1
    echo
    echo "── agent: docker logs (last 30) ──"
    docker logs --tail 30 wazuh-llm-agent 2>&1
    echo
    echo "── agent enrolment status (from manager) ──"
    docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l 2>&1
    echo
    echo "── network: host.docker.internal resolves from manager? ──"
    docker exec single-node-wazuh.manager-1 getent hosts host.docker.internal 2>&1
    echo
    echo "════════════════════ END ════════════════════"
  } > "$LOGS/diag.log" 2>&1
  c_ok "diag $(wc -l < "$LOGS/diag.log") lines → logs/diag.log"
}

cmd_down() {
  cmd_stop
  c_log "tearing down Wazuh stack → logs/teardown.log"
  "$WAZUH_STACK/teardown.sh" > "$LOGS/teardown.log" 2>&1
  c_ok "down"
}

# ─── dispatch ────────────────────────────────────────────────────────────
case "${1:-default}" in
  _serve_bridge) cmd_serve_bridge ;;
  _serve_dashboard) cmd_serve_dashboard ;;
  config) edgesec_print_config ;;
  check)  cmd_check ;;
  setup)  cmd_setup ;;
  bridge) cmd_bridge ;;
  dashboard) cmd_dashboard ;;
  smoke)  cmd_smoke ;;
  diag)   cmd_diag ;;
  status) cmd_status ;;
  start)  cmd_start ;;
  stop)   cmd_stop ;;
  restart) cmd_restart ;;
  down)   cmd_down ;;
  up)     cmd_check && cmd_setup && cmd_start ;;
  default|all)
          cmd_check && cmd_setup && cmd_start && cmd_smoke ;;
  *)      cat <<EOF
usage: $0 {config|check|setup|bridge|dashboard|start|stop|restart|status|smoke|diag|up|down|all}
  config  print unified port and service URL config
  check   prereq audit (Docker, LM Studio, port, bridge source)
  setup   bring up Wazuh stack only
  bridge  start bridge in background → logs/bridge.log
  dashboard start Next.js dashboard in background → logs/dashboard.log
  start   start bridge + dashboard
  stop    stop bridge + dashboard
  restart stop then start bridge + dashboard
  status  show service status and stale PID/port issues
  smoke   fire fake brute-force + dump diag
  diag    just dump current state → logs/diag.log
  up      check + setup + bridge + dashboard   (do this once)
  smoke   trigger after up         (rerunnable)
  down    stop bridge + dashboard + tear down stack
  (no arg) = up && smoke (full happy path)

All command outputs land in ./logs/ for troubleshooting.
EOF
          exit 1 ;;
esac
