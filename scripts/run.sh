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
#   ./run.sh up        # check + setup + bridge
#   ./run.sh           # = up && smoke   (the full happy path)
#   ./run.sh down      # stop bridge + teardown Wazuh + remove agent

set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOGS="$DIR/logs"
mkdir -p "$LOGS"

# ── Project root (one level up from scripts/) ────────────────────────
ROOT="$DIR/.."
WAZUH_STACK="$ROOT/wazuh-stack"

# ── Load unified config (bridge.env) from project root ──────────────
_BRIDGE_ENV="$ROOT/bridge.env"
if [[ -f "$_BRIDGE_ENV" ]]; then
  set -a; source "$_BRIDGE_ENV"; set +a
fi

BRIDGE_DIR="$ROOT/wazuh-llm-bridge"
_BRIDGE_DOTENV="$BRIDGE_DIR/.env"
if [[ -f "$_BRIDGE_DOTENV" ]]; then
  set -a; source "$_BRIDGE_DOTENV"; set +a
fi

BRIDGE_PORT="${BRIDGE_PORT:-8001}"
BRIDGE_BIND_HOST="${BRIDGE_BIND_HOST:-0.0.0.0}"
LM_STUDIO_URL="${LM_STUDIO_URL:-http://localhost:1234/v1/chat/completions}"
LM_MODEL="${LM_MODEL:-gemma-4-31b-it-mlx}"
LM_TIMEOUT_S="${LM_TIMEOUT_S:-180}"
LM_STUDIO_MODELS_URL="${LM_STUDIO_MODELS_URL:-${LM_STUDIO_URL%/chat/completions}/models}"
BRIDGE_SCHEME="http"
BRIDGE_SSL_ARGS=()
if [[ -n "${BRIDGE_SSL_CERTFILE:-}" || -n "${BRIDGE_SSL_KEYFILE:-}" ]]; then
  if [[ -z "${BRIDGE_SSL_CERTFILE:-}" || -z "${BRIDGE_SSL_KEYFILE:-}" ]]; then
    printf "\033[1;31m[x]\033[0m set both BRIDGE_SSL_CERTFILE and BRIDGE_SSL_KEYFILE, or neither\n"
    exit 1
  fi
  BRIDGE_SCHEME="https"
  BRIDGE_SSL_ARGS=(--ssl-certfile "$BRIDGE_SSL_CERTFILE" --ssl-keyfile "$BRIDGE_SSL_KEYFILE")
fi

c_log() { printf "\033[1;36m[%s]\033[0m %s\n" "$(date '+%H:%M:%S')" "$*"; }
c_ok()  { printf "\033[1;32m[✓]\033[0m %s\n" "$*"; }
c_err() { printf "\033[1;31m[x]\033[0m %s\n" "$*"; }
c_warn() { printf "\033[1;33m[!]\033[0m %s\n" "$*"; }

bridge_exposes_network() {
  [[ "$BRIDGE_BIND_HOST" == "0.0.0.0" || "$BRIDGE_BIND_HOST" == "::" || "$BRIDGE_BIND_HOST" == "[::]" ]]
}

ensure_bridge_security() {
  if bridge_exposes_network && [[ -z "${WEBHOOK_SECRET:-}" && "${EDGESEC_ALLOW_UNAUTH_WEBHOOK:-}" != "1" ]]; then
    c_err "refusing to start bridge on $BRIDGE_BIND_HOST without WEBHOOK_SECRET"
    c_err "Set WEBHOOK_SECRET in wazuh-llm-bridge/.env, then restart."
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
  if [[ -f "$LOGS/bridge.pid" ]] && kill -0 "$(cat "$LOGS/bridge.pid")" 2>/dev/null; then
    c_log "bridge already running (pid $(cat "$LOGS/bridge.pid"))"
    return 0
  fi
  ensure_bridge_https || return $?
  ensure_bridge_security || return $?
  if curl -ksS -m 3 "$BRIDGE_SCHEME://localhost:$BRIDGE_PORT/health" 2>/dev/null | grep -q '"status":"ok"'; then
    c_ok "bridge already responding on $BRIDGE_SCHEME://localhost:$BRIDGE_PORT"
    return 0
  fi
  c_log "starting bridge in background → logs/bridge.log (model=$LM_MODEL)"
  cd "$BRIDGE_DIR"
  LM_STUDIO_URL="$LM_STUDIO_URL" \
  LM_MODEL="$LM_MODEL" \
  LM_TIMEOUT_S="$LM_TIMEOUT_S" \
  BRIDGE_BIND_HOST="$BRIDGE_BIND_HOST" \
  nohup python3 -m uvicorn app:app --host "$BRIDGE_BIND_HOST" --port "$BRIDGE_PORT" "${BRIDGE_SSL_ARGS[@]}" \
    > "$LOGS/bridge.log" 2>&1 &
  echo $! > "$LOGS/bridge.pid"
  sleep 3
  if curl -ksS -m 3 "$BRIDGE_SCHEME://localhost:$BRIDGE_PORT/health" 2>/dev/null | grep -q '"status":"ok"'; then
    c_ok "bridge up (pid $(cat "$LOGS/bridge.pid"))"
  else
    c_err "bridge didn't pass /health — see logs/bridge.log"
    return 1
  fi
}

cmd_stop_bridge() {
  if [[ -f "$LOGS/bridge.pid" ]]; then
    local pid; pid="$(cat "$LOGS/bridge.pid")"
    if kill "$pid" 2>/dev/null; then c_ok "stopped bridge (pid $pid)"; fi
    rm -f "$LOGS/bridge.pid"
  fi
}

# ─── smoke test + diagnostics ────────────────────────────────────────────
cmd_smoke() {
  c_log "firing smoke test → logs/smoke.log"
  "$ROOT/tests/e2e/smoke-test.sh" > "$LOGS/smoke.log" 2>&1
  c_log "waiting 10s for the chain to settle (agent → manager → integrator → bridge → LM Studio)"
  sleep 10
  cmd_diag
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
  cmd_stop_bridge
  c_log "tearing down Wazuh stack → logs/teardown.log"
  "$WAZUH_STACK/teardown.sh" > "$LOGS/teardown.log" 2>&1
  c_ok "down"
}

# ─── dispatch ────────────────────────────────────────────────────────────
case "${1:-default}" in
  check)  cmd_check ;;
  setup)  cmd_setup ;;
  bridge) cmd_bridge ;;
  smoke)  cmd_smoke ;;
  diag)   cmd_diag ;;
  down)   cmd_down ;;
  up)     cmd_check && cmd_setup && cmd_bridge ;;
  default|all)
          cmd_check && cmd_setup && cmd_bridge && cmd_smoke ;;
  *)      cat <<EOF
usage: $0 {check|setup|bridge|smoke|diag|up|down|all}
  check   prereq audit (Docker, LM Studio, port, bridge source)
  setup   bring up Wazuh stack only
  bridge  start bridge in background → logs/bridge.log
  smoke   fire fake brute-force + dump diag
  diag    just dump current state → logs/diag.log
  up      check + setup + bridge   (do this once)
  smoke   trigger after up         (rerunnable)
  down    stop bridge + tear down stack
  (no arg) = up && smoke (full happy path)

All command outputs land in ./logs/ for troubleshooting.
EOF
          exit 1 ;;
esac
