#!/usr/bin/env bash
# EdgeSec-Pi test runner.
#
# Usage:
#   ./scripts/test.sh              # unit + fake-service integration tests
#   ./scripts/test.sh unit         # config/contracts only
#   ./scripts/test.sh integration  # fake LM Studio / fake MCP tests
#   ./scripts/test.sh model        # real LM Studio model tool-call test
#   ./scripts/test.sh env          # real local service readiness check
#   ./scripts/test.sh e2e          # real Wazuh Docker stack smoke test
#   ./scripts/test.sh manual       # interactive Slack/failure scenario tests
#   ./scripts/test.sh eval-mock    # prompt/eval harness without real LLM
#   ./scripts/test.sh all          # default + model + eval-mock (not e2e/manual)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ -f "$ROOT/bridge.env" ]]; then
  set -a; source "$ROOT/bridge.env"; set +a
fi

need_pytest() {
  python3 - <<'PY' >/dev/null 2>&1 || {
import pytest
PY
    echo "pytest is missing. Install dev dependencies first:" >&2
    echo "  python3 -m pip install -r requirements-dev.txt" >&2
    exit 1
  }
}

run_pytest() {
  need_pytest
  PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python3 -m pytest "$@"
}

ok() { printf "  \033[32m✓\033[0m %s\n" "$*"; }
warn() { printf "  \033[33m!\033[0m %s\n" "$*"; }
fail() { printf "  \033[31mx\033[0m %s\n" "$*"; return 1; }

http_status() {
  curl -ksS --max-time "${2:-5}" -o /dev/null -w "%{http_code}" "$1" 2>/dev/null || true
}

check_http_ok() {
  local label="$1"
  local url="$2"
  local code
  code="$(http_status "$url" 5)"
  if [[ "$code" =~ ^(200|204|301|302|307|308)$ ]]; then
    ok "$label reachable ($code) — $url"
    return 0
  fi
  fail "$label not reachable (HTTP ${code:-none}) — $url"
}

check_lm_studio() {
  local models_url="${LM_STUDIO_MODELS_URL:-${LM_STUDIO_URL%/chat/completions}/models}"
  local payload
  payload="$(curl -ksS --max-time 8 "$models_url" 2>/dev/null || true)"
  if [[ -z "$payload" ]]; then
    fail "LM Studio models endpoint not reachable — $models_url"
    return 1
  fi

  local model_check
  model_check="$(printf '%s' "$payload" | python3 -c '
import json
import sys

target = sys.argv[1]
data = json.load(sys.stdin)
ids = [str(item.get("id", "")) for item in data.get("data", [])]
if not ids:
    print("NO_MODELS")
elif target in ids or target == "local-model":
    print("FOUND")
else:
    print("MISSING:" + ",".join(ids[:10]))
' "$LM_MODEL" 2>/dev/null || true)"

  case "$model_check" in
    FOUND)
      ok "LM Studio reachable and target model is available ($LM_MODEL)"
      ;;
    NO_MODELS)
      fail "LM Studio reachable but no models are listed — $models_url"
      return 1
      ;;
    MISSING:*)
      warn "LM Studio reachable, but LM_MODEL='$LM_MODEL' was not in /v1/models"
      warn "available models: ${model_check#MISSING:}"
      ;;
    *)
      fail "LM Studio returned non-OpenAI-compatible /models JSON — $models_url"
      return 1
      ;;
  esac
}

check_env() {
  local failures=0

  BRIDGE_PORT="${BRIDGE_PORT:-8001}"
  BRIDGE_PUBLIC_URL="${BRIDGE_PUBLIC_URL:-http://localhost:$BRIDGE_PORT}"
  BRIDGE_LOCAL_URL="http://localhost:$BRIDGE_PORT"
  if [[ "$BRIDGE_PUBLIC_URL" == https://* || -n "${BRIDGE_SSL_CERTFILE:-}" || -n "${BRIDGE_SSL_KEYFILE:-}" ]]; then
    BRIDGE_LOCAL_URL="https://localhost:$BRIDGE_PORT"
  fi
  LM_STUDIO_URL="${LM_STUDIO_URL:-http://localhost:1234/v1/chat/completions}"
  LM_MODEL="${LM_MODEL:-local-model}"
  WAZUH_API_URL="${WAZUH_API_URL:-https://localhost:55000}"
  MCP_SERVER_URL="${MCP_SERVER_URL:-}"

  echo "EdgeSec-Pi local environment readiness"
  echo

  if [[ -f "$ROOT/bridge.env" ]]; then
    ok "bridge.env loaded"
  else
    warn "bridge.env missing; using built-in defaults"
  fi

  check_http_ok "Bridge health" "$BRIDGE_LOCAL_URL/health" || failures=$((failures + 1))
  check_http_ok "Dashboard" "$BRIDGE_LOCAL_URL/dashboard" || failures=$((failures + 1))
  check_http_ok "FastAPI docs" "$BRIDGE_LOCAL_URL/docs" || failures=$((failures + 1))
  check_lm_studio || failures=$((failures + 1))

  local wazuh_code
  wazuh_code="$(http_status "${WAZUH_API_URL%/}/" 5)"
  if [[ "$wazuh_code" =~ ^(200|401)$ ]]; then
    ok "Wazuh API reachable ($wazuh_code) — ${WAZUH_API_URL%/}/"
  else
    warn "Wazuh API not reachable or not running (HTTP ${wazuh_code:-none}) — ${WAZUH_API_URL%/}/"
  fi

  if [[ -n "$MCP_SERVER_URL" ]]; then
    local mcp_code
    mcp_code="$(http_status "${MCP_SERVER_URL%/}/health" 5)"
    if [[ "$mcp_code" =~ ^(200|204)$ ]]; then
      ok "MCP server reachable ($mcp_code) — ${MCP_SERVER_URL%/}/health"
    else
      warn "MCP server configured but not reachable (HTTP ${mcp_code:-none}) — ${MCP_SERVER_URL%/}/health"
    fi
  else
    warn "MCP_SERVER_URL is unset; MCP enrichment is disabled"
  fi

  echo
  if [[ "$failures" -eq 0 ]]; then
    ok "environment readiness passed"
    return 0
  fi
  fail "environment readiness failed with $failures required check(s)"
}

case "${1:-default}" in
  default|ci)
    run_pytest -m "unit or integration" tests/unit tests/integration
    ;;
  unit)
    run_pytest -m unit tests/unit
    ;;
  integration)
    run_pytest -m integration tests/integration
    ;;
  model)
    RUN_MODEL_TESTS=1 run_pytest -m model tests/model
    ;;
  env)
    check_env
    ;;
  e2e)
    tests/e2e/smoke-test.sh
    ;;
  manual)
    echo "Manual scenario test:"
    echo "  tests/manual/test_scenarios.sh"
    echo
    echo "Manual failure-mode test:"
    echo "  tests/manual/test_failures.sh"
    echo
    echo "Run one directly when bridge, LM Studio, Wazuh, and Slack are ready."
    ;;
  eval-mock)
    ( cd wazuh-llm-bridge/eval && python3 eval.py --mode mock )
    ;;
  eval-live)
    ( cd wazuh-llm-bridge/eval && python3 eval.py --mode live )
    ;;
  all)
    run_pytest -m "unit or integration" tests/unit tests/integration
    RUN_MODEL_TESTS=1 run_pytest -m model tests/model
    ( cd wazuh-llm-bridge/eval && python3 eval.py --mode mock )
    ;;
  *)
    echo "unknown test target: $1" >&2
    echo "valid targets: default, unit, integration, model, env, e2e, manual, eval-mock, eval-live, all" >&2
    exit 2
    ;;
esac
