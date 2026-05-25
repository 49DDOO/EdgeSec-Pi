#!/usr/bin/env bash
# EdgeSec-Pi system test batch runner.
#
# Usage:
#   ./test_sys/run_all.sh              # quick: backend + frontend checks, no real services
#   ./test_sys/run_all.sh quick        # same as default
#   ./test_sys/run_all.sh env          # real local service readiness check
#   ./test_sys/run_all.sh release      # quick + quality gate + mock eval
#   ./test_sys/run_all.sh full         # release + env + real model + e2e
#
# Logs:
#   test_sys/logs/<timestamp>/*.log

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-quick}"
RUN_ID="$(date '+%Y%m%d-%H%M%S')"
LOG_DIR="$ROOT/test_sys/logs/$RUN_ID"
SUMMARY_FILE="$LOG_DIR/summary.txt"

# shellcheck disable=SC1091
source "$ROOT/scripts/lib/load-config.sh"

mkdir -p "$LOG_DIR"

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

print_usage() {
  cat <<'EOF'
Usage:
  ./test_sys/run_all.sh [quick|env|release|full|manual]

Modes:
  quick    Backend deterministic tests and frontend lint/build. No real services required.
  env      Real local service readiness check.
  release  quick + repository quality gate + mock evaluation.
  full     release + env + real LM Studio model test + real Wazuh E2E smoke test.
  manual   Print manual Slack/failure scenario entrypoints.
EOF
}

log_line() {
  printf '%s\n' "$*" | tee -a "$SUMMARY_FILE"
}

run_step() {
  local name="$1"
  local logfile="$2"
  shift 2

  log_line ""
  log_line "==> $name"
  log_line "    log: $logfile"

  (
    cd "$ROOT" || exit 1
    printf '## %s\n' "$name"
    printf '## Started: %s\n\n' "$(date '+%Y-%m-%d %H:%M:%S')"
    "$@"
    status=$?
    printf '\n## Finished: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')"
    printf '## Exit code: %s\n' "$status"
    exit "$status"
  ) >"$logfile" 2>&1

  local status=$?
  if [[ "$status" -eq 0 ]]; then
    PASS_COUNT=$((PASS_COUNT + 1))
    log_line "    PASS"
  else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    log_line "    FAIL ($status)"
    log_line "    Last 40 log lines:"
    tail -40 "$logfile" | sed 's/^/      /' | tee -a "$SUMMARY_FILE"
  fi
}

skip_step() {
  local name="$1"
  local reason="$2"
  SKIP_COUNT=$((SKIP_COUNT + 1))
  log_line ""
  log_line "==> $name"
  log_line "    SKIP: $reason"
}

run_frontend_lint() {
  cd "$ROOT/dashboard" || exit 1
  pnpm --config.verify-deps-before-run=false lint
}

run_frontend_build() {
  cd "$ROOT/dashboard" || exit 1
  pnpm --config.verify-deps-before-run=false build
}

run_manual_info() {
  cd "$ROOT" || exit 1
  ./scripts/test.sh manual
}

log_line "EdgeSec-Pi system test batch"
log_line "Mode: $MODE"
log_line "Started: $(date '+%Y-%m-%d %H:%M:%S')"
log_line "Log directory: $LOG_DIR"

case "$MODE" in
  quick)
    run_step "Backend unit + fake-service integration" "$LOG_DIR/01-backend-default.log" ./scripts/test.sh
    run_step "Frontend lint" "$LOG_DIR/02-dashboard-lint.log" run_frontend_lint
    run_step "Frontend production build" "$LOG_DIR/03-dashboard-build.log" run_frontend_build
    ;;

  env)
    run_step "Local service readiness" "$LOG_DIR/01-env-readiness.log" ./scripts/test.sh env
    ;;

  release)
    run_step "Backend unit + fake-service integration" "$LOG_DIR/01-backend-default.log" ./scripts/test.sh
    run_step "Frontend lint" "$LOG_DIR/02-dashboard-lint.log" run_frontend_lint
    run_step "Frontend production build" "$LOG_DIR/03-dashboard-build.log" run_frontend_build
    run_step "Repository quality gate" "$LOG_DIR/04-quality-gate.log" ./scripts/check-quality.sh
    run_step "Prompt evaluation mock" "$LOG_DIR/05-eval-mock.log" ./scripts/test.sh eval-mock
    ;;

  full)
    run_step "Backend unit + fake-service integration" "$LOG_DIR/01-backend-default.log" ./scripts/test.sh
    run_step "Frontend lint" "$LOG_DIR/02-dashboard-lint.log" run_frontend_lint
    run_step "Frontend production build" "$LOG_DIR/03-dashboard-build.log" run_frontend_build
    run_step "Repository quality gate" "$LOG_DIR/04-quality-gate.log" ./scripts/check-quality.sh
    run_step "Prompt evaluation mock" "$LOG_DIR/05-eval-mock.log" ./scripts/test.sh eval-mock
    run_step "Local service readiness" "$LOG_DIR/06-env-readiness.log" ./scripts/test.sh env
    run_step "Real LM Studio model compatibility" "$LOG_DIR/07-model.log" ./scripts/test.sh model
    run_step "Real Wazuh E2E smoke test" "$LOG_DIR/08-e2e.log" ./scripts/test.sh e2e
    ;;

  manual)
    run_step "Manual test entrypoints" "$LOG_DIR/01-manual-entrypoints.log" run_manual_info
    skip_step "Interactive scenario execution" "Run tests/manual/test_scenarios.sh directly after Slack, Wazuh, LM Studio, and bridge are ready."
    skip_step "Interactive failure-mode execution" "Run tests/manual/test_failures.sh directly when you are ready to verify dependency-down behavior."
    ;;

  -h|--help|help)
    print_usage
    exit 0
    ;;

  *)
    print_usage
    exit 2
    ;;
esac

log_line ""
log_line "Finished: $(date '+%Y-%m-%d %H:%M:%S')"
log_line "Passed: $PASS_COUNT"
log_line "Failed: $FAIL_COUNT"
log_line "Skipped: $SKIP_COUNT"
log_line "Summary: $SUMMARY_FILE"

if [[ "$FAIL_COUNT" -gt 0 ]]; then
  exit 1
fi

exit 0
