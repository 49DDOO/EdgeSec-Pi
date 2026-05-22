#!/usr/bin/env bash
# EdgeSec-Pi release-quality gate.
#
# This is intentionally dependency-light: it uses stdlib compileall, the
# existing pytest suite, git's whitespace checker, and a conservative tracked
# file secret scan. It avoids local venvs and generated third-party trees.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ok() { printf "  \033[32m✓\033[0m %s\n" "$*"; }
fail() { printf "  \033[31mx\033[0m %s\n" "$*"; return 1; }

echo "EdgeSec-Pi quality check"
echo

git diff --check
ok "git whitespace check passed"

PYTHONPYCACHEPREFIX="${TMPDIR:-/private/tmp}/edgesec-pycache" \
  python3 -m compileall -q \
    -x '(^|/)(\.venv|venv|wazuh-mcp-server|wazuh-docker|__pycache__|\.pytest_cache)(/|$)' \
    wazuh-llm-bridge tests
ok "python compile check passed"

./scripts/test.sh
ok "unit and integration tests passed"

if git grep -n -E \
  'hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[A-Za-z0-9_-]+|xoxb-[0-9A-Za-z-]{20,}|xapp-[0-9A-Za-z-]{20,}|wazuh_[A-Za-z0-9_-]{32,}|BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY' \
  -- ':!*.example' ':!*.md' ':!tests/*' >/tmp/edgesec-secret-scan.txt; then
  cat /tmp/edgesec-secret-scan.txt
  fail "possible tracked secret found"
fi
ok "tracked secret scan passed"

echo
ok "quality check passed"
