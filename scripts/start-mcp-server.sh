#!/usr/bin/env bash
# Phase 3a — deploy gensecaihq/Wazuh-MCP-Server alongside our Wazuh stack.
#
#   1. clone the MCP-server repo (one-time)
#   2. generate a long-lived API key, write to wazuh-mcp/.env
#   3. point it at our Wazuh manager + indexer (via shared docker net)
#   4. docker compose up
#   5. smoke-test:  /health   +   tools/list   +   one read tool
#
# After this completes you'll have a working MCP server on the configured host
# port (default :3030) that any
# MCP-aware client (our bridge, Claude Desktop, LobeChat, mcphost) can
# connect to and use to query your live Wazuh data.

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/.." && pwd)"
REPO_DIR="$ROOT/wazuh-stack/wazuh-mcp-server"
COMPOSE_DIR="$ROOT/wazuh-stack/wazuh-mcp"
ENV_FILE="$COMPOSE_DIR/.env"

_BRIDGE_ENV="$ROOT/bridge.env"
if [[ -f "$_BRIDGE_ENV" ]]; then
  set -a; source "$_BRIDGE_ENV"; set +a
fi

c_log() { printf "\033[1;36m[%s]\033[0m %s\n" "$(date '+%H:%M:%S')" "$*"; }
c_ok()  { printf "\033[1;32m[✓]\033[0m %s\n" "$*"; }
c_err() { printf "\033[1;31m[x]\033[0m %s\n" "$*" >&2; exit 1; }

# ── Sanity ──────────────────────────────────────────────────────────────
docker ps --format '{{.Names}}' | grep -q '^single-node-wazuh.manager-1$' \
    || c_err "Wazuh manager isn't running. Run ../wazuh-stack/setup.sh first."
docker network ls --format '{{.Name}}' | grep -q '^single-node_default$' \
    || c_err "Wazuh's docker network 'single-node_default' not found."
command -v git >/dev/null || c_err "git not found"

# ── 1. Clone the MCP server repo ───────────────────────────────────────
if [[ ! -d "$REPO_DIR" ]]; then
    c_log "cloning gensecaihq/Wazuh-MCP-Server"
    git clone --depth 1 https://github.com/gensecaihq/Wazuh-MCP-Server.git "$REPO_DIR"
    c_ok "cloned to $REPO_DIR"
else
    c_log "MCP server repo already cloned (run 'git -C $REPO_DIR pull' to update)"
fi

# ── 2. Generate / preserve API key + Wazuh creds ───────────────────────
mkdir -p "$COMPOSE_DIR"
if [[ ! -f "$ENV_FILE" ]]; then
    KEY="wazuh_$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
    cat > "$ENV_FILE" <<EOF
# EdgeSec-Pi · Wazuh MCP server runtime config
MCP_API_KEY=$KEY

# Wazuh API user. Use your own Wazuh credentials.
WAZUH_USER=${WAZUH_USER:-wazuh-wui}
WAZUH_PASS=${WAZUH_PASS:-CHANGE_ME}

# Wazuh Indexer credentials. Use your own Wazuh credentials.
WAZUH_INDEXER_USER=${WAZUH_INDEXER_USER:-admin}
WAZUH_INDEXER_PASS=${WAZUH_INDEXER_PASS:-CHANGE_ME}
EOF
    c_ok "generated $ENV_FILE with new API key"
    if grep -q 'CHANGE_ME' "$ENV_FILE"; then
        c_err "edit $ENV_FILE and replace CHANGE_ME before starting the MCP server"
    fi
else
    c_log "$ENV_FILE already exists, preserving existing API key"
fi

# Source the env so we can echo the key at the end
set -a; source "$ENV_FILE"; set +a

# ── 3. Build + start the container ─────────────────────────────────────
c_log "building + starting wazuh-mcp container (first run takes 2-3 min)"
( cd "$COMPOSE_DIR" && docker compose --env-file .env up -d --build )

# ── 4. Wait for /health ────────────────────────────────────────────────
c_log "waiting for MCP server /health"
for i in $(seq 1 30); do
    if curl -fsS http://localhost:${MCP_HOST_PORT:-3030}/health >/dev/null 2>&1; then
        c_ok "MCP server healthy at http://localhost:${MCP_HOST_PORT:-3030}"
        break
    fi
    sleep 2
    [[ $i -eq 30 ]] && c_err "MCP server didn't pass /health in 60s — see 'docker logs wazuh-mcp-server'"
done

# ── 5. Smoke tests ─────────────────────────────────────────────────────
echo
c_log "smoke test 1 — /health"
curl -s http://localhost:${MCP_HOST_PORT:-3030}/health | python3 -m json.tool || true

echo
c_log "smoke test 2 — exchange API key for short-lived JWT (server requires this dance)"
JWT=$(curl -s -X POST http://localhost:${MCP_HOST_PORT:-3030}/auth/token \
    -H 'Content-Type: application/json' \
    -d "{\"api_key\":\"$MCP_API_KEY\"}" \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('access_token',''))")
if [[ -n "$JWT" ]]; then
    c_ok "got JWT (length ${#JWT})"
else
    c_err "/auth/token didn't return access_token — check container logs"
fi

echo
c_log "smoke test 3 — list available tools using JWT"
curl -s -X POST http://localhost:${MCP_HOST_PORT:-3030}/mcp \
    -H "Authorization: Bearer $JWT" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
    | python3 -c "
import sys, json
try:
    r = json.load(sys.stdin)
    tools = (r.get('result') or {}).get('tools', [])
    print(f'  ✓ {len(tools)} tools registered')
    for t in tools[:8]:
        print(f'      • {t[\"name\"]:35s}  {t.get(\"description\",\"\")[:50]}')
    if len(tools) > 8:
        print(f'      … and {len(tools)-8} more')
except Exception as e:
    print(f'  ✗ tools/list failed: {e}')
    print(sys.stdin.read())
"

echo
c_log "smoke test 4 — call get_wazuh_cluster_health (proves Wazuh API reachable)"
curl -s -X POST http://localhost:${MCP_HOST_PORT:-3030}/mcp \
    -H "Authorization: Bearer $JWT" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_wazuh_cluster_health","arguments":{}}}' \
    | python3 -m json.tool 2>&1 | head -30 || true

cat <<EOF

──────────────────────────────────────────────────────────────────
✓ Wazuh MCP Server up at http://localhost:${MCP_HOST_PORT:-3030}

Save this key — the bridge will need it next:

    MCP_API_KEY=$MCP_API_KEY

Quick manual exploration (nice to play with before committing to bridge integration):

  # list all 48 tools
  curl -s -X POST http://localhost:${MCP_HOST_PORT:-3030}/mcp \\
      -H "Authorization: Bearer \$MCP_API_KEY" \\
      -H "Content-Type: application/json" \\
      -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \\
      | python3 -m json.tool | grep '"name"'

  # search alerts from a specific source IP in the last 24h
  curl -s -X POST http://localhost:${MCP_HOST_PORT:-3030}/mcp \\
      -H "Authorization: Bearer \$MCP_API_KEY" \\
      -H "Content-Type: application/json" \\
      -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"search_security_events","arguments":{"src_ip":"192.0.2.111","time_range":"24h"}}}' \\
      | python3 -m json.tool

  # get the MCP server logs
  docker logs -f wazuh-mcp-server
──────────────────────────────────────────────────────────────────
EOF
