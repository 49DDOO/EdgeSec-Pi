#!/usr/bin/env bash
# EdgeSec-Pi — one-shot installer for Wazuh MCP Server + LobeChat
# Usage: ./install.sh [--with-lobechat]

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WAZUH_DIR="${PROJECT_DIR}/wazuh-mcp"
LOBE_DIR="${PROJECT_DIR}/lobechat"
INSTALL_LOBE="${1:-}"

log()  { printf "\033[1;36m[*]\033[0m %s\n" "$*"; }
ok()   { printf "\033[1;32m[✓]\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m[!]\033[0m %s\n" "$*"; }
err()  { printf "\033[1;31m[x]\033[0m %s\n" "$*" >&2; exit 1; }

command -v docker >/dev/null      || err "docker not found"
docker compose version >/dev/null || err "docker compose v2 required"
command -v git >/dev/null         || err "git not found"
command -v python3 >/dev/null     || err "python3 not found"

# ── 1. Wazuh MCP Server ──────────────────────────────────────────────────────
if [[ ! -d "$WAZUH_DIR" ]]; then
  log "Cloning Wazuh-MCP-Server into $WAZUH_DIR"
  git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git "$WAZUH_DIR"
else
  log "wazuh-mcp dir exists; pulling latest"
  ( cd "$WAZUH_DIR" && git pull --ff-only )
fi

cd "$WAZUH_DIR"
if [[ ! -f .env ]]; then
  cp .env.example .env
  warn "Created $WAZUH_DIR/.env — EDIT IT before continuing (WAZUH_HOST/USER/PASS)."
fi

# Generate API key if missing
if ! grep -qE '^MCP_API_KEY=' .env; then
  KEY="wazuh_$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
  printf "\nMCP_API_KEY=%s\n" "$KEY" >> .env
  ok "Generated MCP_API_KEY and appended to .env"
else
  KEY="$(grep -E '^MCP_API_KEY=' .env | head -1 | cut -d= -f2-)"
fi

log "Starting Wazuh MCP Server (docker compose up -d)"
docker compose up -d

log "Waiting for /health..."
for i in {1..20}; do
  if curl -fsS http://localhost:3000/health >/dev/null 2>&1; then
    ok "Wazuh MCP Server healthy at http://localhost:3000"
    break
  fi
  sleep 2
  [[ $i -eq 20 ]] && warn "MCP server didn't pass /health in 40s — check 'docker logs'"
done

# ── 2. LobeChat (optional) ───────────────────────────────────────────────────
if [[ "$INSTALL_LOBE" == "--with-lobechat" ]]; then
  mkdir -p "$LOBE_DIR" && cd "$LOBE_DIR"
  if [[ ! -f docker-compose.yml ]]; then
    log "Fetching LobeChat docker-compose"
    curl -fsSL https://raw.githubusercontent.com/lobehub/lobe-chat/main/docker-compose/local/docker-compose.yml -o docker-compose.yml
    curl -fsSL https://raw.githubusercontent.com/lobehub/lobe-chat/main/docker-compose/local/.env.example   -o .env
    warn "Edit $LOBE_DIR/.env to set OPENAI_API_KEY / ANTHROPIC_API_KEY / OLLAMA_PROXY_URL"
  fi
  log "Starting LobeChat"
  docker compose up -d
  ok  "LobeChat → http://localhost:3210"
fi

# ── 3. Print MCP marketplace JSON ────────────────────────────────────────────
cat <<EOF

────────────────────────────────────────────────────────────────────
✅  Wazuh MCP server is up.
   Paste the following into LobeChat → Settings → Tools / MCP →
   "Custom MCP Server" (or via MCP Marketplace → Install → Edit JSON):

{
  "mcpServers": {
    "wazuh": {
      "type": "http",
      "url": "http://localhost:3000/mcp",
      "headers": {
        "Authorization": "Bearer ${KEY}"
      }
    }
  }
}

   ⚠  If LobeChat runs in Docker on the same host, replace
      "localhost" with "host.docker.internal".
────────────────────────────────────────────────────────────────────
EOF
