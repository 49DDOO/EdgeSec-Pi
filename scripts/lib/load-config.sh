#!/usr/bin/env bash
# Shared EdgeSec-Pi service-location config.
#
# This file is meant to be sourced, not executed:
#   source scripts/lib/load-config.sh
#
# Only non-secret topology belongs here. Secrets remain in
# wazuh-llm-bridge/.env or component-specific .env files.

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  echo "load-config.sh must be sourced, not executed" >&2
  exit 2
fi

EDGESEC_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EDGESEC_ROOT="$(cd "$EDGESEC_SCRIPT_DIR/.." && pwd)"
EDGESEC_BRIDGE_DIR="$EDGESEC_ROOT/wazuh-llm-bridge"
EDGESEC_DASHBOARD_DIR="$EDGESEC_ROOT/dashboard"
EDGESEC_WAZUH_STACK_DIR="$EDGESEC_ROOT/wazuh-stack"
EDGESEC_BRIDGE_ENV="$EDGESEC_ROOT/bridge.env"
EDGESEC_BRIDGE_DOTENV="$EDGESEC_BRIDGE_DIR/.env"
EDGESEC_TOPOLOGY_KEYS=(
  BRIDGE_PORT
  BRIDGE_PUBLIC_URL
  DASHBOARD_PORT
  DASHBOARD_V2_URL
  BRIDGE_BIND_HOST
  DASHBOARD_BIND_HOST
  BRIDGE_SSL_CERTFILE
  BRIDGE_SSL_KEYFILE
  LM_STUDIO_URL
  LM_STUDIO_MODELS_URL
  LM_MODEL
  LM_TIMEOUT_S
  WAZUH_API_URL
  WAZUH_INDEXER_URL
  MANAGER_HOST
  WAZUH_AGENT_PORT
  WAZUH_AUTHD_PORT
  MCP_HOST_PORT
  MCP_SERVER_URL
  LOBECHAT_URL
  SIEM_DASHBOARD_URL
)

if [[ -f "$EDGESEC_BRIDGE_ENV" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$EDGESEC_BRIDGE_ENV"
  set +a
fi

for _key in "${EDGESEC_TOPOLOGY_KEYS[@]}"; do
  eval "_is_set=\${$_key+x}"
  if [[ -n "$_is_set" ]]; then
    eval "EDGESEC_FROM_BRIDGE_ENV_${_key}=\${$_key}"
    eval "EDGESEC_FROM_BRIDGE_ENV_${_key}_SET=1"
  fi
done

# Load bridge secrets after bridge.env. Topology values from bridge.env are
# restored below so secrets in wazuh-llm-bridge/.env cannot silently override
# ports, hostnames, or public URLs.
if [[ -f "$EDGESEC_BRIDGE_DOTENV" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$EDGESEC_BRIDGE_DOTENV"
  set +a
fi

for _key in "${EDGESEC_TOPOLOGY_KEYS[@]}"; do
  eval "_was_set=\${EDGESEC_FROM_BRIDGE_ENV_${_key}_SET:-}"
  if [[ -n "$_was_set" ]]; then
    eval "$_key=\${EDGESEC_FROM_BRIDGE_ENV_${_key}}"
  fi
done
unset _key _is_set _was_set

BRIDGE_PORT="${BRIDGE_PORT:-8001}"
BRIDGE_BIND_HOST="${BRIDGE_BIND_HOST:-127.0.0.1}"
DASHBOARD_PORT="${DASHBOARD_PORT:-3000}"
DASHBOARD_BIND_HOST="${DASHBOARD_BIND_HOST:-127.0.0.1}"
DASHBOARD_V2_URL="${DASHBOARD_V2_URL:-http://127.0.0.1:$DASHBOARD_PORT}"

LM_STUDIO_URL="${LM_STUDIO_URL:-http://localhost:1234/v1/chat/completions}"
LM_MODEL="${LM_MODEL:-local-model}"
LM_TIMEOUT_S="${LM_TIMEOUT_S:-180}"
LM_STUDIO_MODELS_URL="${LM_STUDIO_MODELS_URL:-${LM_STUDIO_URL%/chat/completions}/models}"

WAZUH_API_URL="${WAZUH_API_URL:-https://localhost:55000}"
WAZUH_API_URL="${WAZUH_API_URL%/}"
WAZUH_INDEXER_URL="${WAZUH_INDEXER_URL:-https://localhost:9200}"
WAZUH_INDEXER_URL="${WAZUH_INDEXER_URL%/}"
MANAGER_HOST="${MANAGER_HOST:-localhost}"
WAZUH_AGENT_PORT="${WAZUH_AGENT_PORT:-1514}"
WAZUH_AUTHD_PORT="${WAZUH_AUTHD_PORT:-1515}"

MCP_HOST_PORT="${MCP_HOST_PORT:-3030}"
MCP_SERVER_URL="${MCP_SERVER_URL:-http://localhost:$MCP_HOST_PORT}"
MCP_SERVER_URL="${MCP_SERVER_URL%/}"
LOBECHAT_URL="${LOBECHAT_URL:-http://localhost:3210}"
SIEM_DASHBOARD_URL="${SIEM_DASHBOARD_URL:-}"

BRIDGE_SCHEME="http"
BRIDGE_LOCAL_BASE="http://127.0.0.1:$BRIDGE_PORT"
BRIDGE_SSL_ARGS=()
if [[ -n "${BRIDGE_SSL_CERTFILE:-}" || -n "${BRIDGE_SSL_KEYFILE:-}" ]]; then
  BRIDGE_SCHEME="https"
  BRIDGE_LOCAL_BASE="https://127.0.0.1:$BRIDGE_PORT"
  if [[ -n "${BRIDGE_SSL_CERTFILE:-}" && -n "${BRIDGE_SSL_KEYFILE:-}" ]]; then
    BRIDGE_SSL_ARGS=(--ssl-certfile "$BRIDGE_SSL_CERTFILE" --ssl-keyfile "$BRIDGE_SSL_KEYFILE")
  fi
fi

export EDGESEC_ROOT EDGESEC_SCRIPT_DIR EDGESEC_BRIDGE_DIR EDGESEC_DASHBOARD_DIR EDGESEC_WAZUH_STACK_DIR
export EDGESEC_BRIDGE_ENV EDGESEC_BRIDGE_DOTENV
export BRIDGE_PORT BRIDGE_BIND_HOST DASHBOARD_PORT DASHBOARD_BIND_HOST DASHBOARD_V2_URL
export LM_STUDIO_URL LM_MODEL LM_TIMEOUT_S LM_STUDIO_MODELS_URL
export WAZUH_API_URL WAZUH_INDEXER_URL MANAGER_HOST WAZUH_AGENT_PORT WAZUH_AUTHD_PORT
export MCP_HOST_PORT MCP_SERVER_URL LOBECHAT_URL SIEM_DASHBOARD_URL
export BRIDGE_SCHEME BRIDGE_LOCAL_BASE

edgesec_print_config() {
  cat <<EOF
EdgeSec-Pi unified service config
  config file          : $EDGESEC_BRIDGE_ENV
  bridge               : $BRIDGE_LOCAL_BASE
  bridge bind host     : $BRIDGE_BIND_HOST
  bridge public URL    : ${BRIDGE_PUBLIC_URL:-unset}
  dashboard            : http://127.0.0.1:$DASHBOARD_PORT
  dashboard bind host  : $DASHBOARD_BIND_HOST
  dashboard v2 URL     : $DASHBOARD_V2_URL
  LM Studio models     : $LM_STUDIO_MODELS_URL
  LM model             : $LM_MODEL
  Wazuh API            : $WAZUH_API_URL
  Wazuh Indexer        : $WAZUH_INDEXER_URL
  Agent manager        : $MANAGER_HOST:$WAZUH_AGENT_PORT
  Agent enrollment     : $MANAGER_HOST:$WAZUH_AUTHD_PORT
  MCP server           : $MCP_SERVER_URL
EOF
}
