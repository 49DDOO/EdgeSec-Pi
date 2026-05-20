#!/usr/bin/env bash
# Tear everything down. Use --wipe to also delete the cloned wazuh-docker
# directory (which contains the generated certs).

set -u
cd "$(dirname "${BASH_SOURCE[0]}")"

WIPE="${1:-}"

if [[ -f agent/docker-compose.yml ]]; then
  echo "→ stopping agent"
  docker compose -f agent/docker-compose.yml down -v --remove-orphans 2>/dev/null || true
fi

if [[ -d wazuh-docker/single-node ]]; then
  echo "→ stopping Wazuh stack"
  ( cd wazuh-docker/single-node && docker compose down -v --remove-orphans 2>/dev/null ) || true
fi

if [[ "$WIPE" == "--wipe" ]]; then
  echo "→ removing wazuh-docker (certs + clone)"
  rm -rf wazuh-docker
fi

echo "✓ teardown complete"
