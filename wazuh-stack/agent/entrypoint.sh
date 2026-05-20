#!/bin/bash
set -e

MANAGER="${WAZUH_MANAGER:-wazuh.manager}"

# Patch the manager address in case the env var changed since image build.
sed -i "s|<address>.*</address>|<address>${MANAGER}</address>|" /var/ossec/etc/ossec.conf

# Auto-enroll the agent. The Wazuh manager image runs authd on :1515 with
# password-less enrollment by default. If the agent was already enrolled
# (volume persists), skip.
if [[ ! -s /var/ossec/etc/client.keys ]]; then
  echo "[agent] enrolling with manager at ${MANAGER}..."
  for i in 1 2 3 4 5; do
    /var/ossec/bin/agent-auth -m "${MANAGER}" -p 1515 && break
    echo "[agent] enrollment attempt $i failed, retrying in 5s..."
    sleep 5
  done
fi

# Start agent in the background, then tail the log so the container stays alive
/var/ossec/bin/wazuh-control start
echo "[agent] running. tailing /var/ossec/logs/ossec.log"
exec tail -F /var/ossec/logs/ossec.log
