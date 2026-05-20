# Wazuh agent groups — OPTIONAL tuning recipes

> ## ⚠️ NOT REQUIRED FOR EDGESEC-PI TO WORK
>
> **EdgeSec-Pi (the LLM bridge) consumes whatever alerts Wazuh produces.**
> Wazuh's per-OS agent installer ships with sensible defaults that already
> read auth.log / Unified Log / Event Log out of the box, and that is
> sufficient for the bridge to do its job.
>
> Everything in this folder is **optional Wazuh hardening** — a recipe for
> adding more log sources (Homebrew, Docker Desktop, package managers,
> filtered Unified Log, scheduled command probes). It is **not part of the
> core EdgeSec-Pi product** and you can run the whole bridge without ever
> deploying it.
>
> Use this if you want to expand what Wazuh monitors. Skip it otherwise.

---

## What this folder is for (when you *do* want it)

A layered set of Wazuh `agent.conf` files that get pushed to the manager
via centralized group configuration. Once installed, every enrolled agent
automatically pulls the right combination based on its detected OS — no
SSH-and-edit-each-machine when you add a new agent.

| Layer | Group | Applies to | Adds (above Wazuh defaults) |
|-------|-------|------------|------------------------------|
| 1 | `default` | every agent (implicit) | Enforces explicit Rootcheck/SCA/Syscollector schedules so vendor changes don't drift them |
| 2 | `macos` | OS=Darwin | `/Applications` + `LaunchDaemons` FIM, install.log, wifi.log, Homebrew logs, Docker Desktop log, **filtered** Unified Log query (focused on security-critical processes), scheduled `lsof`/`who`/`docker ps` probes |
| 2 | `linux` | OS=Linux | `/boot` + `/root` FIM, apt/dpkg/dnf/yum history, docker daemon log, cron log, scheduled `ss`/`who`/`last` probes |
| 2 | `windows` | OS=windows | Registry monitoring (Run keys, Services, Winlogon), PowerShell Operational, Sysmon, Defender Operational, scheduled `netstat`/`query user`/`Get-Process` probes |

Each per-OS file wraps its config in `<agent_config os="...">` so even if
an agent has the "wrong" group attached, only the matching block applies
at runtime.

## Files

```
agent-groups/
├── default/agent.conf      OS-agnostic baseline (mostly explicit redeclaration of Wazuh defaults)
├── macos/agent.conf        macOS-specific additions
├── linux/agent.conf        Linux-specific additions
├── windows/agent.conf      Windows-specific additions
├── setup-agent-groups.sh   bootstrap script (idempotent)
└── README.md               this file
```

## Bootstrap (when you choose to use this)

```bash
cd wazuh-stack/agent-groups
chmod +x setup-agent-groups.sh
./setup-agent-groups.sh
```

The script:
1. Creates the 3 non-default groups inside the manager
2. Copies each `agent.conf` into `/var/ossec/etc/shared/<group>/`, fixes perms
3. Discovers enrolled agents and auto-assigns by OS based on a name heuristic
4. Restarts the manager so `merged.mg` rebuilds immediately
5. Prints verification info

Re-running is safe — every step is idempotent.

## Rolling it back (if you change your mind)

This folder's effect on Wazuh runtime is purely additive — Wazuh merges
the shared agent.conf with the agent's local ossec.conf and dedups
duplicates. To remove these additions and return to Wazuh's pure
out-of-box behaviour:

```bash
# Replace each shared agent.conf with an empty placeholder
for g in default macos linux windows; do
  docker exec single-node-wazuh.manager-1 bash -c \
    "echo '<agent_config/>' > /var/ossec/etc/shared/$g/agent.conf"
done
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart

# Then restart any agents so they pull the (now empty) shared config:
sudo /Library/Ossec/bin/wazuh-control restart           # macOS
docker exec wazuh-agent-01 /var/ossec/bin/wazuh-control restart  # Linux container
```

The agents will fall back to whatever their local ossec.conf already
specifies (which is Wazuh's per-OS default).

## Adding a new agent later (if you keep this enabled)

Specify groups at enrollment so the agent picks up the right
configuration from its very first heartbeat:

```bash
# macOS (after installing the Wazuh agent .pkg)
sudo /Library/Ossec/bin/agent-auth -m <manager_ip> -G default,macos

# Linux
sudo /var/ossec/bin/agent-auth -m <manager_ip> -G default,linux

# Windows (in elevated PowerShell)
& "C:\Program Files (x86)\ossec-agent\agent-auth.exe" -m <manager_ip> -G default,windows
```

## Editing the recipes

After you change any of the four `agent.conf` files:

```bash
./setup-agent-groups.sh        # re-pushes everything + restarts manager
```

Agents pull on their next 10-minute heartbeat, or you can force a
restart on a specific agent to apply immediately.

## Troubleshooting

**Agent shows old config**
- `cat /Library/Ossec/etc/shared/merged.mg` on the agent — see what it actually received
- Force restart agent: `sudo /Library/Ossec/bin/wazuh-control restart`
- Check manager log: `docker exec single-node-wazuh.manager-1 tail -50 /var/ossec/logs/ossec.log | grep -i shared`

**Manager refuses to start after script ran**
- Most likely a syntax error in one of the agent.conf files
- Check: `docker exec single-node-wazuh.manager-1 tail -50 /var/ossec/logs/ossec.log | grep -i error`
- Roll back via the "Rolling it back" section above

**Agent.conf rule fires for the wrong OS**
- The `<agent_config os="...">` filter is case-sensitive in some Wazuh versions
- Stick to: `os="Darwin"`, `os="Linux"`, `os="windows"` (note lowercase "w" for Windows — the value Wazuh's agent detection actually returns)
