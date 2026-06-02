#!/usr/bin/env python3
"""EdgeSec-Pi endpoint isolation active-response helper.

This script is meant to run on Wazuh agents. It keeps isolation reversible by
writing state before changing networking, preserving manager/management
connectivity, and spawning a local TTL release process.

Modes:
  - isolate: Linux uses iptables/ip6tables, macOS uses pfctl, Windows uses
    Windows Firewall. A route-only fallback remains for unusual platforms.
  - release: restores saved firewall/routes from state.

Use --dry-run in labs before installing as a Wazuh Active Response executable.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import platform
import re
import shlex
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


STATE_NAME = "edgesec-ar-state.json"
LOG_NAME = "edgesec-ar.log"
LINUX_CHAIN_OUT = "EDGESEC_AR_OUT"
LINUX_CHAIN_IN = "EDGESEC_AR_IN"
LINUX6_CHAIN_OUT = "EDGESEC_AR6_OUT"
LINUX6_CHAIN_IN = "EDGESEC_AR6_IN"
MACOS_PF_ANCHOR = "com.apple/edgesec-ar"
MACOS_PF_RULES_NAME = "edgesec-ar-pf.conf"
WINDOWS_RULE_PREFIX = "EdgeSec-Pi isolation"
DEFAULT_TTL_S = 900


class EdgeSecArError(RuntimeError):
    pass


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    load_config_env(args)

    if args.scheduled and args.delay > 0:
        time.sleep(min(max(int(args.delay), 0), 86400))

    context = RuntimeContext.from_args(args)
    wazuh_payload = read_wazuh_payload()
    if args.action == "isolate":
        result = isolate(context, wazuh_payload)
    else:
        result = release(context, scheduled=args.scheduled)

    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="EdgeSec-Pi endpoint isolation helper")
    parser.add_argument("action", choices=("isolate", "release"))
    parser.add_argument("--ttl", type=int, default=0, help="Isolation TTL in seconds")
    parser.add_argument("--state-dir", default="", help="Override state directory")
    parser.add_argument("--manager", action="append", default=[], help="Manager host/IP to preserve")
    parser.add_argument("--allow-cidr", action="append", default=[], help="Additional CIDR/IP to preserve")
    parser.add_argument("--dry-run", action="store_true", help="Print planned commands without executing")
    parser.add_argument("--no-schedule", action="store_true", help="Do not spawn TTL release process")
    parser.add_argument("--scheduled", action="store_true", help="Internal flag for TTL release child")
    parser.add_argument("--delay", type=int, default=0, help="Internal scheduled release delay")
    parser.add_argument(
        "--force-without-manager",
        action="store_true",
        help="Allow isolation without a resolvable manager/allowlist",
    )
    return parser


def load_config_env(args: argparse.Namespace) -> None:
    for path in candidate_config_paths(args):
        try:
            exists = path.exists()
        except OSError:
            continue
        if exists:
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except OSError:
                continue
            for line in lines:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                os.environ.setdefault(key.strip(), value.strip().strip("\"'"))


def candidate_config_paths(args: argparse.Namespace) -> list[Path]:
    paths: list[Path] = []
    if os.getenv("EDGESEC_AR_CONFIG"):
        paths.append(Path(os.environ["EDGESEC_AR_CONFIG"]))
    ossec_dir = ossec_root()
    paths.append(ossec_dir / "etc" / "edgesec-ar.env")
    return paths


class RuntimeContext:
    def __init__(
        self,
        *,
        args: argparse.Namespace,
        os_name: str,
        ossec_dir: Path,
        state_dir: Path,
        dry_run: bool,
    ) -> None:
        self.args = args
        self.os_name = os_name
        self.ossec_dir = ossec_dir
        self.state_dir = state_dir
        self.state_file = state_dir / STATE_NAME
        self.log_file = state_dir / LOG_NAME
        self.dry_run = dry_run
        self.commands: list[list[str]] = []
        self.failed_commands: list[dict[str, Any]] = []

    @classmethod
    def from_args(cls, args: argparse.Namespace) -> "RuntimeContext":
        root = ossec_root()
        state_dir = Path(
            args.state_dir
            or os.getenv("EDGESEC_AR_STATE_DIR", "")
            or str(root / "var" / "run")
        )
        dry_run = args.dry_run or truthy(os.getenv("EDGESEC_AR_DRY_RUN"))
        return cls(
            args=args,
            os_name=os.getenv("EDGESEC_AR_PLATFORM", platform.system()).lower(),
            ossec_dir=root,
            state_dir=state_dir,
            dry_run=dry_run,
        )

    def log(self, message: str) -> None:
        line = f"{time.strftime('%Y-%m-%dT%H:%M:%S%z')} {message}\n"
        if self.dry_run:
            return
        self.state_dir.mkdir(parents=True, exist_ok=True)
        with self.log_file.open("a", encoding="utf-8") as fh:
            fh.write(line)

    def run(self, command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
        self.commands.append(command)
        if self.dry_run:
            return subprocess.CompletedProcess(command, 0, "", "")
        self.state_dir.mkdir(parents=True, exist_ok=True)
        proc = subprocess.run(command, text=True, capture_output=True, check=False)
        if proc.returncode != 0:
            self.failed_commands.append({
                "command": quote_cmd(command),
                "returncode": proc.returncode,
                "stderr": proc.stderr.strip(),
            })
        if check and proc.returncode != 0:
            raise EdgeSecArError(
                f"command failed rc={proc.returncode}: {quote_cmd(command)} {proc.stderr.strip()}"
            )
        return proc


def ossec_root() -> Path:
    if os.getenv("EDGESEC_AR_OSSEC_DIR"):
        return Path(os.environ["EDGESEC_AR_OSSEC_DIR"])
    system = os.getenv("EDGESEC_AR_PLATFORM", platform.system()).lower()
    if system == "darwin":
        return Path("/Library/Ossec")
    if system == "windows":
        for base in (os.getenv("ProgramFiles(x86)"), os.getenv("ProgramFiles")):
            if base:
                candidate = Path(base) / "ossec-agent"
                if candidate.exists():
                    return candidate
        return Path(r"C:\Program Files (x86)\ossec-agent")
    return Path("/var/ossec")


def read_wazuh_payload() -> dict[str, Any]:
    if sys.stdin.isatty():
        return {}
    raw = sys.stdin.read().strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {}
    except json.JSONDecodeError:
        return {"raw_stdin": raw}


def isolate(context: RuntimeContext, payload: dict[str, Any]) -> dict[str, Any]:
    ttl_s = isolation_ttl(context.args, payload)
    allow_networks = preserved_networks(context, payload)
    if not allow_networks and not context.args.force_without_manager:
        raise EdgeSecArError(
            "refusing to isolate without a resolvable Wazuh manager or EDGESEC_AR_ALLOW_CIDRS"
        )

    method = isolation_method(context)
    state = {
        "version": 1,
        "isolated_at": time.time(),
        "expires_at": time.time() + ttl_s,
        "ttl_s": ttl_s,
        "os": context.os_name,
        "allow_networks": [str(n) for n in allow_networks],
        "routes": capture_default_routes(context) if method == "route-quarantine" else [],
        "firewall_profiles": (
            capture_windows_firewall_profiles(context) if method == "windows-firewall" else []
        ),
        "method": method,
    }
    write_state(context, state)

    if state["method"] == "linux-iptables":
        apply_linux_iptables(context, allow_networks)
    elif state["method"] == "macos-pf":
        apply_macos_pf(context, allow_networks)
    elif state["method"] == "windows-firewall":
        apply_windows_firewall(context, allow_networks)
    else:
        apply_route_quarantine(context, state, allow_networks)

    schedule_method = ""
    if not context.args.no_schedule:
        schedule_method = schedule_release(context, ttl_s)

    return {
        "ok": True,
        "action": "isolate",
        "dry_run": context.dry_run,
        "method": state["method"],
        "schedule_method": schedule_method,
        "ttl_s": ttl_s,
        "allow_networks": state["allow_networks"],
        "commands": [quote_cmd(cmd) for cmd in context.commands],
    }


def release(context: RuntimeContext, *, scheduled: bool = False) -> dict[str, Any]:
    state = read_state(context)
    if not state:
        return {
            "ok": True,
            "action": "release",
            "dry_run": context.dry_run,
            "already_released": True,
            "commands": [],
        }

    method = str(state.get("method") or "")
    if method == "linux-iptables":
        release_linux_iptables(context)
    elif method == "macos-pf":
        release_macos_pf(context)
    elif method == "windows-firewall":
        release_windows_firewall(context, state)
    else:
        release_route_quarantine(context, state)

    if context.failed_commands and not context.dry_run:
        raise EdgeSecArError(
            "release had failed command(s); keeping state for retry: "
            + json.dumps(context.failed_commands, ensure_ascii=False)
        )

    if not context.dry_run:
        try:
            context.state_file.unlink()
        except FileNotFoundError:
            pass
    return {
        "ok": True,
        "action": "release",
        "scheduled": scheduled,
        "dry_run": context.dry_run,
        "method": method,
        "commands": [quote_cmd(cmd) for cmd in context.commands],
    }


def isolation_ttl(args: argparse.Namespace, payload: dict[str, Any]) -> int:
    values: list[Any] = [
        args.ttl,
        env_int("EDGESEC_AR_TTL_S"),
        lookup(payload, "parameters.alert.data.ttl_s"),
    ]
    extra_args = lookup(payload, "parameters.extra_args")
    if isinstance(extra_args, list):
        values.extend(extra_args)
    for value in values:
        try:
            ttl = int(str(value))
        except (TypeError, ValueError):
            continue
        if ttl > 0:
            return max(60, min(ttl, 86400))
    return DEFAULT_TTL_S


def preserved_networks(context: RuntimeContext, payload: dict[str, Any]) -> list[ipaddress._BaseNetwork]:
    values: list[str] = []
    values.extend(context.args.allow_cidr)
    values.extend(split_csv(os.getenv("EDGESEC_AR_ALLOW_CIDRS", "")))
    values.extend(context.args.manager)
    values.extend(split_csv(os.getenv("EDGESEC_AR_MANAGER", "")))
    values.extend(manager_addresses_from_ossec(context.ossec_dir / "etc" / "ossec.conf"))
    manager_from_payload = lookup(payload, "parameters.alert.data.manager")
    if manager_from_payload:
        values.append(str(manager_from_payload))

    networks: list[ipaddress._BaseNetwork] = []
    for value in values:
        networks.extend(resolve_network(value))
    return dedupe_networks(networks)


def manager_addresses_from_ossec(path: Path) -> list[str]:
    try:
        exists = path.exists()
    except OSError:
        return []
    if not exists:
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    return [item.strip() for item in re.findall(r"<address>\s*([^<]+?)\s*</address>", text) if item.strip()]


def resolve_network(value: str) -> list[ipaddress._BaseNetwork]:
    item = str(value or "").strip()
    if not item:
        return []
    try:
        return [ipaddress.ip_network(item, strict=False)]
    except ValueError:
        pass
    out: list[ipaddress._BaseNetwork] = []
    try:
        for family, _, _, _, sockaddr in socket.getaddrinfo(item, None):
            ip = ipaddress.ip_address(sockaddr[0])
            prefix = 32 if ip.version == 4 else 128
            out.append(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
    except socket.gaierror:
        return []
    return out


def dedupe_networks(networks: list[ipaddress._BaseNetwork]) -> list[ipaddress._BaseNetwork]:
    seen: set[str] = set()
    out: list[ipaddress._BaseNetwork] = []
    for network in networks:
        key = str(network)
        if key not in seen:
            seen.add(key)
            out.append(network)
    return out


def isolation_method(context: RuntimeContext) -> str:
    requested = os.getenv("EDGESEC_AR_METHOD", "").strip().lower()
    if requested:
        return requested
    if context.os_name == "linux" and shutil.which("iptables"):
        return "linux-iptables"
    if context.os_name == "darwin":
        return "macos-pf"
    if context.os_name == "windows":
        return "windows-firewall"
    return "route-quarantine"


def apply_linux_iptables(
    context: RuntimeContext,
    allow_networks: list[ipaddress._BaseNetwork],
) -> None:
    apply_linux_filter_family(
        context,
        binary=shutil.which("iptables") or "iptables",
        chain_out=LINUX_CHAIN_OUT,
        chain_in=LINUX_CHAIN_IN,
        allow_networks=[n for n in allow_networks if n.version == 4],
    )
    ip6tables = shutil.which("ip6tables") or "ip6tables"
    apply_linux_filter_family(
        context,
        binary=ip6tables,
        chain_out=LINUX6_CHAIN_OUT,
        chain_in=LINUX6_CHAIN_IN,
        allow_networks=[n for n in allow_networks if n.version == 6],
    )


def apply_linux_filter_family(
    context: RuntimeContext,
    *,
    binary: str,
    chain_out: str,
    chain_in: str,
    allow_networks: list[ipaddress._BaseNetwork],
) -> None:
    if not shutil.which(binary) and binary in {"iptables", "ip6tables"} and not context.dry_run:
        raise EdgeSecArError(f"{binary} not found")
    context.run([binary, "-N", chain_out], check=False)
    context.run([binary, "-N", chain_in], check=False)
    context.run([binary, "-F", chain_out])
    context.run([binary, "-F", chain_in])
    context.run([binary, "-A", chain_out, "-o", "lo", "-j", "ACCEPT"])
    context.run([binary, "-A", chain_in, "-i", "lo", "-j", "ACCEPT"])
    for network in allow_networks:
        context.run([binary, "-A", chain_out, "-d", str(network), "-j", "ACCEPT"])
        context.run([binary, "-A", chain_in, "-s", str(network), "-j", "ACCEPT"])
    context.run([binary, "-A", chain_out, "-j", "REJECT"])
    context.run([binary, "-A", chain_in, "-j", "DROP"])
    ensure_jump(context, binary, "OUTPUT", chain_out)
    ensure_jump(context, binary, "INPUT", chain_in)


def ensure_jump(context: RuntimeContext, iptables: str, chain: str, target: str) -> None:
    if context.dry_run:
        context.run([iptables, "-I", chain, "1", "-j", target])
        return
    check = subprocess.run([iptables, "-C", chain, "-j", target], capture_output=True, text=True)
    if check.returncode != 0:
        context.run([iptables, "-I", chain, "1", "-j", target])


def release_linux_iptables(context: RuntimeContext) -> None:
    release_linux_filter_family(
        context,
        binary=shutil.which("iptables") or "iptables",
        chain_out=LINUX_CHAIN_OUT,
        chain_in=LINUX_CHAIN_IN,
    )
    release_linux_filter_family(
        context,
        binary=shutil.which("ip6tables") or "ip6tables",
        chain_out=LINUX6_CHAIN_OUT,
        chain_in=LINUX6_CHAIN_IN,
        optional=True,
    )


def release_linux_filter_family(
    context: RuntimeContext,
    *,
    binary: str,
    chain_out: str,
    chain_in: str,
    optional: bool = False,
) -> None:
    if optional and not shutil.which(binary) and binary in {"iptables", "ip6tables"} and not context.dry_run:
        return
    for chain, target in (("OUTPUT", chain_out), ("INPUT", chain_in)):
        for _ in range(10):
            proc = context.run([binary, "-D", chain, "-j", target], check=False)
            if context.dry_run:
                break
            if proc.returncode != 0:
                break
    for target in (chain_out, chain_in):
        context.run([binary, "-F", target], check=False)
        context.run([binary, "-X", target], check=False)


def apply_macos_pf(
    context: RuntimeContext,
    allow_networks: list[ipaddress._BaseNetwork],
) -> None:
    pfctl = shutil.which("pfctl") or "pfctl"
    rules_path = context.state_dir / MACOS_PF_RULES_NAME
    rules = macos_pf_rules(allow_networks)
    if not context.dry_run:
        context.state_dir.mkdir(parents=True, exist_ok=True)
        rules_path.write_text(rules, encoding="utf-8")
    context.run([pfctl, "-E"], check=False)
    context.run([pfctl, "-a", MACOS_PF_ANCHOR, "-F", "rules"], check=False)
    context.run([pfctl, "-a", MACOS_PF_ANCHOR, "-f", str(rules_path)])
    context.run([pfctl, "-k", "0.0.0.0/0"], check=False)
    context.run([pfctl, "-k", "::/0"], check=False)


def release_macos_pf(context: RuntimeContext) -> None:
    pfctl = shutil.which("pfctl") or "pfctl"
    context.run([pfctl, "-a", MACOS_PF_ANCHOR, "-F", "rules"], check=False)
    context.run([pfctl, "-a", MACOS_PF_ANCHOR, "-F", "states"], check=False)
    if not context.dry_run:
        try:
            (context.state_dir / MACOS_PF_RULES_NAME).unlink()
        except FileNotFoundError:
            pass


def macos_pf_rules(allow_networks: list[ipaddress._BaseNetwork]) -> str:
    v4 = [str(n) for n in allow_networks if n.version == 4]
    v6 = [str(n) for n in allow_networks if n.version == 6]
    lines = [
        "# EdgeSec-Pi endpoint isolation anchor",
        "set block-policy drop",
        "set skip on lo0",
    ]
    if v4:
        lines.append(f"table <edgesec_mgmt4> persist {{ {', '.join(v4)} }}")
        lines.append("pass out quick inet to <edgesec_mgmt4> keep state")
        lines.append("pass in quick inet from <edgesec_mgmt4> keep state")
    if v6:
        lines.append(f"table <edgesec_mgmt6> persist {{ {', '.join(v6)} }}")
        lines.append("pass out quick inet6 to <edgesec_mgmt6> keep state")
        lines.append("pass in quick inet6 from <edgesec_mgmt6> keep state")
    lines.append("block drop quick all")
    return "\n".join(lines) + "\n"


def apply_windows_firewall(
    context: RuntimeContext,
    allow_networks: list[ipaddress._BaseNetwork],
) -> None:
    ps = powershell_binary()
    remote_addresses = powershell_array(str(n) for n in allow_networks)
    if not remote_addresses:
        raise EdgeSecArError("no Windows firewall allowlist available")
    context.run([
        ps,
        "-NoProfile",
        "-Command",
        (
            f"New-NetFirewallRule -DisplayName '{WINDOWS_RULE_PREFIX} allow outbound management' "
            "-Direction Outbound -Action Allow -Profile Any "
            f"-RemoteAddress {remote_addresses} -Enabled True"
        ),
    ])
    context.run([
        ps,
        "-NoProfile",
        "-Command",
        (
            f"New-NetFirewallRule -DisplayName '{WINDOWS_RULE_PREFIX} allow inbound management' "
            "-Direction Inbound -Action Allow -Profile Any "
            f"-RemoteAddress {remote_addresses} -Enabled True"
        ),
    ])
    context.run([
        ps,
        "-NoProfile",
        "-Command",
        (
            "Set-NetFirewallProfile -Profile Domain,Private,Public "
            "-Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block"
        ),
    ])


def release_windows_firewall(context: RuntimeContext, state: dict[str, Any]) -> None:
    ps = powershell_binary()
    context.run([
        ps,
        "-NoProfile",
        "-Command",
        f"Remove-NetFirewallRule -DisplayName '{WINDOWS_RULE_PREFIX}*' -ErrorAction SilentlyContinue",
    ], check=False)
    profiles = state.get("firewall_profiles") if isinstance(state, dict) else []
    if not isinstance(profiles, list) or not profiles:
        context.run([
            ps,
            "-NoProfile",
            "-Command",
            "Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction NotConfigured -DefaultOutboundAction Allow",
        ], check=False)
        return
    for profile in profiles:
        if not isinstance(profile, dict):
            continue
        name = str(profile.get("name") or "")
        inbound = str(profile.get("default_inbound") or "NotConfigured")
        outbound = str(profile.get("default_outbound") or "Allow")
        enabled = str(profile.get("enabled") or "True")
        if not name:
            continue
        context.run([
            ps,
            "-NoProfile",
            "-Command",
            (
                f"Set-NetFirewallProfile -Name '{name}' "
                f"-Enabled {enabled} "
                f"-DefaultInboundAction {inbound} "
                f"-DefaultOutboundAction {outbound}"
            ),
        ], check=False)


def capture_windows_firewall_profiles(context: RuntimeContext) -> list[dict[str, str]]:
    if context.os_name != "windows":
        return []
    if context.dry_run:
        return []
    ps = powershell_binary()
    script = (
        "Get-NetFirewallProfile | "
        "Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction | "
        "ConvertTo-Json -Compress"
    )
    proc = subprocess.run([ps, "-NoProfile", "-Command", script], text=True, capture_output=True)
    if proc.returncode != 0:
        return []
    try:
        parsed = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError:
        return []
    items = parsed if isinstance(parsed, list) else [parsed]
    profiles: list[dict[str, str]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        profiles.append({
            "name": str(item.get("Name") or ""),
            "enabled": str(item.get("Enabled") or "True"),
            "default_inbound": str(item.get("DefaultInboundAction") or "NotConfigured"),
            "default_outbound": str(item.get("DefaultOutboundAction") or "Allow"),
        })
    return [profile for profile in profiles if profile["name"]]


def powershell_binary() -> str:
    return shutil.which("powershell") or shutil.which("pwsh") or "powershell"


def powershell_array(values: Any) -> str:
    items = [str(value) for value in values if str(value)]
    if not items:
        return ""
    quoted = ",".join("'" + item.replace("'", "''") + "'" for item in items)
    return f"@({quoted})"


def capture_default_routes(context: RuntimeContext) -> list[dict[str, str]]:
    if context.dry_run:
        return []
    if context.os_name == "windows":
        return capture_windows_default_routes(context)
    if context.os_name == "darwin":
        return capture_macos_default_routes(context)
    return capture_linux_default_routes(context)


def capture_linux_default_routes(context: RuntimeContext) -> list[dict[str, str]]:
    ip_cmd = shutil.which("ip")
    if not ip_cmd:
        return []
    proc = subprocess.run([ip_cmd, "route", "show", "default"], text=True, capture_output=True)
    routes = []
    for line in proc.stdout.splitlines():
        parts = line.split()
        route = {"raw": line}
        if "via" in parts:
            route["gateway"] = parts[parts.index("via") + 1]
        if "dev" in parts:
            route["dev"] = parts[parts.index("dev") + 1]
        if "metric" in parts:
            route["metric"] = parts[parts.index("metric") + 1]
        if route.get("gateway") or route.get("dev"):
            routes.append(route)
    return routes


def capture_macos_default_routes(context: RuntimeContext) -> list[dict[str, str]]:
    route_cmd = shutil.which("route")
    if not route_cmd:
        return []
    proc = subprocess.run([route_cmd, "-n", "get", "default"], text=True, capture_output=True)
    route: dict[str, str] = {"raw": proc.stdout}
    for line in proc.stdout.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.strip().partition(":")
        if key in {"gateway", "interface"}:
            route[key] = value.strip()
    return [route] if route.get("gateway") else []


def capture_windows_default_routes(context: RuntimeContext) -> list[dict[str, str]]:
    ps = shutil.which("powershell") or shutil.which("pwsh")
    if not ps:
        return []
    script = (
        "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | "
        "Select-Object InterfaceIndex,NextHop,RouteMetric | ConvertTo-Json -Compress"
    )
    proc = subprocess.run([ps, "-NoProfile", "-Command", script], text=True, capture_output=True)
    try:
        parsed = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError:
        return []
    items = parsed if isinstance(parsed, list) else [parsed]
    routes = []
    for item in items:
        if not isinstance(item, dict):
            continue
        routes.append({
            "interface_index": str(item.get("InterfaceIndex") or ""),
            "gateway": str(item.get("NextHop") or ""),
            "metric": str(item.get("RouteMetric") or ""),
        })
    return [route for route in routes if route.get("interface_index") and route.get("gateway")]


def apply_route_quarantine(
    context: RuntimeContext,
    state: dict[str, Any],
    allow_networks: list[ipaddress._BaseNetwork],
) -> None:
    if context.os_name == "windows":
        apply_windows_routes(context, state, allow_networks)
    elif context.os_name == "darwin":
        apply_macos_routes(context, state, allow_networks)
    else:
        apply_linux_routes(context, state, allow_networks)


def release_route_quarantine(context: RuntimeContext, state: dict[str, Any]) -> None:
    if context.os_name == "windows":
        release_windows_routes(context, state)
    elif context.os_name == "darwin":
        release_macos_routes(context, state)
    else:
        release_linux_routes(context, state)


def apply_linux_routes(
    context: RuntimeContext,
    state: dict[str, Any],
    allow_networks: list[ipaddress._BaseNetwork],
) -> None:
    ip_cmd = shutil.which("ip") or "ip"
    routes = routes_for_action(context, state)
    if not routes:
        raise EdgeSecArError("no default route found to quarantine")
    first = routes[0]
    for network in allow_networks:
        if network.version != 4:
            continue
        cmd = [ip_cmd, "route", "replace", str(network)]
        if first.get("gateway"):
            cmd += ["via", first["gateway"]]
        if first.get("dev"):
            cmd += ["dev", first["dev"]]
        context.run(cmd)
    for route in routes:
        cmd = [ip_cmd, "route", "del", "default"]
        if route.get("gateway"):
            cmd += ["via", route["gateway"]]
        if route.get("dev"):
            cmd += ["dev", route["dev"]]
        context.run(cmd, check=False)


def release_linux_routes(context: RuntimeContext, state: dict[str, Any]) -> None:
    ip_cmd = shutil.which("ip") or "ip"
    for route in state.get("routes") or []:
        cmd = [ip_cmd, "route", "replace", "default"]
        if route.get("gateway"):
            cmd += ["via", route["gateway"]]
        if route.get("dev"):
            cmd += ["dev", route["dev"]]
        if route.get("metric"):
            cmd += ["metric", route["metric"]]
        context.run(cmd, check=False)


def apply_macos_routes(
    context: RuntimeContext,
    state: dict[str, Any],
    allow_networks: list[ipaddress._BaseNetwork],
) -> None:
    routes = routes_for_action(context, state)
    if not routes or not routes[0].get("gateway"):
        raise EdgeSecArError("no default gateway found to quarantine")
    gateway = routes[0]["gateway"]
    for network in allow_networks:
        if network.version != 4:
            continue
        host = str(network.network_address)
        context.run(["route", "-n", "add", "-host", host, gateway], check=False)
    context.run(["route", "-n", "delete", "default", gateway], check=False)


def release_macos_routes(context: RuntimeContext, state: dict[str, Any]) -> None:
    for route in state.get("routes") or []:
        gateway = route.get("gateway")
        if gateway:
            context.run(["route", "-n", "add", "default", gateway], check=False)


def apply_windows_routes(
    context: RuntimeContext,
    state: dict[str, Any],
    allow_networks: list[ipaddress._BaseNetwork],
) -> None:
    ps = shutil.which("powershell") or shutil.which("pwsh") or "powershell"
    routes = routes_for_action(context, state)
    if not routes:
        raise EdgeSecArError("no Windows default route found to quarantine")
    first = routes[0]
    for network in allow_networks:
        if network.version != 4:
            continue
        context.run([
            ps,
            "-NoProfile",
            "-Command",
            (
                "New-NetRoute "
                f"-DestinationPrefix '{network}' "
                f"-InterfaceIndex {first['interface_index']} "
                f"-NextHop '{first['gateway']}' -PolicyStore ActiveStore"
            ),
        ], check=False)
    for route in routes:
        context.run([
            ps,
            "-NoProfile",
            "-Command",
            (
                "Remove-NetRoute -DestinationPrefix '0.0.0.0/0' "
                f"-InterfaceIndex {route['interface_index']} "
                f"-NextHop '{route['gateway']}' -Confirm:$false"
            ),
        ], check=False)


def routes_for_action(context: RuntimeContext, state: dict[str, Any]) -> list[dict[str, str]]:
    routes = state.get("routes") or []
    if routes or not context.dry_run:
        return routes
    if context.os_name == "windows":
        return [{"interface_index": "1", "gateway": "192.0.2.1", "metric": "0"}]
    if context.os_name == "darwin":
        return [{"gateway": "192.0.2.1", "interface": "en0"}]
    return [{"gateway": "192.0.2.1", "dev": "eth0", "metric": "0"}]


def release_windows_routes(context: RuntimeContext, state: dict[str, Any]) -> None:
    ps = shutil.which("powershell") or shutil.which("pwsh") or "powershell"
    for route in state.get("routes") or []:
        context.run([
            ps,
            "-NoProfile",
            "-Command",
            (
                "New-NetRoute -DestinationPrefix '0.0.0.0/0' "
                f"-InterfaceIndex {route['interface_index']} "
                f"-NextHop '{route['gateway']}' "
                f"-RouteMetric {route.get('metric') or 0} -PolicyStore ActiveStore"
            ),
        ], check=False)


def schedule_release(context: RuntimeContext, ttl_s: int) -> str:
    script = Path(__file__).resolve()
    cmd = [
        sys.executable,
        str(script),
        "release",
        "--scheduled",
        "--state-dir",
        str(context.state_dir),
    ]
    if context.dry_run:
        method = preferred_scheduler(context)
        context.commands.append(["schedule", method, f"ttl={ttl_s}", "--"] + cmd)
        return method

    method = schedule_with_system_scheduler(context, ttl_s, cmd)
    if method:
        return method
    schedule_detached_sleep(context, ttl_s, cmd)
    return "detached-sleep-fallback"


def preferred_scheduler(context: RuntimeContext) -> str:
    if context.os_name == "windows":
        return "schtasks"
    if shutil.which("at"):
        return "at"
    if context.os_name == "linux" and shutil.which("systemd-run"):
        return "systemd-run"
    if context.os_name == "darwin" and shutil.which("launchctl"):
        return "launchd-submit"
    return "detached-sleep-fallback"


def schedule_with_system_scheduler(
    context: RuntimeContext,
    ttl_s: int,
    cmd: list[str],
) -> str:
    if context.os_name == "windows":
        return "schtasks" if schedule_windows_task(context, ttl_s, cmd) else ""
    if shutil.which("at"):
        return "at" if schedule_at(context, ttl_s, cmd) else ""
    if context.os_name == "linux" and shutil.which("systemd-run"):
        unit = f"edgesec-ar-release-{int(time.time())}"
        result = context.run([
            "systemd-run",
            "--unit",
            unit,
            "--on-active",
            f"{int(ttl_s)}s",
            "--collect",
            *cmd,
        ], check=False)
        if result.returncode == 0:
            return "systemd-run"
    if context.os_name == "darwin" and shutil.which("launchctl"):
        return "launchd-submit" if schedule_launchd_submit(context, ttl_s, cmd) else ""
    return ""


def schedule_at(context: RuntimeContext, ttl_s: int, cmd: list[str]) -> bool:
    at_cmd = ["at", "now", "+", str(int(ttl_s)), "seconds"]
    context.commands.append(at_cmd + ["<<", quote_cmd(cmd)])
    proc = subprocess.run(
        at_cmd,
        input=quote_cmd(cmd) + "\n",
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        context.failed_commands.append({
            "command": quote_cmd(at_cmd),
            "returncode": proc.returncode,
            "stderr": proc.stderr.strip(),
        })
    return proc.returncode == 0


def schedule_launchd_submit(context: RuntimeContext, ttl_s: int, cmd: list[str]) -> bool:
    # macOS has no direct one-shot "run after N seconds" equivalent in
    # launchctl submit, so submit a small shell wrapper that sleeps under
    # launchd supervision. This survives the parent AR process exiting, but not
    # a reboot; bridge-side TTL cleanup remains the cross-reboot safety net.
    shell_cmd = f"sleep {int(ttl_s)}; exec {quote_cmd(cmd)}"
    result = context.run([
        "launchctl",
        "submit",
        "-l",
        f"edgesec-ar-release-{int(time.time())}",
        "--",
        "/bin/sh",
        "-c",
        shell_cmd,
    ], check=False)
    return result.returncode == 0


def schedule_windows_task(context: RuntimeContext, ttl_s: int, cmd: list[str]) -> bool:
    run_at = time.localtime(time.time() + max(60, int(ttl_s)))
    task_name = f"EdgeSec-Pi-Release-{int(time.time())}"
    result = context.run([
        "schtasks",
        "/Create",
        "/TN",
        task_name,
        "/SC",
        "ONCE",
        "/ST",
        time.strftime("%H:%M", run_at),
        "/TR",
        subprocess.list2cmdline(cmd),
        "/F",
    ], check=False)
    return result.returncode == 0


def schedule_detached_sleep(context: RuntimeContext, ttl_s: int, cmd: list[str]) -> None:
    sleep_cmd = [*cmd[:3], "--delay", str(ttl_s), *cmd[3:]]
    kwargs: dict[str, Any] = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "close_fds": True,
    }
    if platform.system().lower() == "windows":
        kwargs["creationflags"] = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(
            subprocess,
            "CREATE_NEW_PROCESS_GROUP",
            0,
        )
    else:
        kwargs["start_new_session"] = True
    subprocess.Popen(sleep_cmd, **kwargs)


def write_state(context: RuntimeContext, state: dict[str, Any]) -> None:
    if context.dry_run:
        return
    context.state_dir.mkdir(parents=True, exist_ok=True)
    tmp = context.state_file.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(context.state_file)


def read_state(context: RuntimeContext) -> dict[str, Any]:
    if context.dry_run and not context.state_file.exists():
        return {
            "method": os.getenv("EDGESEC_AR_METHOD", "route-quarantine"),
            "routes": [],
        }
    if not context.state_file.exists():
        return {}
    try:
        parsed = json.loads(context.state_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def lookup(obj: dict[str, Any], dotted: str) -> Any:
    cur: Any = obj
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def split_csv(value: str) -> list[str]:
    return [item.strip() for item in str(value or "").split(",") if item.strip()]


def env_int(name: str) -> int:
    try:
        return int(os.getenv(name, "0"))
    except ValueError:
        return 0


def truthy(value: Any) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def quote_cmd(command: list[str]) -> str:
    return " ".join(shlex.quote(str(part)) for part in command)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except EdgeSecArError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        raise SystemExit(2)
