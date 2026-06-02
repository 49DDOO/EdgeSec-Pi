"""EdgeSec-Pi 每日資安狀態檢查 (freshness digest).

Collects:
  - Wazuh manager version vs latest GitHub release   → 「你的 SIEM 該不該升級了」
  - Last successful CVE feed update                   → 「漏洞資料是不是新的」
  - Agent online / offline counts                     → 「監控網有沒有破洞」
  - 24-hour alert volume + severity breakdown         → 「昨天到底有沒有事」

Two ways to consume:
  - GET /status            (on-demand JSON)
  - Scheduled daily 09:00  (auto-posted to Slack as a coloured card)
"""
from __future__ import annotations

import asyncio
import fcntl
import logging
import os
import re
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import httpx

import db
import notify_channels

log = logging.getLogger("digest")

WAZUH_MANAGER_CONTAINER = os.getenv(
    "WAZUH_MANAGER_CONTAINER", "single-node-wazuh.manager-1"
)
DIGEST_HOUR_LOCAL = int(os.getenv("DIGEST_HOUR_LOCAL", "9"))  # 09:00 by default
DIGEST_LOCK_PATH = Path(
    os.getenv(
        "DIGEST_LOCK_PATH",
        str(Path(__file__).resolve().parent / "data" / "digest-scheduler.lock"),
    )
)

# Set when the bridge starts up; used to report uptime.
START_TIME = time.time()


# ─── Helpers (sync, called via asyncio.to_thread) ───────────────────────
def _docker_exec(args: list[str], timeout: float = 5.0) -> Optional[str]:
    """Run a single `docker exec` and return stripped stdout, or None on any error."""
    try:
        r = subprocess.run(
            ["docker", "exec", WAZUH_MANAGER_CONTAINER, *args],
            capture_output=True, text=True, timeout=timeout,
        )
        if r.returncode != 0:
            return None
        return r.stdout.strip()
    except Exception as e:
        log.warning("docker exec failed (%s): %s", " ".join(args), e)
        return None


def _semver_tuple(s: str) -> tuple:
    """Best-effort semver parse: 'v4.14.5' → (4, 14, 5)."""
    return tuple(int(x) for x in re.findall(r"\d+", s)[:3])


def _get_wazuh_version_sync() -> Optional[str]:
    """Read the running manager's installed version (returns e.g. 'v4.14.5')."""
    for cmd in (
        ["cat", "/var/ossec/etc/VERSION"],
        ["cat", "/var/ossec/VERSION"],
        ["/var/ossec/bin/wazuh-control", "info"],
    ):
        out = _docker_exec(cmd)
        if out:
            m = re.search(r"v?(\d+\.\d+\.\d+)", out)
            if m:
                return f"v{m.group(1)}"
    return None


def _get_cve_feed_status_sync() -> dict:
    """Find the most recent successful vulnerability feed update.

    Older Wazuh versions log a clear "Feed update process completed" line.
    Newer vulnerability scanner builds keep feed metadata under vd_updater,
    so we fallback to the newest metadata write when the log line is absent.
    """
    out = _docker_exec(
        ["sh", "-c",
         "grep -F 'Feed update process completed' /var/ossec/logs/ossec.log "
         "| tail -1"],
        timeout=10,
    )
    if out:
        m = re.match(r"(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})", out)
        if m:
            # The manager container runs in UTC.
            ts = datetime.strptime(m.group(1), "%Y/%m/%d %H:%M:%S").replace(tzinfo=timezone.utc)
            return _cve_status_from_timestamp(ts, "ossec_log")

    metadata = _get_vulnerability_metadata_status_sync()
    if metadata["status"] != "unknown":
        return metadata

    return {
        "last_update": None,
        "minutes_ago": None,
        "status": "unknown",
        "source": "none",
    }


def _cve_status_from_timestamp(ts: datetime, source: str) -> dict[str, Any]:
    """Classify a vulnerability feed timestamp as fresh/stale/stuck."""
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    minutes_ago = int((datetime.now(timezone.utc) - ts).total_seconds() / 60)

    if minutes_ago < 60 * 36:        # < 36h → fresh
        status = "fresh"
    elif minutes_ago < 60 * 24 * 7:  # < 7d → stale (suspicious)
        status = "stale"
    else:
        status = "stuck"             # > 7d → broken
    return {
        "last_update": ts.isoformat(),
        "minutes_ago": minutes_ago,
        "status": status,
        "source": source,
    }


def _get_vulnerability_metadata_status_sync() -> dict[str, Any]:
    """Fallback for Wazuh 4.x vulnerability scanner metadata freshness."""
    out = _docker_exec(
        [
            "sh",
            "-c",
            "find /var/ossec/queue/vd_updater/rocksdb/updater_vulnerability_feed_manager_metadata "
            "-maxdepth 1 -type f \\( -name '*.sst' -o -name '[0-9]*.log' "
            "-o -name 'MANIFEST-*' -o -name 'CURRENT' \\) "
            "-printf '%T@ %p\\n' 2>/dev/null | sort -nr | head -1",
        ],
        timeout=10,
    )
    if not out:
        return {
            "last_update": None,
            "minutes_ago": None,
            "status": "unknown",
            "source": "vd_metadata",
        }

    try:
        epoch = float(out.split()[0])
    except (ValueError, IndexError):
        return {
            "last_update": None,
            "minutes_ago": None,
            "status": "unknown",
            "source": "vd_metadata",
        }

    return _cve_status_from_timestamp(datetime.fromtimestamp(epoch, timezone.utc), "vd_metadata")


def _get_agents_status_sync() -> dict:
    """Parse output of `/var/ossec/bin/agent_control -l`."""
    out = _docker_exec(["/var/ossec/bin/agent_control", "-l"], timeout=10)
    if not out:
        return {"total": 0, "active": 0, "disconnected": 0, "details": []}

    agents = []
    for line in out.splitlines():
        m = re.match(
            r"\s*ID:\s*(\d+),\s*Name:\s*([^,]+),\s*IP:\s*([^,]+),\s*(.+?)\s*$",
            line,
        )
        if m:
            agents.append({
                "id": m.group(1),
                "name": m.group(2).strip(),
                "ip": m.group(3).strip(),
                "status": m.group(4).strip(),
            })
    active = sum(1 for a in agents if "Active" in a["status"])
    return {
        "total": len(agents),
        "active": active,
        "disconnected": len(agents) - active,
        "details": agents,
    }


async def _get_agents_status_api() -> Optional[dict[str, Any]]:
    """Read agent status from Wazuh Manager API.

    This is the production path. The docker `agent_control` reader above is
    kept as a lab fallback for the bundled demo stack.
    """
    api_url = os.getenv("WAZUH_API_URL", "https://localhost:55000").rstrip("/")
    user = os.getenv("WAZUH_API_USER", "wazuh-wui")
    password = os.getenv("WAZUH_API_PASS", "")
    verify_ssl = os.getenv("WAZUH_VERIFY_SSL", "true").strip().lower() != "false"
    if not password:
        return None

    try:
        async with httpx.AsyncClient(verify=verify_ssl, timeout=10.0) as c:
            auth = await c.post(
                f"{api_url}/security/user/authenticate",
                auth=(user, password),
            )
            auth.raise_for_status()
            token = auth.json()["data"]["token"]
            r = await c.get(
                f"{api_url}/agents",
                params={"limit": 100, "select": "id,name,ip,status,os.platform,os.version,lastKeepAlive,version"},
                headers={"Authorization": f"Bearer {token}"},
            )
            r.raise_for_status()
            items = r.json().get("data", {}).get("affected_items", [])
    except Exception as e:
        log.warning("wazuh API agent lookup failed: %s", e)
        return None

    agents: list[dict[str, Any]] = []
    for item in items:
        os_info = item.get("os") if isinstance(item.get("os"), dict) else {}
        agents.append({
            "id": str(item.get("id") or ""),
            "name": item.get("name") or "",
            "ip": item.get("ip") or "",
            "status": item.get("status") or "unknown",
            "os_platform": os_info.get("platform") or "",
            "os_version": os_info.get("version") or "",
            "lastKeepAlive": item.get("lastKeepAlive") or "",
            "version": item.get("version") or "",
        })
    active = sum(1 for a in agents if str(a.get("status", "")).lower() == "active")
    return {
        "total": len(agents),
        "active": active,
        "disconnected": len(agents) - active,
        "details": agents,
        "source": "wazuh_api",
    }


async def _get_agents_status() -> dict[str, Any]:
    api_status = await _get_agents_status_api()
    if api_status is not None:
        return api_status
    return await asyncio.to_thread(_get_agents_status_sync)


# ─── Async wrappers ──────────────────────────────────────────────────────
async def _get_latest_wazuh_release() -> Optional[str]:
    """Query GitHub for the latest published Wazuh release tag."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as c:
            r = await c.get(
                "https://api.github.com/repos/wazuh/wazuh/releases/latest",
                headers={"Accept": "application/vnd.github+json"},
            )
            r.raise_for_status()
            return r.json().get("tag_name")
    except Exception as e:
        log.warning("github release lookup failed: %s", e)
        return None


async def collect_status() -> dict[str, Any]:
    """Gather every freshness signal we report on."""
    current_ver, cve, agents, stats, latest_ver = await asyncio.gather(
        asyncio.to_thread(_get_wazuh_version_sync),
        asyncio.to_thread(_get_cve_feed_status_sync),
        _get_agents_status(),
        db.compute_stats(),
        _get_latest_wazuh_release(),
    )

    version_status = "unknown"
    if current_ver and latest_ver:
        try:
            version_status = (
                "current" if _semver_tuple(current_ver) >= _semver_tuple(latest_ver)
                else "behind"
            )
        except Exception:
            pass

    return {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "bridge_uptime_s": int(time.time() - START_TIME),
        "wazuh": {
            "manager_version": current_ver,
            "latest_release":  latest_ver,
            "version_status":  version_status,
        },
        "cve_feed": cve,
        "agents":   agents,
        "alerts_24h": {
            "total":       stats.get("alerts_last_24h", 0),
            "errors":      stats.get("errors_last_24h", 0),
            "by_severity": stats.get("by_severity_24h", {}),
            "top_rules":   stats.get("top_rules_24h", []),
        },
    }


# ─── Slack formatting ────────────────────────────────────────────────────
def _human_minutes(m: Optional[int]) -> str:
    if m is None:
        return "—"
    if m < 60:
        return f"{m} 分鐘前"
    if m < 60 * 48:
        return f"{m // 60} 小時前"
    return f"{m // 60 // 24} 天前"


def format_digest_slack(status: dict[str, Any]) -> dict:
    wz   = status.get("wazuh")    or {}
    cve  = status.get("cve_feed") or {}
    ag   = status.get("agents")   or {}
    a24  = status.get("alerts_24h") or {}

    ver_emoji = {"current": "✅", "behind": "⚠️"}.get(wz.get("version_status"), "❓")
    cve_emoji = {"fresh": "✅", "stale": "⚠️", "stuck": "🔥"}.get(cve.get("status"), "❓")
    agent_emoji = "✅" if (ag.get("disconnected") or 0) == 0 else "⚠️"

    ver_note = {
        "current": "（已是最新）",
        "behind":  "→ **建議升級**",
        "unknown": "",
    }.get(wz.get("version_status"), "")

    cve_note = {
        "fresh":   "（正常）",
        "stale":   "— 已超過 36 小時，請檢查 manager 對外網路",
        "stuck":   "— 已超過 7 天，自動更新可能壞掉",
        "unknown": "（找不到更新紀錄，可能 manager 剛啟動）",
    }.get(cve.get("status"), "")

    sev_breakdown = a24.get("by_severity") or {}
    sev_str = " · ".join(f"{k}: {v}" for k, v in sorted(sev_breakdown.items())) or "（無告警）"

    # Health = green only if all 3 checks are happy
    healthy = (
        wz.get("version_status") in ("current",)
        and cve.get("status") == "fresh"
        and (ag.get("disconnected") or 0) == 0
        and a24.get("errors", 0) == 0
    )
    color = "#16a34a" if healthy else "#ea580c"  # green or orange

    lines = [
        f"*EdgeSec-Pi 每日資安狀態檢查*",
        "",
        f"{ver_emoji} *Wazuh 版本*：你裝的 `{wz.get('manager_version','?')}`，"
        f"上游最新 `{wz.get('latest_release','?')}` {ver_note}",
        "",
        f"{cve_emoji} *CVE 漏洞資料*：最後更新 {_human_minutes(cve.get('minutes_ago'))} {cve_note}",
        "",
        f"{agent_emoji} *受監控主機*：{ag.get('active',0)} / {ag.get('total',0)} 上線"
        + (
            f"（{ag.get('disconnected',0)} 台離線，請聯絡 IT 確認）"
            if (ag.get("disconnected") or 0) > 0 else "（全部正常）"
        ),
        "",
        f"📊 *過去 24 小時*：共 {a24.get('total',0)} 筆告警"
        + (f"（含 {a24['errors']} 筆 LLM 推論失敗）" if a24.get("errors") else ""),
        f"   分級：{sev_str}",
    ]

    top_rules = a24.get("top_rules") or []
    if top_rules:
        lines.append("")
        lines.append("   最常觸發的規則：")
        for r in top_rules[:3]:
            lines.append(f"     • `{r.get('rule_id','?')}` {(r.get('rule_description') or '')[:60]} ×{r.get('c',0)}")

    return {
        "attachments": [{
            "color":   color,
            "text":    "\n".join(lines),
            "footer":  f"EdgeSec-Pi · 每日 {DIGEST_HOUR_LOCAL:02d}:00 自動檢查",
            "ts":      int(time.time()),
            "mrkdwn_in": ["text"],
        }]
    }


def _acquire_scheduler_lock():
    """Keep only one daily digest scheduler active across bridge processes."""
    DIGEST_LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    lock_file = DIGEST_LOCK_PATH.open("w", encoding="utf-8")
    try:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        lock_file.close()
        return None

    lock_file.seek(0)
    lock_file.truncate()
    lock_file.write(f"pid={os.getpid()} started_at={datetime.now(timezone.utc).isoformat()}\n")
    lock_file.flush()
    return lock_file


# ─── Sender ──────────────────────────────────────────────────────────────
async def send_digest(slack_url: Optional[str]) -> dict:
    """Collect, optionally post to Slack, return the status dict."""
    status = await collect_status()
    slack_url = slack_url or notify_channels.get_config("SLACK_WEBHOOK_URL")
    if slack_url:
        payload = format_digest_slack(status)
        try:
            async with httpx.AsyncClient(timeout=10) as c:
                r = await c.post(slack_url, json=payload)
                log.info("digest posted: HTTP %d", r.status_code)
        except Exception as e:
            log.warning("digest slack post failed: %s", e)
    return status


# ─── Daily scheduler ─────────────────────────────────────────────────────
async def daily_scheduler(slack_url: Optional[str]) -> None:
    """Run forever; sleep until the next DIGEST_HOUR_LOCAL local-time, send, repeat.

    Intentionally simple: no cron, no APScheduler. macOS doesn't change
    timezone often, so a daily realign on each iteration is enough.
    """
    scheduler_lock = _acquire_scheduler_lock()
    if scheduler_lock is None:
        log.warning(
            "digest scheduler already active; this process will not post daily Slack digests"
        )
        return

    log.info("digest scheduler armed for %02d:00 local time daily", DIGEST_HOUR_LOCAL)
    try:
        while True:
            now = datetime.now()
            target = now.replace(
                hour=DIGEST_HOUR_LOCAL, minute=0, second=0, microsecond=0
            )
            if target <= now:
                target += timedelta(days=1)
            sleep_s = (target - now).total_seconds()
            log.info("next digest at %s (in %.1f h)", target.isoformat(timespec="seconds"), sleep_s/3600)

            try:
                await asyncio.sleep(sleep_s)
            except asyncio.CancelledError:
                log.info("digest scheduler stopping")
                return

            try:
                await send_digest(slack_url)
            except Exception:
                log.exception("daily digest run failed; will retry tomorrow")
    finally:
        fcntl.flock(scheduler_lock.fileno(), fcntl.LOCK_UN)
        scheduler_lock.close()
