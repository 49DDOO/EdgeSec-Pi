"""
Replay Wazuh's built-in sample alerts into the EdgeSec-Pi bridge.
================================================================

Workflow:
  1. In Wazuh Dashboard → ☰ → Indexer management → Sample Data,
     press "Add data" on each module you want to test (Security Events,
     Threat Intelligence, Endpoint Security, etc).
  2. Wazuh injects ~200-500 sample alerts into `wazuh-alerts-4.x-sample-*`
     indices on the indexer.
  3. Run this script. It scrolls those indices and POSTs each `_source`
     document to the bridge's /webhook, simulating what would happen if
     those alerts had actually flowed through the integrator.

This is intentionally read-only against the indexer (no modifications)
and write-only against the bridge — safe to abort mid-run.

Usage:
  python tools/replay_sample_alerts.py                       # all defaults
  python tools/replay_sample_alerts.py --dry-run             # count only
  python tools/replay_sample_alerts.py --limit 20            # first 20 alerts
  python tools/replay_sample_alerts.py --rate 2              # 2 req/s
  python tools/replay_sample_alerts.py --rule-id 5712        # filter to one rule
  python tools/replay_sample_alerts.py --min-level 7         # only level >= 7
  python tools/replay_sample_alerts.py \\
      --indexer-url https://localhost:9200 \\
      --indexer-user admin \\
      --indexer-pass SecretPassword \\
      --bridge-url   http://localhost:$BRIDGE_PORT/webhook  (default from env BRIDGE_PORT)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Iterator

import httpx

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parents[2] / "bridge.env", override=False)
except ImportError:
    pass


# ─── defaults (override via flags or env vars) ─────────────────────────────
DEF_INDEXER_URL = os.getenv("WAZUH_INDEXER_URL", "https://localhost:9200")
DEF_INDEXER_U   = os.getenv("WAZUH_INDEXER_USER", "admin")
DEF_INDEXER_P   = os.getenv("WAZUH_INDEXER_PASS", "SecretPassword")
# ── Port unified via bridge.env ──────────────────────────
_DEF_PORT = os.getenv("BRIDGE_PORT", "8001")
DEF_BRIDGE_URL  = os.getenv("BRIDGE_URL", f"http://localhost:{_DEF_PORT}/webhook")
DEF_INDEX_PAT   = os.getenv("SAMPLE_INDEX_PATTERN", "wazuh-alerts-4.x-sample-*")


# ─── indexer scroll ─────────────────────────────────────────────────────────
def iter_sample_alerts(client: httpx.Client,
                       indexer_url: str,
                       index_pattern: str,
                       batch: int = 500) -> Iterator[dict[str, Any]]:
    """Stream all sample alerts via the OpenSearch scroll API.

    Scroll keeps a server-side snapshot so we don't miss documents if the
    index grows during the run. We close the scroll when finished.
    """
    # Open scroll
    r = client.post(
        f"{indexer_url}/{index_pattern}/_search?scroll=2m",
        json={"size": batch, "query": {"match_all": {}}},
    )
    r.raise_for_status()
    payload = r.json()
    scroll_id = payload.get("_scroll_id")
    hits      = payload.get("hits", {}).get("hits", [])

    try:
        while hits:
            for h in hits:
                src = h.get("_source")
                if isinstance(src, dict):
                    yield src
            # Continue scroll
            r = client.post(
                f"{indexer_url}/_search/scroll",
                json={"scroll": "2m", "scroll_id": scroll_id},
            )
            r.raise_for_status()
            payload = r.json()
            scroll_id = payload.get("_scroll_id", scroll_id)
            hits      = payload.get("hits", {}).get("hits", [])
    finally:
        # Clean up the scroll on the server (best-effort)
        if scroll_id:
            try:
                client.delete(
                    f"{indexer_url}/_search/scroll",
                    json={"scroll_id": [scroll_id]},
                )
            except Exception:
                pass


# ─── filter ─────────────────────────────────────────────────────────────────
def keep(alert: dict[str, Any],
         rule_id: str | None,
         min_level: int | None,
         category: str | None) -> bool:
    rule = alert.get("rule") or {}
    if rule_id is not None and str(rule.get("id")) != str(rule_id):
        return False
    if min_level is not None:
        lvl = rule.get("level")
        try:
            if int(lvl) < min_level:
                return False
        except (TypeError, ValueError):
            return False
    if category:
        groups = [str(g).lower() for g in (rule.get("groups") or [])]
        if category.lower() not in groups:
            return False
    return True


# ─── main ───────────────────────────────────────────────────────────────────
def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--indexer-url",  default=DEF_INDEXER_URL)
    p.add_argument("--indexer-user", default=DEF_INDEXER_U)
    p.add_argument("--indexer-pass", default=DEF_INDEXER_P)
    p.add_argument("--bridge-url",   default=DEF_BRIDGE_URL,
                   help="POST target. Set to '' or pass --dry-run to skip POSTing.")
    p.add_argument("--index-pattern", default=DEF_INDEX_PAT)

    p.add_argument("--limit",   type=int, default=None,
                   help="Stop after N alerts (after filtering).")
    p.add_argument("--rate",    type=float, default=5.0,
                   help="Max POSTs per second. 0 = unlimited.")
    p.add_argument("--rule-id",   default=None, help="Keep only this rule_id.")
    p.add_argument("--min-level", type=int, default=None,
                   help="Keep only alerts with rule.level >= N.")
    p.add_argument("--category",  default=None,
                   help="Keep only alerts whose rule.groups contains this tag "
                        "(e.g. 'authentication_failed', 'vulnerability').")
    p.add_argument("--dry-run",  action="store_true",
                   help="Pull + count + show first match, do NOT POST.")
    p.add_argument("--insecure", action="store_true", default=True,
                   help="Skip TLS verify on the indexer (default for self-signed labs).")
    args = p.parse_args()

    print(f"  indexer:   {args.indexer_url}  (index: {args.index_pattern})")
    print(f"  bridge:    {args.bridge_url}{'  [DRY-RUN]' if args.dry_run else ''}")
    if args.rule_id   is not None: print(f"  filter:    rule_id={args.rule_id}")
    if args.min_level is not None: print(f"  filter:    min_level={args.min_level}")
    if args.category  is not None: print(f"  filter:    category={args.category}")
    if args.limit     is not None: print(f"  limit:     {args.limit}")
    print()

    # Single shared client; basic auth for the indexer.
    indexer_client = httpx.Client(
        auth=(args.indexer_user, args.indexer_pass),
        verify=not args.insecure,
        timeout=30.0,
    )
    bridge_client = httpx.Client(timeout=10.0)

    sent = 0
    skipped = 0
    errors = 0
    first_shown = False
    sleep_s = (1.0 / args.rate) if (args.rate and args.rate > 0) else 0.0
    t_start = time.perf_counter()

    try:
        for alert in iter_sample_alerts(indexer_client,
                                        args.indexer_url,
                                        args.index_pattern):
            if not keep(alert, args.rule_id, args.min_level, args.category):
                skipped += 1
                continue

            # Show the first surviving alert so you can sanity-check filters.
            if not first_shown:
                rule = alert.get("rule") or {}
                print(f"  first match → rule_id={rule.get('id')} "
                      f"level={rule.get('level')} desc={rule.get('description')!r:.80}")
                first_shown = True

            if args.dry_run:
                sent += 1
            else:
                try:
                    r = bridge_client.post(
                        args.bridge_url,
                        json=alert,
                        headers={"Content-Type": "application/json"},
                    )
                    if r.status_code in (200, 201, 202):
                        sent += 1
                    elif r.status_code == 503:
                        # Bridge is back-pressuring; wait and retry once.
                        time.sleep(0.5)
                        r2 = bridge_client.post(args.bridge_url, json=alert)
                        if r2.status_code in (200, 201, 202):
                            sent += 1
                        else:
                            errors += 1
                    else:
                        errors += 1
                except Exception as e:
                    errors += 1
                    print(f"  ! POST failed: {e!r}", file=sys.stderr)

            if args.limit is not None and sent >= args.limit:
                break
            if sleep_s:
                time.sleep(sleep_s)

            # Heartbeat every 25 alerts so the operator sees progress.
            if (sent + skipped) and (sent + skipped) % 25 == 0:
                print(f"  ... sent={sent} skipped={skipped} errors={errors}")
    except httpx.HTTPStatusError as e:
        print(f"\nindexer error: {e}\n"
              f"  did you press 'Add data' in Dashboard → Indexer management "
              f"→ Sample Data?\n"
              f"  index pattern in use: {args.index_pattern}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"\nfatal: {e!r}", file=sys.stderr)
        return 1
    finally:
        indexer_client.close()
        bridge_client.close()

    elapsed = time.perf_counter() - t_start
    print(f"\ndone in {elapsed:.1f}s — "
          f"sent={sent}  skipped={skipped}  errors={errors}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
