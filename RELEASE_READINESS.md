# Release Readiness

This checklist keeps EdgeSec-Pi honest before a public GitHub release. The goal
is a credible preview for SMB pilots, not a claim that this replaces a SIEM,
SOC, or production SOAR platform.

## Public Positioning

Recommended wording:

> EdgeSec-Pi is a preview-stage Wazuh alert assistant for small businesses. It
> turns raw Wazuh alerts into readable Traditional Chinese dashboard and
> notification workflows, with optional controlled response buttons.

Avoid claiming:

- "Complete SIEM"
- "Autonomous SOC"
- "Guaranteed protection"
- "One-click endpoint isolation works everywhere"
- "LLM makes the final security decision"

Wazuh is the detection source of truth. The LLM is used for summarization,
business-context explanation, and suggested next steps.

## Owner Installation Path

The owner-facing setup must stay short:

1. Set and test at least one notification channel.
2. Connect or install Wazuh.
3. Install endpoint agents.
4. Fill endpoint business context.
5. Wait for notifications and review only items that need action.

MCP, LobeChat, raw Wazuh searches, and Active Response tuning are advanced
operations for IT or an outsourced security partner.

## What Is Pilot-Ready

- FastAPI webhook intake with immediate `202 Accepted`.
- Bounded async queue and worker processing.
- Local LLM-compatible analysis through LM Studio-style APIs.
- SQLite alert history.
- Owner-facing dashboard.
- First-time setup checklist for Wazuh, AI, notifications, endpoint online
  status, hardening status, business context, and test alerts.
- Detection-category presets with noisy-category warnings.
- Bridge-level false-positive suppression for repeated known-noise alerts.
- MCP-backed Dashboard investigation with deterministic fast playbooks before
  the restricted tool loop.
- LINE, Slack, Telegram, and email notification configuration pages.
- Slack interactive actions when Bot Token + Socket Mode are configured.
- Active Response lifecycle tracking for block/isolate/release with TTL,
  retries, and audit rows.
- Deterministic unit and integration tests with fake LM/MCP services.
- Local macOS dashboard installer for evaluation.

## What Must Stay Marked Advanced

- Wazuh MCP Server and LobeChat.
- Wazuh Active Response outside a tested local/LAN environment.
- Endpoint isolation for any OS not explicitly verified on real machines.
- Production TLS / domain / reverse proxy.
- Multi-tenant deployment.
- Automatic remediation.

These features are useful, but they require clear authorization, environment
testing, and rollback planning.

## Freeze Gate

Before enabling endpoint isolation or broader detection presets for a pilot,
freeze the current response surface and verify these done criteria:

- Test `edgesec-ar` on real Linux, macOS, and Windows endpoints before adding
  that OS to `ACTIVE_RESPONSE_ISOLATION_VERIFIED_PLATFORMS`.
- Do not enable isolation in production for an OS that is not listed in the
  verified-platform gate.
- Confirm isolate, release, TTL release, reboot/fail-open behavior, and manager
  connectivity on each verified OS.
- Document that endpoint reboot intentionally clears local isolation rules
  (fail-open) and that the bridge state converges after TTL release/sweeper.
- Confirm the Dashboard can show active response failures clearly enough for IT
  to undo a bad action.

Detection presets should ship with a feedback loop, not as "turn everything on"
defaults. Sysmon, YARA, VirusTotal, and expanded FIM can produce useful signal,
but also increase false positives, API usage, and CPU cost. Keep bridge-level
false-positive suppression enabled so repeated known-noise alerts are archived
without another LLM call or owner notification.

The setup checklist must keep two hardening signals separate:

- Agent-group deployment/assignment proves Wazuh Manager pushed the optional
  hardening recipe to the expected OS group.
- Module event flow proves recent alerts actually arrived from modules such as
  FIM/SCA/Sysmon/VirusTotal/YARA.

Do not present agent-group membership as proof that every detection module is
working.

## Security Boundary

Before a public release:

- Keep `.env`, `bridge.env`, SQLite databases, logs, certificates, and
  `org_profile.yaml` out of git.
- Use `WEBHOOK_SECRET` when `/webhook` is reachable beyond the local Wazuh
  manager.
- Treat `ACTIVE_RESPONSE_TOKEN` as a password.
- Default destructive actions to review-only until the environment is tested.
- Document that endpoint isolation requires an explicitly installed and tested
  agent-side script. It is not a universal built-in Wazuh action.
- Keep raw alert fields, usernames, command lines, HTTP headers, and file paths
  framed as untrusted data in prompts. Deterministic guardrails and human
  approval must remain the authority for severity escalation and destructive
  actions.
- Keep false-positive suppressions visible and removable. A suppression rule can
  intentionally skip future LLM calls, so it must remain auditable.

## Test Gate

Run before tagging or announcing a release:

```bash
./scripts/test.sh
```

This proves deterministic code paths only. It does not prove real Wazuh, real
LM Studio, real Slack/LINE, or customer networking.

For a demo or pilot, also run:

```bash
./scripts/test.sh env
tests/e2e/smoke-test.sh
```

Then manually verify:

- Dashboard loads.
- Notification settings page can save and test one channel.
- An endpoint appears online.
- The setup checklist reports whether agent-groups are applied and whether
  recent module event flow exists.
- Business context can be saved.
- A sample alert produces readable notification text with endpoint name,
  business context, consequence, and next step.

## Known Release Risks

- Self-signed local HTTPS is confusing for non-technical users. For customer
  installs, prefer a real domain and trusted certificate.
- Wazuh agent installation differs by OS and by whether the manager is local,
  Docker-based, or already owned by the customer.
- LLM output quality depends on the loaded model. Keep prompt tests and sample
  alert evaluations visible.
- Response buttons can be misunderstood as fully automatic remediation. Label
  them as controlled actions and show failure reasons clearly.
