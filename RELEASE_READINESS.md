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
- LINE, Slack, Telegram, and email notification configuration pages.
- Slack interactive actions when Bot Token + Socket Mode are configured.
- Deterministic unit and integration tests with fake LM/MCP services.
- Local macOS dashboard installer for evaluation.

## What Must Stay Marked Advanced

- Wazuh MCP Server and LobeChat.
- Wazuh Active Response.
- Endpoint isolation.
- Production TLS / domain / reverse proxy.
- Multi-tenant deployment.
- Automatic remediation.

These features are useful, but they require clear authorization, environment
testing, and rollback planning.

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

