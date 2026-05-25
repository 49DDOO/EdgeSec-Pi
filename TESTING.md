# Testing

EdgeSec-Pi tests are split by dependency level. The default test command runs
only deterministic tests that use temporary files and local fake HTTP services.

## Install Dev Dependencies

```bash
python3 -m pip install -r requirements-dev.txt
```

## Default Test Gate

```bash
./scripts/test.sh
```

This runs:

- `tests/unit` - config and packaging contracts.
- `tests/integration` - fake LM Studio, fake Wazuh MCP Server, bridge queue,
  SQLite persistence, back-pressure, MCP token refresh, enrichment, and
  agentic loop behavior.

It does not require Docker, real Wazuh, real LM Studio, or Slack.

## Batch Test Runner With Logs

For a single command that runs grouped checks and writes logs to files:

```bash
./test_sys/run_all.sh quick
```

Logs are written under:

```text
test_sys/logs/YYYYMMDD-HHMMSS/
```

Available modes:

| Command | Scope |
|---------|-------|
| `./test_sys/run_all.sh quick` | Backend default tests and dashboard lint/build. |
| `./test_sys/run_all.sh env` | Local service readiness check. |
| `./test_sys/run_all.sh release` | `quick` plus quality gate and mock eval. |
| `./test_sys/run_all.sh full` | `release` plus service readiness, real LM Studio model test, and Wazuh E2E smoke test. |
| `./test_sys/run_all.sh manual` | Prints manual interactive test entrypoints. |

## Unified Port / URL Config

Service ports and non-secret URLs are managed from:

```text
bridge.env
```

Shell scripts load the shared parser:

```text
scripts/lib/load-config.sh
```

To see the effective config before running real-environment tests:

```bash
./scripts/run.sh config
```

`wazuh-llm-bridge/.env` should be used for secrets such as tokens and passwords.
When the same port or URL exists in both files, `bridge.env` wins.

## Test Categories

| Command | Scope | External dependencies |
|---------|-------|-----------------------|
| `./scripts/test.sh unit` | Fast config/contracts. | None |
| `./scripts/test.sh integration` | Bridge + fake LM/MCP services. | None |
| `./scripts/test.sh model` | Real LM Studio tool-call compatibility. | LM Studio running |
| `./scripts/test.sh env` | Local service readiness check. | Bridge + LM Studio |
| `./scripts/test.sh e2e` | Real Wazuh agent -> manager -> bridge smoke test. | Wazuh stack + bridge |
| `./scripts/test.sh manual` | Prints interactive manual test entrypoints. | Slack / operator |
| `./scripts/test.sh eval-mock` | LLM evaluation harness sanity check. | None |
| `./scripts/test.sh eval-live` | LLM quality evaluation. | LM Studio running |

## Direct Pytest Usage

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python3 -m pytest -m "unit or integration" tests/unit tests/integration
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python3 -m pytest -m unit tests/unit
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python3 -m pytest -m integration tests/integration
```

Model tests are skipped unless explicitly enabled:

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 RUN_MODEL_TESTS=1 python3 -m pytest -m model tests/model
```

## Local Environment Readiness

```bash
./scripts/test.sh env
```

This checks the real services configured by `bridge.env`:

- `http://localhost:$BRIDGE_PORT/health`
- `http://127.0.0.1:3000`
- `http://localhost:$BRIDGE_PORT/docs`
- LM Studio `/v1/models` derived from `LM_STUDIO_URL`
- Wazuh API from `WAZUH_API_URL` when available
- MCP `/health` from `MCP_SERVER_URL` when configured

Bridge and LM Studio are required checks. Wazuh and MCP are reported as warnings
because they may be intentionally disabled for bridge-only development.

## Owner-Facing Self-Test

The dashboard also includes a non-technical self-test button:

```text
http://127.0.0.1:3000/settings/testing
```

It calls:

```text
GET /self-test
```

This endpoint returns Traditional Chinese status and next-step guidance for
owners. It does not inject fake Wazuh alerts and does not send Slack messages;
it only checks service readiness and recent alert data.

## Manual / E2E Tests

Real pipeline smoke test:

```bash
tests/e2e/smoke-test.sh
```

Interactive Slack scenario checks:

```bash
tests/manual/test_scenarios.sh
tests/manual/test_failures.sh
```

These are intentionally outside the default gate because they depend on running
services and human verification.

## What The Default Gate Proves

- `/webhook` returns `202` quickly and uses the async queue.
- Queue back-pressure returns `503` under burst load.
- LLM JSON is parsed into persisted SQLite fields.
- The test database is isolated under `tmp_path`.
- MCP `/auth/token` exchange works.
- MCP `401` responses trigger JWT refresh.
- MCP enrichment is injected only when a source IP exists.
- The agentic loop can call tools and submit a final verdict.
- The agentic loop records evidence and degrades when tool calls fail.
- Triage router force/never policy is deterministic.
