#!/usr/bin/env bash

# ── Load bridge config ─────────────────────────────────
_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$_SCRIPT_DIR/../../scripts/lib/load-config.sh"

#
# test_failures.sh — Sprint 2D 失敗情境驗證
#
# Bridge 設計上應該對 dependency 掛掉「優雅降級」而不是 crash。
# 這支腳本主動把 dependency 拉下來、發 alert、再看 bridge 行為。
#
# 3 個情境：
#   1. MCP server down  → enrichment 失敗、agentic tool 失敗，Stage-1 仍 OK
#   2. LM Studio down   → Stage-1 失敗，DB 記 error_msg，bridge 不 crash
#   3. 恢復後            → 下一筆 alert 應自動正常，不必重啟 bridge
#

set -e
BRIDGE_HOST="${BRIDGE_HOST:-$BRIDGE_LOCAL_BASE}"
MCP_CONTAINER="${MCP_CONTAINER:-wazuh-mcp-server}"

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m⚠\033[0m %s\n' "$*"; }
fail() { printf '  \033[31m✗\033[0m %s\n' "$*"; exit 1; }
pause() { read -rp "→ $* " _; }

send_alert() {
  local payload="$1"
  curl -sS -X POST "$BRIDGE_HOST/webhook" \
       -H 'Content-Type: application/json' -d "$payload"
  echo
}

# Canonical test alert — SSH brute force (Case 1 from test_scenarios.sh)
ALERT='{"rule":{"id":"5712","level":10,"description":"sshd brute force","groups":["syslog","sshd"]},
 "agent":{"id":"002","name":"wazuh-agent-01"},
 "data":{"srcip":"203.0.113.99"},
 "full_log":"Failed password for invalid user admin from 203.0.113.99 port 55501 ssh2"}'

# ── Pre-flight ────────────────────────────────────────────────
bold "Sprint 2D — Failure mode verification"
echo
echo "本測試會："
echo "  1. 把 MCP server 短暫 pause 起來，看 bridge 是否優雅降級"
echo "  2. 請你手動把 LM Studio Local Server 停掉，看 bridge 是否不 crash"
echo "  3. 各自恢復後驗證 bridge 自動回復"
echo
echo "全程不會動到 SQLite 或 Slack — 失敗的 alert 會留在 DB 給你事後 inspect。"
echo

bold "Pre-flight"
curl -fsS "$BRIDGE_HOST/health" > /dev/null || fail "bridge 不在 $BRIDGE_HOST/health"
ok "bridge alive"

if ! docker ps --format '{{.Names}}' | grep -q "^${MCP_CONTAINER}\$"; then
  fail "找不到 MCP container '$MCP_CONTAINER' — 設環境變數 MCP_CONTAINER=<name> 來指定"
fi
ok "MCP container '$MCP_CONTAINER' 在跑"
echo

# ──────────────────────────────────────────────────────────────
bold "════════════════════════════════════════════════════════════"
bold "▶ Scenario 1: MCP server down"
bold "════════════════════════════════════════════════════════════"
echo
echo "暫停 MCP container ($MCP_CONTAINER)..."
docker pause "$MCP_CONTAINER" > /dev/null
ok "MCP paused"

# 驗證 MCP 真的不通了
if curl -fsS --max-time 3 "$MCP_SERVER_URL/health" > /dev/null 2>&1; then
  warn "MCP /health 還回應了？pause 沒生效"
else
  ok "MCP $MCP_SERVER_URL 已斷"
fi

echo
echo "送一筆 SSH brute force alert（會觸發 MCP enrichment + 可能 agentic）..."
send_alert "$ALERT"

echo
cat <<'EXPECT'
預期觀察（切到 uvicorn log 視窗看）：
  • "MCP enrichment failed: ..."  WARNING
  • Stage-1 LLM 仍然完整跑（沒有 MCP context，但 alert 還能翻譯）
  • 如果 LLM 升級到 agentic，每個 tool call 會收到 "(tool error: ...)"
    最後 LLM 應該還是會 submit_final_verdict 收尾
  • Slack 仍然會收到訊息（可能沒有 AI 調查段或者調查段較弱）
  • bridge /health 仍然 200 OK
EXPECT
echo

pause "切去 uvicorn 視窗看完 log，覺得 OK 按 ENTER 恢復 MCP 並進下一步..."

docker unpause "$MCP_CONTAINER" > /dev/null
sleep 3
ok "MCP unpaused"

# ──────────────────────────────────────────────────────────────
bold "════════════════════════════════════════════════════════════"
bold "▶ Scenario 2: LM Studio Local Server down"
bold "════════════════════════════════════════════════════════════"
echo
warn "需要你手動操作 LM Studio app："
echo "  1. 切到 LM Studio 應用程式"
echo "  2. 左側 'Developer' or 'Local Server' 區塊"
echo "  3. 把 Server Running 切換成 STOPPED"
echo "  4. 等 5 秒讓 $LM_STUDIO_MODELS_URL 真的關掉"
echo
echo "確認 LM Studio 真的關了："
echo "  curl -sS $LM_STUDIO_MODELS_URL  # 應該回 connection refused"
echo
pause "LM Studio Local Server 已停止？按 ENTER 繼續..."

echo
echo "再驗證一次 LM Studio 確實不通..."
if curl -fsS --max-time 3 "$LM_STUDIO_MODELS_URL" > /dev/null 2>&1; then
  warn "LM Studio 還在回應，請確認真的停掉了"
  pause "停掉後按 ENTER 繼續..."
fi
ok "LM Studio $LM_STUDIO_MODELS_URL 已斷"

echo
echo "送同一筆 alert..."
send_alert "$ALERT"

echo
cat <<'EXPECT'
預期觀察：
  • bridge log 應該有 "Stage-1 error: ..." WARNING（或 agentic 失敗 fallback）
  • bridge 不會 crash
  • 沒有 Slack 訊息（因為 answer 是空的）
  • DB 應該有一筆 latency_ms + error_msg 的紀錄
  • /health 仍然 200 OK，workers 還在
EXPECT
echo

echo "驗證 bridge 還活著..."
curl -sS "$BRIDGE_HOST/health" && echo
echo

echo "看最近一筆 DB 紀錄是否有 error_msg..."
curl -sS "${BRIDGE_HOST}/alerts?limit=1" | python3 -m json.tool 2>/dev/null | head -30
echo

pause "看完 log + DB 紀錄，把 LM Studio 重新打開（Server Running → ON），按 ENTER 繼續..."

echo
echo "等 3 秒讓 LM Studio 服務起來..."
sleep 3
if ! curl -fsS --max-time 5 "$LM_STUDIO_MODELS_URL" > /dev/null 2>&1; then
  warn "LM Studio 還沒回應，再等 5 秒..."
  sleep 5
fi
ok "LM Studio 回應正常"

# ──────────────────────────────────────────────────────────────
bold "════════════════════════════════════════════════════════════"
bold "▶ Scenario 3: 服務恢復後 — bridge 自動回復"
bold "════════════════════════════════════════════════════════════"
echo
echo "送同一筆 alert（不重啟 bridge）..."
send_alert "$ALERT"

echo
cat <<'EXPECT'
預期觀察：
  • Stage-1 LLM 應該正常回應
  • Slack 應該收到完整訊息（含 AI 調查段，如果有升級）
  • Bridge 完全不必重啟，自動就好了
EXPECT
echo

pause "看完最後一輪 log + Slack 確認自動回復，按 ENTER 結束..."

# ──────────────────────────────────────────────────────────────
bold "════════════════════════════════════════════════════════════"
ok "Sprint 2D 全部跑完"
bold "════════════════════════════════════════════════════════════"

cat <<'EOF'

檢查重點總結：

  □ MCP 掛掉 → Stage-1 LLM 仍能跑、Slack 仍收到訊息
  □ MCP 掛掉時 agentic 工具呼叫優雅降級（收到 "(tool error: ...)" 不 crash）
  □ LM Studio 掛掉 → bridge 不會 crash，error_msg 寫進 DB
  □ /health 在所有失敗情境下都還 200 OK
  □ 服務恢復後不必重啟 bridge，下一筆 alert 自動正常

如果某項沒過，把 uvicorn 對應時間的 log 段落貼出來，我們對症修。
EOF
