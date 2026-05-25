#!/usr/bin/env bash

# ── Load bridge config ─────────────────────────────────
_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$_SCRIPT_DIR/../../scripts/lib/load-config.sh"

#
# test_scenarios.sh — 7 個情境的多樣性壓力測試
#
# 每跑完一個 case 會暫停，讓你切去 Slack 看訊息再按 ENTER 繼續。
# 整輪約 5–7 分鐘（agentic 路徑每 case ~40s，quick 路徑 ~20s + 看圖時間）。
#
# 跑這支前確認：
#   1. uvicorn app:app --host 0.0.0.0 --port $BRIDGE_PORT --env-file .env  (還在跑)
#   2. LM Studio Gemma 4 31B 還 loaded + Local Server Running
#   3. Wazuh stack 起著（讓 MCP enrichment 拿得到歷史）
#

set -e
BRIDGE_HOST=${BRIDGE_HOST:-$BRIDGE_LOCAL_BASE}
URL="${BRIDGE_HOST}/webhook"
HEALTH="${BRIDGE_HOST}/health"

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m⚠\033[0m %s\n' "$*"; }
fail() { printf '  \033[31m✗\033[0m %s\n' "$*"; exit 1; }

# ── Pre-flight ───────────────────────────────────────────────────
bold "Pre-flight check"
if ! curl -fsS "$HEALTH" > /dev/null 2>&1; then
  fail "bridge not reachable at $HEALTH — start it first:
      cd EdgeSec-Pi/wazuh-llm-bridge
      uvicorn app:app --host 0.0.0.0 --port $BRIDGE_PORT --env-file .env"
fi
ok "bridge is alive"
echo

# ── Helper ───────────────────────────────────────────────────────
run() {
  local n="$1"; local label="$2"; local expect="$3"; local payload="$4"
  echo
  bold "════════════════════════════════════════════════════════"
  bold "▶ Case $n: $label"
  printf "  預期路徑：%s\n" "$expect"
  bold "════════════════════════════════════════════════════════"
  curl -sS -X POST "$URL" -H 'Content-Type: application/json' -d "$payload"
  echo
  read -rp "→ 切去 Slack 看訊息，看完按 ENTER 跑下一個（Ctrl+C 中止）… " _
}

# ─── Case 1：SSH brute force（默認路徑 → llm_decides → 升級 agentic） ───
run 1 \
  "SSH brute force（外部 IP 連續失敗）" \
  "llm_decides → Stage-1 應自評需升級 → 跑 agentic loop" \
'{"rule":{"id":"5712","level":10,"description":"sshd brute force","groups":["syslog","sshd"]},
 "agent":{"id":"002","name":"wazuh-agent-01"},
 "data":{"srcip":"203.0.113.99"},
 "full_log":"Failed password for invalid user admin from 203.0.113.99 port 55501 ssh2"}'

# ─── Case 2：CIS SCA 合規檢查（NEVER 群組） ───
run 2 \
  "macOS 防火牆未啟用（CIS SCA failed）" \
  "quick（NEVER groups=sca 鎖在 Stage-1，不會 agentic 升級）" \
'{"rule":{"id":"19007","level":3,"description":"CIS Apple macOS - Firewall not enabled","groups":["sca","compliance"]},
 "agent":{"id":"002","name":"wazuh-agent-01"},
 "data":{"sca":{"check":{"title":"Ensure Firewall is Enabled","result":"failed","rationale":"A firewall protects against unauthorized network access.","remediation":"Open System Settings > Network > Firewall and toggle on."}}},
 "full_log":"SCA: CIS 5.2.3 Firewall check failed"}'

# ─── Case 3：CVE 高危漏洞（預期 agent 改查 vuln） ───
run 3 \
  "高危 CVE（xz-utils CVE-2024-3094 CVSS 10）" \
  "llm_decides → 預期升級 → agent 應呼叫 get_critical_vulnerabilities" \
'{"rule":{"id":"23504","level":10,"description":"Vulnerability detector: high-severity CVE","groups":["vulnerability-detector"]},
 "agent":{"id":"002","name":"wazuh-agent-01"},
 "data":{"vulnerability":{"cve":"CVE-2024-3094","cvss3":10.0,"package":{"name":"xz-utils","version":"5.6.0"},"reference":"https://nvd.nist.gov/vuln/detail/CVE-2024-3094"}},
 "full_log":"Vulnerable package xz-utils 5.6.0 detected (CVE-2024-3094, CVSS 10.0)"}'

# ─── Case 4：FIM 敏感檔被改（預期 agent 查 process） ───
run 4 \
  "/etc/passwd 被修改（FIM）" \
  "llm_decides → 預期升級 → agent 應呼叫 get_agent_processes 看可疑程式" \
'{"rule":{"id":"550","level":7,"description":"Integrity checksum changed","groups":["syscheck"]},
 "agent":{"id":"002","name":"wazuh-agent-01"},
 "data":{"syscheck":{"path":"/etc/passwd","event":"modified","audit":{"process":{"name":"vim"},"user":{"name":"root"}}}},
 "full_log":"File /etc/passwd was modified by user root using vim"}'

# ─── Case 5：Level 14 攻擊（FORCE level≥12 → 跳過 Stage-1） ───
run 5 \
  "Web SQL injection（level 14）" \
  "agentic（FORCE level≥12 → 直接深度調查，不走 Stage-1）" \
'{"rule":{"id":"31103","level":14,"description":"Multiple SQL injection attempts","groups":["web","attack"]},
 "agent":{"id":"003","name":"web-server-prod"},
 "data":{"srcip":"198.51.100.42"},
 "full_log":"Multiple SQLi signatures matched from 198.51.100.42 against /login.php"}'

# ─── Case 6：低風險合法登入（預期不升級） ───
run 6 \
  "合法用戶 SSH 登入成功" \
  "llm_decides → Stage-1 應判 needs_investigation=false → 不升級" \
'{"rule":{"id":"5501","level":3,"description":"PAM: session opened","groups":["syslog","pam"]},
 "agent":{"id":"002","name":"wazuh-agent-01"},
 "data":{"srcuser":"alice"},
 "full_log":"pam_unix(sshd:session): session opened for user alice(uid=501)"}'

# ─── Case 7：NEVER 壓過 FORCE level（優先級驗證） ───
run 7 \
  "Level 14 但屬 sca 群組（NEVER vs FORCE 優先級）" \
  "quick（NEVER groups=sca 應壓過 FORCE level≥12）" \
'{"rule":{"id":"19099","level":14,"description":"CIS critical compliance gap","groups":["sca"]},
 "agent":{"id":"002","name":"wazuh-agent-01"},
 "data":{"sca":{"check":{"title":"Disk encryption","result":"failed","remediation":"Enable FileVault."}}},
 "full_log":"SCA: disk encryption not enforced"}'

# ── Summary checklist ────────────────────────────────────────────
cat <<'EOF'

═══════════════════════════════════════════════════════════════════
✅ 全部 7 個 case 跑完。請檢查：

  □ Case 1 / 3 / 4 / 5 → Slack 有 「🔍 AI 怎麼調查的」 區塊（白話中文）
  □ Case 2 / 6 / 7    → Slack 「沒有」 「🔍 AI 怎麼調查的」 區塊
  □ Case 5            → uvicorn log 看到 "agentic loop (admin policy)"
                       （而不是 "Stage-1" 路徑）
  □ Case 7            → uvicorn log 看到 "triage → quick"
                       （level=14 但仍被 NEVER 鎖住）
  □ Case 3            → agent 應該選 get_critical_vulnerabilities
                       而不是 search_security_events
  □ Case 4            → agent 應該選 get_agent_processes
                       而不是 search_security_events
  □ 白話品質           → 所有「🔍 AI 怎麼調查的」內容是否：
                         - 沒英文技術詞
                         - 工具名稱有翻成具體動作
                         - 結尾有「因此...」判斷邏輯

═══════════════════════════════════════════════════════════════════

把以下三樣貼回來我幫你看：
  1. uvicorn 的完整 log（從 "Case 1" 開始到最後）
  2. 任 3 張 Slack 截圖（建議 Case 3、Case 5、Case 7 — 路徑差異最大）
  3. 任何「白話寫得怪」或「工具選錯」的 case 標號

EOF
