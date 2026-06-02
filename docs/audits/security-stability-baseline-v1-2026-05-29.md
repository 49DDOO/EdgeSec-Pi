# EdgeSec-Pi — 安全與穩定基線稽核 v1

**稽核日期:** 2026-05-29
**基準:** 實際程式碼查證 + 測試執行(unit 104 passed / 全套 105 passed, 1 failed, 1 skipped)
**定位判定:** 「負責的實驗版」— 尚未到可直接交付的穩定版
**主題一致性:** 未偏離 Wazuh(偵測)+ LLM(解釋/分流)+ 封鎖/隔離(回應)的初衷

---

## 0. 總結(Executive Summary)

EdgeSec-Pi 的**架構骨架與安全意識屬於 8 分等級**,明顯高於它所在的價位帶;真正的限制不在「會不會做」,而在「落地門檻太高」與「核心承諾(偵測覆蓋)尚未補滿」。

這一輪的關鍵轉變是:**從「一直加功能」轉向「補投資前的安全與穩定基線」**。這是 PoC → 可交付的分水嶺,方向正確。

| 維度 | 狀態 |
|---|---|
| 破壞性動作安全(封鎖/隔離) | 🟢 已達最低安全線 |
| Prompt 注入防護 | 🟢 資料隔離一致 |
| FP 誤報抑制閉環 | 🟢 功能 + 測試皆完成 |
| 隔離 capability gate | 🟢 已落地 |
| God module / 肥大 | 🟡 開始拆,仍有 1 個未處理 |
| 兩套 tool-loop 重複 | 🔴 未收斂(已選定方向) |
| MCP 安全查詢層 | 🟡 有邊界,未收斂成獨立模組 |
| 偵測 preset(抓得到) | 🔴 未實作 |
| LLM 體驗量測 | 🔴 未實作 |
| 真機矩陣 / 穩定性 | 🔴 未驗證 |

---

## 1. 已完成且查證通過的安全基線 🟢

### 1.1 破壞性回應的最低安全線
- 封鎖(block IP)與隔離(isolate endpoint)**均由人觸發**(Slack/Dashboard 按鈕 + HMAC 一次性 token),**LLM 不自動執行任何破壞性動作**。
- IP 嚴格驗證(`ipaddress` 解析、限 IPv4、拒非全域)、保護網段 + org_profile 資產白名單。
- **TTL 自動解除**:封鎖與隔離都有 sweeper + 重試/退避;隔離另有 `edgesec-ar` 端點自我到期。
- **原子 claim**:sweeper 的 `claim_expired_*` 帶狀態守衛的 UPDATE,避免多進程重複派送。
- 暫時性失敗(網路抖動)會自動重試,不再默默變永久封鎖。

### 1.2 隔離 capability gate(本輪新增)
- `isolation_capability()` + `isolation_verified_platforms()` + `/isolation-capability` API。
- **未驗證過的平台不顯示隔離按鈕**,不再只看 env var。符合「沒通過真機測試的 OS 不准標可安全啟用」的要求。
- `edgesec-ar` 三平台真防火牆(iptables/ip6tables、pfctl、Windows Firewall)、IPv6、切斷現有連線、保留管理通道、可逆、TTL 走真排程器(schtasks/at/systemd-run/launchd)。

### 1.3 Prompt 注入防護
- 所有攻擊者可控輸入(full_log、username、rule_description、observables、MCP 結果、SCA)統一以 `untrusted_data_block` 包裝(`DATA>` 前綴 + `BEGIN/END_QUOTED_DATA` 邊界)。
- 確定性護欄:嚴重度不靠模型自由心證(例:失敗後成功登入 → 強制升級)。

### 1.4 FP 誤報抑制閉環(功能 + 測試皆完成)
- 標記 false_positive → 建立 scoped suppression(rule + agent + source_ip)→ ingest 時 `match_false_positive_suppression` 命中即跳過 LLM、不送 Slack、直接歸檔。
- **測試覆蓋(`tests/unit/test_alert_case_status.py`)**:scoped 建立、三鍵命中、disable 後不命中、disable 二次回 False(rowcount 原子檢查)、`ENABLED=0` 不建立/不匹配、sample data 不建立/不匹配、過期不匹配且預設列表不顯示。

### 1.5 前端 prompt 收回後端
- 前端不再建構 prompt;`api.ts` 只送 `alert_id + question`。SOC policy 集中於 bridge,UI 改字不會改變查證行為。
- 查證 helper 收斂進 `dashboard/src/lib/investigation.ts`(共用,非各複製一份)。

---

## 2. Wazuh MCP Server 整合就緒度 🟡

**結論:整合層已「結構化、可控、可觀察」,但安全查詢邊界尚未收斂成獨立可重用模組。**

| 項目 | 狀態 | 證據 |
|---|---|---|
| 工具白名單(只允許特定 MCP 工具) | 🟢 | `investigation_chat._is_allowed_tool` 把關 |
| 參數正規化 / 不接受 raw query | 🟢 | `_normalize_tool_args`;不允許任意 Lucene 直接拼接 |
| 查詢結果結構化後才餵 LLM | 🟢 | 結果經 evidence block 包裝,非 raw JSON |
| **統一 safe-query builder 模組** | 🟡 | 邏輯散在 `investigation_chat.py`(1334 行),`mcp_client.py`(298)為薄客戶端;**尚未抽成獨立可重用層** |

> **修正先前過度樂觀的說法:** 「safe query builder 化」目前是「查詢邊界已存在但未模組化」。把它抽成獨立模組,正是下一步 tool-loop 收斂的自然產物。

---

## 3. God Module / 程式碼肥大 🟡(改善中)

| 檔案 | 前 | 現 | 評語 |
|---|---|---|---|
| `ops_api.py` | 1282 | **743** | ✅ 已拆(−539) |
| `active_response_safety.py` | 1262 | **439** | ✅ 拆出 `active_response_state.py`(862) |
| `admin_ui.py` | 1496 | 已大幅下降 | ✅ 瘦身/拆分 |
| `investigation_chat.py` | 1334 | **1334** | 🔴 未動,現為最大 god module |
| `alerts-table.tsx`(前端) | 1141 | 1102 | ➖ 幾乎未變 |

**判定:** god module 問題**從「五個破千」收斂到「一個破千 + 一個前端巨獸」**。最後的硬骨頭 `investigation_chat.py` 會在 tool-loop 收斂時一併解決。

---

## 4. 未爆點 / 待處理 🔴

| # | 項目 | 風險 | 說明 |
|---|---|---|---|
| 1 | 兩套 tool-loop 未收斂 | 中 | `agent_loop.py`(414)+ `investigation_chat.py`(1334)各自帶 `tool_choice`、重複 agentic 邏輯。**已選定方向:抽共用 loop 引擎 + 兩個薄入口。** |
| 2 | 偵測 preset 未實作 | 高(對核心承諾) | 無 Basic/Recommended/Aggressive 分級;「抓得到」仍靠手動開 agent-groups。需與 FP 抑制搭配以防告警洪水。 |
| 3 | LLM 體驗量測未實作 | 中 | 無「老闆/IT 對 AI 解釋是否正確」的回饋訊號(現有 "feedback" 是 FP 借詞)。差異化無法量化迭代。 |
| 4 | 真機矩陣未驗證 | 高(對隔離) | `edgesec-ar` 跨四平台、高權限、會改網路;沙箱綠燈 ≠ production-ready。需 Win/macOS/Linux 真機測 isolate/release/TTL/重開機 fail-open。 |
| 5 | backpressure 整合測試失敗 | 待查 | `tests/integration/test_bridge_smoke.py::...backpressure` 在本環境失敗(可能環境敏感/flaky),unit 全綠。建議本機重跑確認是否穩定失敗。 |

---

## 5. 行為事實(務必寫入正式文件)

1. **重開機 = 解除隔離(fail-open)**:iptables/pf 規則不持久,加上 transient systemd-timer 重開消失。對 SMB 友善(不會把機器鎖死),但「還中毒的機器重開就脫離隔離」要明示,且 bridge 狀態需能反映「可能已因重開失效」。
2. **管理通道是「聲明」非「驗證」**:bridge 強制管理員 ack「腳本會保留 manager 通道」,但無法檢查腳本真有做到。正確性最終落在 `edgesec-ar` 腳本(已內建保留 manager + 自我到期)。
3. **edgesec-ar 防刪除**:0750 + root 擁有 → 一般使用者刪不掉;root / 已提權木馬刪得掉(主機端工具共同宿命)。建議補 FIM 監控該目錄,把「防不了刪除」轉為「刪了會被偵測」。

---

## 6. 建議執行順序(全部不加新功能,先固基線)

1. **🔴 收斂兩套 tool-loop**(已選:共用引擎 + 薄入口)— 同時消最大 god module、去重複 agentic 邏輯,並把 MCP safe-query 抽成獨立層。
2. **🔴 偵測 preset + 噪音保護**(分級 + 速率/成本保護)— 補「抓得到」這個核心承諾,與已完成的 FP 抑制搭配。
3. **🟠 真機矩陣 + setup 檢查表接上 capability gate** — 讓「可安全啟用」由實測決定。
4. **🟡 LLM 體驗量測** — 老闆/IT 回饋訊號回流到 prompt 與規則評估。
5. **🟡 收尾 god module**:`investigation_chat`(隨 #1 解決)、`alerts-table.tsx` 拆子元件。

---

## 7. 定位結論

> **隔離已做到「夠負責」,不應再往 EDR 深挖。**
> 接下來的能量應拉回三件事:**偵測覆蓋(+FP 迴路)、LLM 白話判斷(+對錯量測)、安裝體驗(+真機驗證硬閘)。**

下一階段命名建議維持:**「Playbook-Driven MDR investigation」**,而非「Agentic SOC chatbot」——
固定 playbook + 時間線 evidence + deterministic correlation + 人可理解的結論 + 可追蹤的處置狀態。本輪的 tool-loop 收斂與 MCP safe-query 模組化,正是讓這個命名真正成立的基礎建設。

---
*本報告所有狀態均以實際程式碼查證,非依宣稱。標 🔴 者為查證後確認尚未實作或失敗。*
