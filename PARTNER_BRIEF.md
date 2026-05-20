# EdgeSec-Pi — 技術簡報（Partner / SI / MSSP 視角）

**LLM-Augmented SIEM Translation & Response Layer for the SMB Segment**

---

## 1. 摘要

EdgeSec-Pi 是建構於 Wazuh 4.14 之上的**告警翻譯與半自動回應層** (Alert Triage & Semi-Auto Response Layer)，專為 5–50 endpoint 規模、缺乏專職 SOC 人力的中小企業設計。

核心架構是 **Wazuh 偵測引擎 + 本地 LLM 推論（Gemma 4 31B / MLX）+ Slack Bolt 互動式工作流**，將 Wazuh 規則引擎產出的英文技術告警，轉譯為非技術主管可即時閱讀並執行決策的中文化通知，搭配 Slack Block Kit 互動按鈕直接觸發 Wazuh Active Response API（如 `firewall-drop`），實現端到端 30 秒內的**人在迴路 (human-in-the-loop) 自動化封鎖**。

**對資安公司而言，EdgeSec-Pi 不是競品——是補強既有產品線無法服務的下沉市場 (under-served segment) 的可整合元件。**

---

## 2. 技術架構

### 2.1 元件堆疊

| 層 | 元件 | 角色 |
|----|------|------|
| **採集** | Wazuh agent (Linux / macOS / Windows / Docker) | OS-level 事件採集（日誌、FIM、Syscollector、Rootcheck） |
| **規則引擎** | Wazuh Manager (analysisd) | 4000+ 條官方規則 + decoders；產出標準化 alerts.json |
| **整合分發** | Wazuh `integratord` daemon | 透過 `<integration>` block 將符合 level 過濾的告警 webhook 出去 |
| **告警翻譯** | EdgeSec-Pi Bridge (FastAPI + asyncio) | 接收 webhook、佇列管理、調用 LLM、保存歷史 |
| **LLM 推論** | LM Studio + Gemma 4 31B-A3B (MLX 8-bit) | 本地推論，產出結構化 JSON（severity / IOCs / MITRE / 中英文 dual-track 摘要） |
| **互動界面** | Slack App (Socket Mode + Block Kit) | 推送告警卡片 + 互動按鈕；支援 Active Response 觸發與 audit trail |
| **歷史 / 查詢** | SQLite (WAL mode) + REST API | `/alerts`、`/stats`、`/status` 端點 |
| **回應動作** | Wazuh REST API `/active-response` + 本機 pfctl | 透過 `firewall-drop0` 命令調用 agent 端 binary，整合 macOS pfctl 與 Linux iptables |

### 2.2 資料流（簡化）

```
endpoint event
 → wazuh-agent (encrypted 1514/tcp)
 → wazuh-analysisd (rule + decoder evaluation)
 → wazuh-integratord (POST → bridge $BRIDGE_PORT/webhook)
 → asyncio.Queue (bounded, back-pressure)
 → worker → LM Studio /v1/chat/completions
 → JSON parse → SQLite INSERT → Slack chat.postMessage with Block Kit
 → user click → Slack Socket Mode → bridge handler
 → wazuh REST PUT /active-response
 → agent exec /Library/Ossec/active-response/bin/firewall-drop
 → pfctl wazuh_fwtable add <ip>
 → bridge updates Slack message via respond() (audit trail preserved)
```

### 2.3 設計決策

| 決策 | 理由 |
|------|------|
| **本地 LLM 推論** | 資料主權（GDPR / 個資法 / 客戶 NDA）+ deterministic latency + zero per-alert OPEX |
| **Async + bounded queue + back-pressure** | 告警 burst 時 503 觸發 Wazuh integratord 重送，避免 OOM 或丟失告警 |
| **Slack Socket Mode（非 incoming webhook）** | 互動式按鈕需要雙向通訊；Socket Mode 不需 public HTTPS endpoint，符合 SMB 內網部署 |
| **Block Kit + 嚴重度色階 + 雙語 layout** | 同一張卡片同時服務非技術主管（中文摘要、影響、立即動作）與 IT（rule ID / MITRE / IOCs / raw log） |
| **Audit trail 留 Slack channel** | 滿足部分合規稽核需求（who / when / what）；不需額外 IR ticketing 系統 |
| **Active Response via Wazuh API（非 SSH / agent rewrite）** | 沿用 Wazuh 官方派發機制；保留與 Wazuh ruleset 升級相容性 |

---

## 3. 偵測覆蓋範圍

繼承 Wazuh ruleset 既有覆蓋，無自製規則：

| 類別 | 涵蓋 |
|------|------|
| 入侵偵測 | sshd brute force、SQLi、Path Traversal、Web Shell、PowerShell 混淆等（rule 5xxx / 31xxx / 91xxx） |
| 端點異常 | rootcheck、FIM、syscheck（rule 5xx / 550 / 510） |
| 漏洞偵測 | Wazuh vulnerability-detector module（每日自動拉 NVD / Canonical / Microsoft / Red Hat OVAL feeds） |
| 合規 | CIS Benchmark（Linux / macOS / Windows）、PCI-DSS、HIPAA、GDPR、ISO 27001 mapping（rule 19xxx） |
| Active Response | firewall-drop、host-deny、disable-account、process kill（內建 + 可擴充） |

**MITRE ATT&CK 對映由 Wazuh ruleset 提供**，LLM 層在輸出時自動帶 `mitre.id` 欄位（譬如 T1110 Brute Force、T1059.001 PowerShell、T1078 Valid Accounts）。

---

## 4. LLM 增強層的方法論

不只是單純把 alert 餵給 LLM 翻譯，**Prompt 結構針對 SMB 場景做過 4 個方向的調校**：

### 4.1 嚴重度語料化（Severity Rubric）

預設 5 級 (`critical / high / medium / low / info`) 各帶具體判準範例（譬如「critical = active compromise 含 rootkit / RCE in progress / shadow tampering」），避免 LLM 自主編造分級邏輯。

**實測（自建 15 筆 corpus）**：Gemma 4 31B 嚴重度命中率 **80%**（含 5 筆「合理上下級分歧」）；4B 模型約 67%。

### 4.2 雙觀眾 Dual-Track 輸出

JSON schema 強制同時產出：
- `summary_zh` / `impact_zh` / `next_step_zh`：中文白話、給非技術主管
- `root_cause` / `action`：英文技術細節、給 IT
- `iocs[]` / `mitre`：結構化欄位、給下游自動化

### 4.3 平台特定誤報感知 (Platform-Specific FP Awareness)

針對已知平台誤報（譬如 macOS rule 510 rootcheck "hidden port" 在 Darwin kernel >90% 為誤報）注入 advisory，**指示 LLM 降級嚴重度為 info 並建議 lsof 自查**，不要警報疲勞。

### 4.4 SCA 修補步驟具體化

CIS / SCA 類告警 (`rule.id = 19007`) 包含 Wazuh decoder 提供的 `data.sca.check.remediation` 欄位，prompt 引導 LLM 將其翻譯為**具體可執行的中文 IT 工單指令**（譬如 `sudo pwpolicy -setglobalpolicy "requiresSymbol=1"`），而非空泛「請聯絡 IT」。

---

## 5. Active Response 機制與安全性

### 5.1 動作觸發路徑

兩條獨立路徑：
- **Block (新增)**: Wazuh API `PUT /active-response?agents_list=<id>` → manager → agent → `firewall-drop` binary → `pfctl wazuh_fwtable` add
- **Unblock (移除)**: bridge 直接調用 host pfctl（透過 `/etc/sudoers.d/edgesec-bridge-unblock` 內 NOPASSWD 限定的 `pfctl -t wazuh_fwtable -T delete *`）

不採用「Wazuh `<active-response>` 自動觸發」模式（即 rules_id-bound auto-fire），改採 **human-in-the-loop**：每個動作須由人在 Slack 上確認，避免 LLM 誤判導致自我 DoS。

### 5.2 權限模型

- Bridge 端 `/active-response/*` 端點以 Bearer Token 保護
- Wazuh API JWT 認證，token cache 12 分鐘 TTL
- pfctl 解封權限收斂至 NOPASSWD 單一指令（不開全套 sudo）
- Slack Bot Scope 最小化（`chat:write` only）
- Action button 二次 confirm dialog，避免誤觸

### 5.3 Audit Trail

所有封鎖 / 解封動作以 context block 形式 append 在原 Slack 卡片：

```
✅ 已封鎖 192.0.2.111 (by security-admin · 18:35:14 · Wazuh active response)
🔓 已解封 192.0.2.111 (by security-admin · 19:42:08 · local pfctl)
```

訊息保留在 Slack channel 滿足 ISO 27001 / SOC 2 對 access log 的留存要求。

---

## 6. 部署與運維特性

| 項目 | 規格 |
|------|------|
| 最小部署規模 | 單一 host（Mac M-series ≥ 32GB 或 Linux x86 32GB），跑 Wazuh stack + LM Studio + bridge |
| 推論延遲 (Gemma 31B) | 5–10 sec / alert (Mac Studio M2 Ultra 64GB MLX 8-bit) |
| 推論延遲 (Qwen 4B fallback) | < 1 sec / alert（適用低延遲需求） |
| Bridge 吞吐 (預設 2 worker) | 16–32 alerts/min sustained |
| 對外連線 | 僅 Slack webhook（出向）；Wazuh CTI feed（出向，非告警內容） |
| 資料持久化 | SQLite WAL（`/alerts /stats` REST API 即時可查） |
| 升級 cadence | Wazuh manager `docker compose pull` 季度一次（CVE feed 自動更新） |

**Single-tenant single-host**。多客戶 / 多租戶部署需擴充（見 §9 Roadmap）。

---

## 7. 與既有方案比較

| 比較對象 | 重疊 | EdgeSec-Pi 差異化 |
|---------|------|-------------------|
| **Wazuh 官方 ChatGPT integration PoC** | 都用 `integratord` webhook + LLM 增強 | 官方 PoC 用 OpenAI 雲端、enrichment 寫回 alerts.json（仍在 Wazuh dashboard 內看）；EdgeSec-Pi 用本地 LLM、推 Slack 中文卡片 + 互動式 Active Response |
| **Microsoft Sentinel + Security Copilot** | LLM-augmented SIEM | Sentinel 為 cloud-native enterprise-tier 產品（NTD 30 萬+/年）；EdgeSec-Pi 針對 SMB 自架 |
| **CrowdStrike Charlotte AI / Falcon Go** | LLM analyst assistant | 商業 EDR，月費 SaaS、資料上 vendor 雲；EdgeSec-Pi 本地 + 開源底層 |
| **MSSP 託管 Wazuh** | 同樣以 Wazuh 為偵測核心 | MSSP 提供人力分析；EdgeSec-Pi 提供「LLM 替代第一線分析師」的元件，可被 MSSP 整合提升每客戶分析容量 |
| **SentinelOne / Bitdefender / Sophos** | 端點防護 | 商業 EDR 偵測能力較強但廠商 lock-in；EdgeSec-Pi 適合「先入場、出事再升級」的漏斗下層 |

---

## 8. Partner / Integration 模型

EdgeSec-Pi **不直接面對終端客戶銷售**，定位為可整合元件，三種合作可能：

### 8.1 MSSP / Managed Wazuh 服務商

將 EdgeSec-Pi 作為服務工具棧的一部分：客戶端維持 Wazuh agent，MSSP 端跑 manager + bridge + LLM。**單一分析師可服務的客戶數提升 5–10 倍**（LLM 處理掉 80% 噪音 + 中文化降低溝通成本）。

### 8.2 商業 EDR 廠商的 SMB Channel

EdgeSec-Pi 作為「免費試用門檻」——客戶先用 EdgeSec-Pi 看到價值，**規模成長後升級為商業 EDR + 持續使用 EdgeSec-Pi 的中文化通知層**。EDR 廠商獲取 SMB 客戶、LLM 翻譯層留在客戶手上不流失。

### 8.3 SI / 顧問公司的 Audit / Compliance 工具

EdgeSec-Pi 內建 CIS / PCI / GDPR 合規檢查 + Slack 上的 audit trail，可作為**合規顧問交付給客戶的持續監控基礎建設**。顧問完成 audit 後留下 EdgeSec-Pi，產生持續價值（每月健康報告、合規偏移即時警示）。

### 8.4 White-label / OEM

bridge 元件採 MIT 授權（規劃中），允許資安公司**白標重新打包**（自家 logo、自家 Slack workspace、客製 prompt）後納入產品線。

---

## 9. Roadmap 與已知 Gap

### 9.1 短期（1–2 月）

- 一鍵安裝包（macOS .pkg / Linux .deb；含 Wazuh stack + bridge + LM Studio 模型 pre-pull）
- Webhook 端點 HMAC 簽章驗證（防止公網偽造告警）
- Bridge HTTPS + reverse proxy（Caddy / Nginx）部署範本
- SSO / RBAC：Slack 端整合 Slack 用戶身份限制誰能按 Active Response 按鈕

### 9.2 中期（3–6 月）

- 多租戶 manager（一個 Wazuh 管多家客戶 + 各自 Slack workspace）
- 月度 PDF 合規報告自動生成（CIS / PCI 偏移趨勢、24/7 偵測統計）
- 額外 Active Response 動作（host isolation、user disable、process kill）+ 對應 Slack 按鈕
- Threat Intel feed 整合（AbuseIPDB / OTX / MISP）讓 LLM 在判讀時參考 IOC reputation

### 9.3 長期 / 開放協作

- 多 LLM backend 抽象層（OpenAI / Claude / Gemini API + Llama.cpp / Ollama / vLLM 本地）
- WebUI（給不裝 Slack 的客戶，提供瀏覽器介面）
- 行動 app（iOS / Android push、不靠 Slack）

### 9.4 已知限制

- Active Response 解封路徑目前依賴 host 端 NOPASSWD sudoers（單機部署 OK，多 agent 跨主機部署需改寫為 custom Wazuh AR script）
- macOS sudo 命令審計依賴 zsh shell function shadowing（涵蓋互動式 sudo，不涵蓋 cron / daemon 觸發的 sudo）
- 預設仰賴 Slack 作為通知通道（無 Slack 客戶需自建 WebUI）

---

## 10. 接觸與技術驗證

**Live Demo 提供**：可在受控環境（單機或客戶測試環境）部署完整 stack，30 分鐘內可重現「真實 SSH brute force → 中文 Slack 卡片 → 一鍵封鎖 → pfctl 驗證」端到端流程。

**程式碼 / 文件**：完整 source code、wazuh-stack/setup.sh、TESTING.md、API 規格、prompt corpus 與 evaluation harness 可提供給合作夥伴技術團隊評估。

**驗證指標已知**：
- Bridge 從 webhook 接到告警到完成 LLM 推論：5–10 sec (31B) / < 1 sec (4B)
- LLM 嚴重度命中率（自建 15 筆 corpus）：80%（31B）/ 67%（4B）
- 端到端「告警→Slack 卡片→人按按鈕→pfctl 封鎖」demo 實測：< 30 sec
- 整套 stack 單機資源：~36GB RAM（含 Gemma 31B 8-bit）

---

**EdgeSec-Pi 不取代任何資安產品。它把開源 SIEM 偵測引擎，配上本地 LLM 與台灣 SMB 主管習慣的工作介面，補上中小企業安全產品線下沉市場長期 under-served 的空缺——這個空缺，正是商業資安公司想做但做不下來、MSSP 想接但人力撐不住、開源工具想用但客戶看不懂的交集。**
