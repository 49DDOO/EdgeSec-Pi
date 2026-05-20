# EdgeSec-Pi — 可選的 LobeChat + Wazuh MCP Server 安裝指南

> 這份文件是 **可選的對話式查詢路線**，不是 EdgeSec-Pi 的主流程。
> 主流程是 `wazuh-llm-bridge/` 接 Wazuh webhook，產生中文 Dashboard 與 Slack 通知。
> 本文件說明如何另外部署 LobeChat 與 Wazuh MCP Server，讓使用者用聊天介面查詢 Wazuh。

---

## ⚠️ 關於原始 URL 的說明

你提供的網址 `https://lobehub.com/mcp/unmuktoai-wazuh-mcp-server/skill.md` 在抓取時回傳**空內容**——
LobeHub 該 listing 頁並未實際發布 `skill.md`（404 / 空 body）。
本指南是從以下三個來源彙整的等效安裝步驟：

1. LobeHub MCP catalog 頁：`https://lobehub.com/mcp/unmuktoai-wazuh-mcp-server`
2. 上游 GitHub 倉庫：`https://github.com/gensecaihq/Wazuh-MCP-Server` (原 unmuktoai/Wazuh-MCP-Server，已轉移)
3. PulseMCP listing：`https://www.pulsemcp.com/servers/unmuktoai-wazuh`

---

## 架構總覽

```
┌────────────────┐      MCP/HTTP      ┌──────────────────────┐      REST API     ┌──────────────┐
│   LobeChat     │ ─────────────────► │  Wazuh MCP Server    │ ────────────────► │  Wazuh SIEM  │
│ (LobeHub UI)   │   Bearer token     │  :3000/mcp           │   :55000 / :9200  │  Manager +   │
│                │ ◄───────────────── │  (48 security tools) │ ◄──────────────── │   Indexer    │
└────────────────┘    JSON-RPC        └──────────────────────┘                   └──────────────┘
        ▲
        │  Browser
        │
   👤 SOC analyst
```

LobeChat 是 LobeHub 出的開源對話介面，內建 **MCP Marketplace**，可直接搜尋並掛載 MCP server。
Wazuh MCP Server 對外暴露一支 `/mcp` 端點，把 48 個安全工具（查告警、查弱點、封 IP、隔離主機…）變成 LLM 可呼叫的 function。

---

## 前置需求

| 元件 | 版本 |
|------|------|
| Docker Engine | 20.10+ |
| Docker Compose | v2 |
| 記憶體 | ≥ 4 GB（LobeChat ~1G, Wazuh MCP ~512M, 餘量給 LLM client） |
| Wazuh Manager | 4.8.0 – 4.14.4，且已啟用 API |
| 一個可呼叫的 LLM（雲端 OpenAI/Anthropic 或本地 Ollama） |

---

## 步驟 1 — Clone Wazuh MCP Server

```bash
cd EdgeSec-Pi
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git wazuh-mcp
cd wazuh-mcp
cp .env.example .env
```

編輯 `wazuh-mcp/.env`，至少填入：

```env
# Wazuh Manager API
WAZUH_HOST=10.0.0.10                # 你的 Wazuh manager IP / hostname
WAZUH_PORT=55000
WAZUH_USER=wazuh-wui
WAZUH_PASS=YourStrongPassword!

# Wazuh Indexer (查 alert / vulnerability 必填)
WAZUH_INDEXER_HOST=10.0.0.10
WAZUH_INDEXER_PORT=9200
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASS=YourIndexerPassword!

# MCP Server
MCP_HOST=0.0.0.0
MCP_PORT=3000
AUTH_MODE=bearer
ALLOWED_ORIGINS=http://localhost:3210,https://chat.your-domain.tld
VERIFY_SSL=false                    # 自簽憑證的 lab 設 false
```

產生一把 API key（之後 LobeChat 連線會用到）：

```bash
python3 -c "import secrets; print('wazuh_' + secrets.token_urlsafe(32))"
# 例：wazuh_8f3c1...   ← 複製存好，等下兩邊都要填
```

把它寫進 `.env` 的 `MCP_API_KEY=` 欄位（若範本沒有就追加一行）。

啟動：

```bash
docker compose up -d
curl http://localhost:3000/health    # 期待回 {"status":"healthy",...}
```

---

## 步驟 2 — 部署 LobeChat（含 MCP Marketplace）

LobeChat **v1.x 起原生支援 MCP**，Marketplace 在側邊欄「Discover → MCP」進入。
最快的方式是用官方 docker-compose：

```bash
cd EdgeSec-Pi
mkdir lobechat && cd lobechat

# 取得官方 compose 範本
curl -fsSL https://raw.githubusercontent.com/lobehub/lobe-chat/main/docker-compose/local/docker-compose.yml \
  -o docker-compose.yml
curl -fsSL https://raw.githubusercontent.com/lobehub/lobe-chat/main/docker-compose/local/.env.example \
  -o .env

# 編輯 .env，填入 LLM API key（任選其一即可）
#   OPENAI_API_KEY=sk-...
#   ANTHROPIC_API_KEY=sk-ant-...
#   或設定 OLLAMA_PROXY_URL=http://host.docker.internal:11434
nano .env

docker compose up -d
# 開啟 http://localhost:3210
```

第一次進入會要你建立帳號（本機部署預設用 NextAuth credential）。

---

## 步驟 3 — 在 LobeHub MCP Marketplace 掛載 Wazuh

1. 登入 LobeChat → 左下角 **Settings** → **Tools / MCP**（中文版：工具 / MCP 外掛）。
2. 點 **MCP Marketplace** → 搜尋 `wazuh` → 選 **Wazuh MCP Server (unmuktoai)**。
3. 點 **Install**，會跳出 JSON 設定。改成你本機跑的 instance：

```json
{
  "mcpServers": {
    "wazuh": {
      "type": "http",
      "url": "http://localhost:3000/mcp",
      "headers": {
        "Authorization": "Bearer wazuh_8f3c1..."
      }
    }
  }
}
```

> 若 LobeChat 跑在 Docker、Wazuh MCP 也跑在 Docker（不同 compose）：
> 把 `localhost` 改成 `host.docker.internal`（Mac/Windows）或建立共用 docker network。

4. 儲存後在對話視窗右下角的 🧰 工具列會看到 **wazuh**，列出 48 個 tool。
5. 開啟一個新對話，左下選 **Enable Tools → wazuh**，就可以自然語言詢問：

   - 「列出過去 1 小時 critical 等級的告警」
   - 「agent-003 上有哪些未修補的 CVE？」
   - 「把 10.0.1.45 在 agent-003 上封掉」（會觸發 active response，需要 `wazuh:write` scope）

---

## 步驟 4 — 驗證

```bash
# Wazuh MCP server health
curl http://localhost:3000/health

# Tool 列表 (需帶 token)
curl -H "Authorization: Bearer $MCP_API_KEY" \
     http://localhost:3000/mcp \
     -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

# LobeChat container
docker ps | grep lobe-chat
```

在 LobeChat 對話中輸入：
> *「呼叫 wazuh 的 get_wazuh_cluster_health，告訴我叢集狀態」*

如果回得出 JSON / 摘要 → 整條 pipeline 接通。

---

## 可選：本地 LLM（air-gapped 模式）

中小企業若不想把告警內容送雲端，把 LobeChat 的 LLM 切到 Ollama：

```bash
# Mac / Linux 主機
brew install ollama || curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5:7b      # 或 llama3.1:8b
```

LobeChat `.env`：
```
OLLAMA_PROXY_URL=http://host.docker.internal:11434
DEFAULT_AGENT_CONFIG=model=qwen2.5:7b;provider=ollama
```

整套（LobeChat + Wazuh MCP + Ollama + Wazuh）就完全離線可用。

---

## 安全注意事項

| 項目 | 建議 |
|------|------|
| `MCP_API_KEY` | 用 `secrets.token_urlsafe(32)`，不要 commit 進 git |
| Active Response 工具（封 IP / 隔離 / 殺 process） | 預設需要 `wazuh:write` scope；先用 read-only token 試跑幾天再放權 |
| `ALLOWED_ORIGINS` | 限制成你 LobeChat 的實際 URL，不要放 `*` |
| TLS | production 一定要在前面套 nginx / Caddy 反向代理 |
| 稽核日誌 | `docker logs wazuh-mcp` 會記每一次 destructive tool call，記得 ship 到中央 log |

---

## 疑難排解

| 症狀 | 可能原因 | 解法 |
|------|----------|------|
| `/health` 回 401 | AUTH_MODE 設錯 | 確認 `.env` 是 `bearer` 且 token 正確 |
| LobeChat 看不到 tool | URL 用了 `localhost` 但 LobeChat 在容器裡 | 改 `host.docker.internal` 或共用 network |
| Tool call 卡住 | Wazuh API timeout | 檢查 `WAZUH_HOST` 連得到，`VERIFY_SSL` 對應憑證設定 |
| Indexer 查 alert 空 | 沒填 indexer 變數 | 補 `WAZUH_INDEXER_*` 那一組 |

更多：<https://github.com/gensecaihq/Wazuh-MCP-Server/blob/main/docs/TROUBLESHOOTING.md>

---

## 輔助啟動腳本

專案根目錄的 `install.sh` 會協助 clone Wazuh MCP Server、產生 API key，並印出 LobeChat MCP JSON。
這條路線適合想要聊天式 Wazuh 查詢的人；如果只需要 EdgeSec-Pi Dashboard 與 Slack 通知，可以略過。

## Sources

- [Wazuh MCP Server | LobeHub MCP Catalog](https://lobehub.com/mcp/unmuktoai-wazuh-mcp-server)
- [gensecaihq/Wazuh-MCP-Server (GitHub, upstream)](https://github.com/gensecaihq/Wazuh-MCP-Server)
- [Wazuh MCP Server by unmukto.ai | PulseMCP](https://www.pulsemcp.com/servers/unmuktoai-wazuh)
- [Setup & Configuration | DeepWiki](https://deepwiki.com/unmuktoai/Wazuh-MCP-Server/3-setup-and-configuration)
- [Bringing AI to SIEM: Wazuh MCP + Claude Desktop (Medium)](https://medium.com/@iamblacklight/bringing-ai-to-siem-my-experiment-with-wazuh-mcp-server-and-claude-desktop-09f2aa15165d)
