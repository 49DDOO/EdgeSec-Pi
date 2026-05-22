# EdgeSec-Pi 完整安裝手冊

Language: 繁體中文 | [English](INSTALL.en.md)

這份文件是給第一次安裝的人看的。目標是從一台乾淨的管理電腦開始，把整套系統跑起來：

1. Wazuh：負責收集電腦與伺服器的資安事件。
2. EdgeSec-Pi Dashboard：給管理者看今天要不要處理。
3. 本機 AI：把 Wazuh 技術告警翻成看得懂的中文。
4. LINE / Slack / Telegram / Email：收到告警通知。
5. Agent：安裝在每台要保護的電腦上。

> MCP / LobeChat 是進階查詢功能，不是第一次上線必裝。需要時再看 [SETUP_GUIDE.md](SETUP_GUIDE.md)。

---

## 先選安裝方式

### A. 本機試用版（建議第一次用）

適合：先在一台 Mac 上完整試跑。

這會安裝：

- EdgeSec-Pi Dashboard
- 本機 HTTPS
- 本機 Wazuh lab stack（Manager / Indexer / Dashboard / demo agent）
- 後續可從 Dashboard 安裝真正電腦的 Agent

### B. 正式部署版

適合：公司已經有 Wazuh，或準備把 Wazuh 放到正式伺服器。

這會安裝：

- EdgeSec-Pi Dashboard / Bridge
- 接到既有 Wazuh Manager
- Agent 由既有 Wazuh 流程或 Dashboard 下載安裝

---

## A. 本機試用版：從 0 開始

### 1. 準備一台管理電腦

建議規格：

| 項目 | 建議 |
|------|------|
| 作業系統 | macOS |
| 記憶體 | 32 GB 以上較順；若使用大型模型建議 64 GB |
| Docker | Docker Desktop 已安裝並啟動 |
| Python | Python 3.10 以上較佳 |
| Git | 用來下載專案 |
| AI | LM Studio 已安裝 |

先確認 Docker 可用：

```bash
docker ps
```

### 2. 下載 EdgeSec-Pi

```bash
git clone https://github.com/49DDOO/EdgeSec-Pi.git
cd EdgeSec-Pi
```

### 3. 啟動本機 AI

1. 打開 LM Studio。
2. 下載並載入一個支援中文的模型。
3. 到 Local Server，按 Start。
4. 確認這個網址有回應：

```bash
curl http://localhost:1234/v1/models
```

你會看到模型名稱。把模型名稱記下來，例如：

```text
gemma-4-31b-it-mlx
```

### 4. 安裝 Dashboard 與 Wazuh lab

```bash
./scripts/install-dashboard-macos.sh --with-wazuh-stack
```

這個指令會做幾件事：

- 建立 `bridge.env`
- 建立 `wazuh-llm-bridge/.env`
- 安裝 Python 套件
- 建立本機 HTTPS 憑證
- 啟動 EdgeSec-Pi Dashboard
- 啟動本機 Wazuh lab stack

如果安裝過程詢問是否信任 EdgeSec-Pi Local CA，選 `Y`。這是為了讓本機瀏覽器可以開 HTTPS Dashboard。

### 5. 設定 AI 模型名稱

打開 `bridge.env`，把 `LM_MODEL` 改成 LM Studio 實際載入的模型名稱：

```env
LM_MODEL=gemma-4-31b-it-mlx
```

重新啟動 Dashboard：

```bash
./scripts/run.sh bridge
```

### 6. 打開 Dashboard

```text
https://localhost:8001/dashboard?view=setup
```

第一次進入只照這個順序做：

1. 設定通知，並測試成功。
2. 安裝 Agent。
3. 設定每台電腦的業務用途。
4. 回到今日待辦，等通知。

### 7. 設定通知

在 Dashboard 點：

```text
上線設定 → 設定通知
```

至少設定一種：

- LINE：適合非技術使用者。
- Slack：適合公司已有 Slack。
- Telegram：適合技術窗口。
- Email：適合備援通知。

每一種通知都要按「測試」。手機或 Slack 有收到測試訊息，才算完成。

### 8. 安裝第一台 Agent

Agent 不是一個檔案裝全部。每台電腦要依照自己的作業系統下載對應版本：

| 電腦類型 | Dashboard 下載選項 | 適合對象 |
|----------|--------------------|----------|
| Windows | `Windows / MSI` | 一般 Windows 桌機、筆電、Windows Server |
| macOS Apple silicon | `macOS / Apple silicon` | M1 / M2 / M3 / M4 Mac |
| macOS Intel | `macOS / Intel` | 舊款 Intel Mac |
| Ubuntu / Debian | `Linux / DEB` | Ubuntu、Debian、Linux Mint |
| Red Hat 系 | `Linux / RPM` | RHEL、Rocky Linux、AlmaLinux、CentOS、Fedora |

如果要把目前這台 Mac 也納入監控，可以直接跑：

```bash
sudo ./scripts/install-mac-agent.sh
```

如果是其他電腦，請在 Dashboard 操作：

1. 到 `電腦端點`。
2. 點 `安裝 Agent`。
3. 依照電腦作業系統選下載檔。
4. 在那台電腦上安裝。
5. 回到 `電腦端點`，確認新電腦出現在清單。

> 重要：如果 Agent 裝在另一台電腦，Manager 位址不能填 `localhost` 或 `127.0.0.1`，要填 EdgeSec-Pi / Wazuh Manager 那台機器的內網 IP，例如 `192.168.50.177`。

Agent 需要連到 Wazuh Manager：

| Port | 用途 |
|------|------|
| `1515/tcp` | 第一次註冊 Agent |
| `1514/tcp` | Agent 持續回報事件 |

如果 Agent 安裝後沒有出現在 Dashboard，先在那台電腦確認：

```bash
nc -vz <Wazuh-Manager-IP> 1515
nc -vz <Wazuh-Manager-IP> 1514
```

Windows 沒有 `nc` 時，可用 PowerShell：

```powershell
Test-NetConnection <Wazuh-Manager-IP> -Port 1515
Test-NetConnection <Wazuh-Manager-IP> -Port 1514
```

不同 OS 的服務確認方式：

| 作業系統 | 確認 Agent 是否有跑 |
|----------|----------------------|
| Windows | `services.msc` 裡確認 `WazuhSvc` 是 Running |
| macOS | `sudo /Library/Ossec/bin/wazuh-control status` |
| Linux | `sudo systemctl status wazuh-agent` |

### 9. 補每台電腦的業務用途

到：

```text
電腦端點 → 端點業務背景
```

每台電腦至少填：

- 用途：例如「開發者」、「會計主機」、「門市 POS」。
- 重要程度：低 / 一般 / 重要 / critical。
- 使用時段：例如 `Mon-Fri 09:00-19:00 Asia/Taipei`。
- 說明：例如「只有 Peter 會使用」、「處理客戶資料」。

這一步很重要。沒有業務用途，AI 只能說技術告警；補完後，通知會直接說明可能影響誰、哪個流程或哪套系統。

### 10. 驗證整套系統

跑環境檢查：

```bash
./scripts/test.sh env
```

期待看到：

```text
environment readiness passed
```

再打開：

```text
https://localhost:8001/dashboard?view=platform
```

點「立即檢查」。如果顯示「系統可以正常使用」，表示主要服務都通。

---

## B. 正式部署版：接到既有 Wazuh

如果公司已經有 Wazuh，流程是：

1. 在管理電腦或伺服器安裝 EdgeSec-Pi Bridge。
2. 在 Wazuh Manager 加上 webhook integration。
3. 設定通知。
4. 安裝或確認 Wazuh Agent。

### 1. 安裝 EdgeSec-Pi Bridge

```bash
git clone https://github.com/49DDOO/EdgeSec-Pi.git
cd EdgeSec-Pi
cp bridge.env.example bridge.env
cd wazuh-llm-bridge
cp .env.example .env
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. 編輯 `bridge.env`

至少確認：

```env
BRIDGE_PORT=8001
BRIDGE_PUBLIC_URL=https://你的-dashboard-網址:8001

LM_STUDIO_URL=http://localhost:1234/v1/chat/completions
LM_MODEL=你的模型名稱

WAZUH_API_URL=https://你的-wazuh-manager:55000
WAZUH_INDEXER_URL=https://你的-wazuh-indexer:9200
SIEM_DASHBOARD_URL=https://你的-wazuh-dashboard

MANAGER_HOST=你的-wazuh-manager-IP
WAZUH_AGENT_PORT=1514
WAZUH_AUTHD_PORT=1515
```

### 3. 編輯 `wazuh-llm-bridge/.env`

至少確認 Wazuh API 帳密與通知設定。

正式環境建議設定：

```env
WEBHOOK_SECRET=請換成一組長密碼
ACTIVE_RESPONSE_TOKEN=請換成一組長密碼
```

不要把 `.env` 或 `bridge.env` commit 到 GitHub。

### 4. 啟動 Bridge

```bash
cd ../scripts
./run.sh bridge
```

確認：

```bash
curl -k https://localhost:8001/health
```

### 5. 在 Wazuh Manager 加 webhook

Wazuh 的 `<integration>` 不是只改 `ossec.conf` 就好，還需要一支同名 forwarder script。正式環境請做兩件事。

#### 5-1. 安裝 forwarder script

把本專案的 forwarder 放到 Wazuh Manager：

```bash
sudo cp wazuh-stack/customizations/custom-llm-bridge /var/ossec/integrations/custom-llm-bridge
sudo chown root:wazuh /var/ossec/integrations/custom-llm-bridge
sudo chmod 750 /var/ossec/integrations/custom-llm-bridge
```

如果你的 Wazuh Manager 跑在 Docker container，請改用：

```bash
docker cp wazuh-stack/customizations/custom-llm-bridge \
  <wazuh-manager-container>:/var/ossec/integrations/custom-llm-bridge
docker exec <wazuh-manager-container> chown root:wazuh /var/ossec/integrations/custom-llm-bridge
docker exec <wazuh-manager-container> chmod 750 /var/ossec/integrations/custom-llm-bridge
```

#### 5-2. 加入 `ossec.conf` integration

在 Wazuh Manager 的 `/var/ossec/etc/ossec.conf` 加入：

```xml
<integration>
  <name>custom-llm-bridge</name>
  <hook_url>https://你的-edgesec-pi-host:8001/webhook</hook_url>
  <api_key>你的 WEBHOOK_SECRET</api_key>
  <level>7</level>
  <alert_format>json</alert_format>
</integration>
```

`api_key` 必須和 `wazuh-llm-bridge/.env` 的 `WEBHOOK_SECRET` 一樣。Wazuh 會把它交給 `custom-llm-bridge`，forwarder 會用 `Authorization: Bearer ...` 送到 EdgeSec-Pi。

修改後重啟 Wazuh Manager。

#### 5-3. 驗證 Wazuh 有打到 EdgeSec-Pi

看 Wazuh integration log：

```bash
sudo tail -80 /var/ossec/logs/integrations.log
```

Docker 版：

```bash
docker exec <wazuh-manager-container> tail -80 /var/ossec/logs/integrations.log
```

看 EdgeSec-Pi 是否收到：

```bash
curl -k https://localhost:8001/alerts?limit=5
```

### 6. 確認 Agent

每台要保護的電腦都要安裝 Wazuh Agent，並指向：

```text
MANAGER_HOST:1514
MANAGER_HOST:1515
```

Dashboard 的 `電腦端點` 頁會列出已納管端點。

---

## MCP / LobeChat 要不要裝？

第一次上線不需要。

建議順序：

1. 先讓 Dashboard、通知、Agent 正常。
2. 公司已經能收到告警並看懂。
3. 再讓 IT 或外包資安安裝 MCP / LobeChat。

MCP 適合做：

- 查 Wazuh 原始事件。
- 查端點弱點。
- 查 agent 狀態。
- 給 AI 更多上下文。

請看 [SETUP_GUIDE.md](SETUP_GUIDE.md)。

---

## 常見問題

### 1. Dashboard 打不開 HTTPS

本機憑證沒有被瀏覽器信任。先執行：

```bash
EDGESEC_TRUST_LOCAL_CA=1 ./scripts/run.sh bridge
```

如果還是不行，重開瀏覽器。正式部署建議用正式網域與公開憑證。

### 2. LM Studio 顯示不正常

確認：

```bash
curl http://localhost:1234/v1/models
```

如果沒有模型，先到 LM Studio 載入模型並啟動 Local Server。然後把 `bridge.env` 的 `LM_MODEL` 改成實際模型名稱。

### 3. Agent 裝好了但 Dashboard 沒出現

檢查 Agent 是否啟動：

```bash
sudo /Library/Ossec/bin/wazuh-control status
```

檢查能不能連到 Manager：

```bash
nc -vz <MANAGER_HOST> 1514
nc -vz <MANAGER_HOST> 1515
```

如果 macOS Agent 設定裡還有 `MANAGER_IP`，代表安裝後沒有替換 Manager 位址，需要重新設定 `ossec.conf`。

### 4. Slack / LINE 沒收到通知

先不要等真的告警。到：

```text
上線設定 → 設定通知
```

按「測試」。測試訊息收得到，才代表通知完成。

### 5. 今日待辦出現很多重複事件

新版 Dashboard 會把同一台電腦、同一規則、同一來源 IP / 帳號的事件合併成一張卡。卡片會顯示「同類事件 N 次」，按一次處理狀態會更新整組。

---

## 完整上線檢查表

- [ ] Docker Desktop 已啟動。
- [ ] LM Studio Local Server 已啟動。
- [ ] `LM_MODEL` 已填成實際模型名稱。
- [ ] EdgeSec-Pi Dashboard 可開啟。
- [ ] Wazuh Manager / Indexer / Dashboard 可用。
- [ ] 至少一個通知管道測試成功。
- [ ] 至少一台 Agent 在線。
- [ ] 每台端點已填業務用途。
- [ ] `/self-test` 顯示系統可以正常使用。
- [ ] `./scripts/test.sh env` 通過。
