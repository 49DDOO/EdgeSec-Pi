# EdgeSec-Pi Active Response Scripts

這個目錄放的是 Wazuh agent 端的隔離/解除隔離腳本。

## 檔案

| 檔案 | 用途 |
| --- | --- |
| `edgesec-ar.py` | 真正的跨平台隔離/解除隔離邏輯 |
| `edgesec-isolate` | Linux/macOS wrapper，呼叫 `edgesec-ar.py isolate` |
| `edgesec-release-isolate` | Linux/macOS wrapper，呼叫 `edgesec-ar.py release` |
| `edgesec-isolate.cmd` | Windows wrapper，呼叫 `edgesec-ar.py isolate` |
| `edgesec-release-isolate.cmd` | Windows wrapper，呼叫 `edgesec-ar.py release` |

## 安全設計

- 先寫入狀態檔，再改網路。
- 隔離前必須能解析 Wazuh manager 或設定 `EDGESEC_AR_ALLOW_CIDRS`。
- 隔離時會保留 manager/管理網段的 host route。
- 每次隔離都會安排本機 TTL release，到期自動解除；Linux/macOS 優先使用 `at`，Windows 使用 `schtasks`，Linux 沒有 `at` 時才用 transient `systemd-run`，macOS 沒有 `at` 時才用 `launchctl submit`，最後才 fallback 到 detached sleep process。
- `release` 會根據狀態檔恢復路由或清掉 Linux iptables chain。

預設隔離方式：

| 平台 | 預設方式 | 說明 |
| --- | --- | --- |
| Linux | `iptables` + `ip6tables` | 建立 EdgeSec-Pi 專用 chain，只放行 manager/管理 CIDR，其餘 inbound/outbound 阻擋。 |
| macOS | `pfctl` anchor | 使用 `com.apple/edgesec-ar` anchor，只放行 manager/管理 CIDR，其餘 IPv4/IPv6 阻擋，並清掉現有 pf state。 |
| Windows | Windows Firewall | 新增管理 allow rule，將 Domain/Private/Public profile 的預設 inbound/outbound 改成 Block。 |
| 其他/手動指定 | route quarantine | 保留 manager host route 後移除 default route；這只能擋跨網段，不建議作為正式隔離。 |

Linux 規則不再全域放行 `ESTABLISHED,RELATED`；只有管理 allowlist 會被放行，避免隔離後既有 C2 session 繼續存活。

`--dry-run` 不會讀取本機路由或防火牆 profile；只有 `route-quarantine` fallback 在 dry-run 顯示 placeholder route command，方便檢查流程但不代表實際 gateway。

## TTL 與重開機語意

隔離規則刻意不做永久化。端點重開機後，本機防火牆/路由隔離會解除，這是 fail-open 設計：寧可恢復網路，也不要讓一台端點因為重開而永久卡在半隔離狀態。這也代表「重開機會解除隔離」是已知行為，不應被當成強制持久隔離。

bridge 的狀態對齊方式是：隔離紀錄仍會留到 TTL sweeper 執行 release。若端點重開後本機已沒有隔離 state，`edgesec-release-isolate` 會回報成功/已解除，bridge 會把該 isolation 標成 `released`。也就是說，重開機後到 TTL sweeper 下一次處理之前，bridge 可能短暫顯示隔離仍開著；TTL release 成功後狀態會收斂。

Linux 排程器選擇上，`at` 排在 transient `systemd-run` 前面。原因是 `at` 是明確的一次性排程語意，較不依賴 transient unit policy 與 systemd runtime 狀態；`systemd-run --on-active` 是 fallback，不是首選。

## Agent 端安裝

Linux/macOS 本機 agent 可用：

```bash
./scripts/install-edgesec-ar-agent.sh
```

Windows agent 需要把以下檔案放到 agent 的 active-response 目錄：

```text
C:\Program Files (x86)\ossec-agent\active-response\bin\edgesec-ar.py
C:\Program Files (x86)\ossec-agent\active-response\bin\edgesec-isolate.cmd
C:\Program Files (x86)\ossec-agent\active-response\bin\edgesec-release-isolate.cmd
```

Windows 需要 Python Launcher `py -3` 可用，或自行修改 `.cmd` wrapper 指向 Python。

## Manager 端啟用 command

在 Wazuh manager 註冊 command：

```bash
./scripts/enable-edgesec-ar.sh
```

然後 bridge `.env` 設：

```env
WAZUH_ISOLATE_COMMAND=edgesec-isolate0
WAZUH_RELEASE_ISOLATE_COMMAND=edgesec-release-isolate0
ACTIVE_RESPONSE_ISOLATION_PRESERVE_CHANNELS_ACK=1
ACTIVE_RESPONSE_ISOLATION_VERIFIED_PLATFORMS=linux
```

`ACTIVE_RESPONSE_ISOLATION_PRESERVE_CHANNELS_ACK=1` 只能在你已經用 `--dry-run` 和測試機確認「保留 Wazuh/管理連線」後再打開。
`ACTIVE_RESPONSE_ISOLATION_VERIFIED_PLATFORMS` 也要逐 OS 填寫：Linux 測過只填 `linux`，macOS/Windows 沒做真機隔離、解除、TTL、重開機測試前不要放進去；未列入的平台不會顯示或執行隔離。

## 測試

先在 agent 上 dry-run：

```bash
sudo /var/ossec/active-response/bin/edgesec-isolate --dry-run --ttl 120 --manager <wazuh-manager-ip> --no-schedule
sudo /var/ossec/active-response/bin/edgesec-release-isolate --dry-run
```

確認輸出的 `allow_networks` 有 Wazuh manager，且 `commands` 符合預期後，再用測試 agent 做真隔離。若環境是雙協定網路，請同時確認 IPv6 管理位址或管理 CIDR 有被列入 allowlist。
